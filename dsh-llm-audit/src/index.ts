/**
 * @dsh-external/dsh-llm-audit — LLM 端点安全审计插件（宿主侧）。
 *
 * 本文件只做四件事：目标清单持久化、**隔离**地拉起探测子进程、把子进程回传的
 * 已脱敏结论渲染成正式审计报告落盘、以及把工具 / HTTP 面板接口挂上去。
 *
 * 隔离要点（与 audit-core / probe-worker 配套）：
 * - 网络探测一律发生在 fork 出来的子进程里；本进程不直接接触被审计端点。
 * - 回到本进程的只有结构化判定 + 脱敏摘录；端点原文只在证据文件里。
 * - 工具结果默认**不含**完整报告正文（避免不可信数据大面积进入上下文），
 *   只给判定摘要 + 报告/证据文件路径；需要正文时显式传 includeReport。
 * - 端点请求的工具调用一律只记录、不执行。
 */
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import { fork } from 'node:child_process'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from 'cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import z from 'schemastery'
import {
  auditRun, buildLedgerEntries, keyFingerprintOf, makeRunId, maskKey, normalizeBase, renderReport, resolveChecks, UNTRUSTED_NOTICE,
  type AuditRunResult, type AuditTarget, type DangerLedgerRecord, type ProgressUpdate, type ReportMeta, type TargetReport,
} from './audit-core.js'

export const name = '@dsh-external/dsh-llm-audit'
export const inject = ['tools']

const PLUGIN_VERSION = '0.4.2'

export interface Config {
  timeoutMs: number
  delayMs: number
  /** 关闭后退化为同进程执行（不推荐；仅用于排障）。 */
  isolate: boolean
  /** 每个目标默认最多审计多少个模型。 */
  maxModels: number
  /** 危险 Key 自动台账：扫到即写入本地文件（默认开）。 */
  ledger: boolean
  /** 模型级并发（默认 1 串行；限流宽松的端点可调 2-3 提速）。 */
  concurrency: number
  /** 面板 HTTP 接口访问令牌；非空时所有 /plugins/dsh-llm-audit/* 请求必须携带 x-audit-token。 */
  authToken: string
}

export const Config = z.object({
  timeoutMs: z.number().default(45000),
  delayMs: z.number().default(300),
  isolate: z.boolean().default(true),
  maxModels: z.number().default(12),
  ledger: z.boolean().default(true),
  concurrency: z.number().default(1),
  authToken: z.string().default(''),
})

// ──────────────────────────── 存储 ────────────────────────────

function storeDir(): string {
  return join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'llm-audit')
}
function storePath(): string {
  return join(storeDir(), 'targets.json')
}
function reportsDir(): string {
  return join(storeDir(), 'reports')
}
function evidenceDir(): string {
  return join(storeDir(), 'evidence')
}
function ledgerDir(): string {
  return join(storeDir(), 'ledger')
}

function loadSavedTargets(): AuditTarget[] {
  try {
    const arr = JSON.parse(fs.readFileSync(storePath(), 'utf8'))
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

function saveSavedTargets(list: AuditTarget[]): void {
  fs.mkdirSync(storeDir(), { recursive: true })
  // 至少限制为仅当前用户可读写（Windows 上 POSIX 权限位不强制，但避免类 Unix 环境过宽）。
  fs.writeFileSync(storePath(), JSON.stringify(list, null, 2), { encoding: 'utf8', mode: 0o600 })
}

function errText(e: unknown): string {
  const anyE = e as any
  return String(anyE?.message ?? anyE ?? '未知错误')
}

function asJson<T = any>(v: unknown): T | undefined {
  if (v === undefined || v === null) return undefined
  if (typeof v !== 'string') return v as T
  const s = v.trim()
  if (s === '') return undefined
  try { return JSON.parse(s) as T } catch { return undefined }
}

/** 递归剔除 undefined —— 工具输出必须是 lossless JSON。 */
function clean<T>(v: T): T {
  if (Array.isArray(v)) return v.map((x) => clean(x)) as unknown as T
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) if (val !== undefined) out[k] = clean(val)
    return out as T
  }
  return v
}

// ──────────────────────── 隔离执行（fork 子进程）────────────────────────

const WORKER_PATH = join(dirname(fileURLToPath(import.meta.url)), 'probe-worker.js')

// ──────────────────────── 进度登记（供 UI 进度条轮询）────────────────────────

interface ProgressState extends ProgressUpdate {
  startedAt: number
  updatedAt: number
  error?: string
}

/** 最近若干次运行的进度（本地单用户工具，保留 5 条足够）。 */
const progressRuns = new Map<string, ProgressState>()

function recordProgress(update: ProgressUpdate, error?: string): void {
  const prev = progressRuns.get(update.runId)
  progressRuns.set(update.runId, {
    ...update,
    startedAt: prev?.startedAt ?? Date.now(),
    updatedAt: Date.now(),
    ...(error === undefined ? {} : { error }),
  })
  if (progressRuns.size > 5) {
    const oldest = [...progressRuns.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt)[0]
    if (oldest !== undefined) progressRuns.delete(oldest[0])
  }
}

function progressSnapshot(): Record<string, unknown> {
  // 并发时 active 取最近仍在运行的 run，而不是依赖单个全局 activeRunId。
  const values = [...progressRuns.values()]
  const active = values.filter((u) => !u.finished).sort((a, b) => b.updatedAt - a.updatedAt)[0] ?? null
  const recent = values.sort((a, b) => b.updatedAt - a.updatedAt).slice(0, 5)
  return { ok: true, active, recent }
}

interface IsolatedOutcome extends AuditRunResult {
  isolation: string
  degradedReason?: string
}

/** 隔离进程失败时已收到的部分成果（红队加固：慢速/恶意端点耗尽预算也不至于颗粒无收）。 */
export interface PartialOutcome {
  reports: TargetReport[]
  reason: string
}

/**
 * 在独立子进程里跑一轮审计；子进程崩溃/超时都不会影响宿主。
 * @param budgetMs - 整轮预算，超时即 kill（隔离的兑现方式）。
 * @param onPartial - 每完成一个目标回调一次（留存部分成果）。
 */
function runIsolated(targets: AuditTarget[], options: Record<string, unknown>, budgetMs: number, onPartial?: (r: TargetReport) => void): Promise<IsolatedOutcome> {
  return new Promise<IsolatedOutcome>((resolve, reject) => {
    let child
    try {
      child = fork(WORKER_PATH, [], {
        // 子进程不继承业务环境变量，只留最小必需集（Windows 上保留 SystemRoot/TEMP 等系统项，
        // 部分 Node 子系统在精简 env 下行为异常）。
        env: {
          PATH: process.env.PATH,
          NODE_ENV: process.env.NODE_ENV ?? 'production',
          ...(process.env.SystemRoot !== undefined ? { SystemRoot: process.env.SystemRoot } : {}),
          ...(process.env.TEMP !== undefined ? { TEMP: process.env.TEMP } : {}),
          ...(process.env.TMP !== undefined ? { TMP: process.env.TMP } : {}),
          ...(process.env.ComSpec !== undefined ? { ComSpec: process.env.ComSpec } : {}),
        },
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      })
    } catch (e) {
      reject(new Error('无法拉起隔离进程：' + errText(e)))
      return
    }
    let settled = false
    let stderr = ''
    const collectedPartials: TargetReport[] = []
    child.stderr?.on('data', (chunk: Buffer) => { if (stderr.length < 4000) stderr += chunk.toString() })
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      child.kill('SIGKILL')
      const err = new Error(`隔离进程超出预算 ${Math.round(budgetMs / 1000)}s，已强制终止`) as Error & { partials?: TargetReport[] }
      err.partials = collectedPartials
      reject(err)
    }, budgetMs)
    child.on('error', (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const e = new Error('隔离进程错误：' + errText(err)) as Error & { partials?: TargetReport[] }
      e.partials = collectedPartials
      reject(e)
    })
    child.on('message', (raw: unknown) => {
      const msg = raw as { type?: string; payload?: any; error?: string }
      if (msg?.type === 'progress' && msg.payload !== undefined) {
        recordProgress(msg.payload as ProgressUpdate)
        return
      }
      if (msg?.type === 'partial' && msg.payload !== undefined) {
        collectedPartials.push(msg.payload as TargetReport)
        onPartial?.(msg.payload as TargetReport)
        return
      }
      if (settled) return
      if (msg?.type === 'result' && msg.payload !== undefined) {
        settled = true
        clearTimeout(timer)
        resolve({ ...(msg.payload as AuditRunResult), isolation: '独立子进程（fork + IPC）' })
      } else if (msg?.type === 'error') {
        settled = true
        clearTimeout(timer)
        const err = new Error(msg.error ?? '隔离进程报错') as Error & { partials?: TargetReport[] }
        err.partials = collectedPartials
        reject(err)
      }
    })
    child.on('exit', (code) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const err = new Error(`隔离进程退出(code=${code})未回传结果${stderr ? '：' + stderr.slice(0, 500) : ''}`) as Error & { partials?: TargetReport[] }
      err.partials = collectedPartials
      reject(err)
    })
    try {
      child.send({ type: 'audit', targets, options })
    } catch (e) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const err = new Error('无法向隔离进程发送任务：' + errText(e)) as Error & { partials?: TargetReport[] }
      err.partials = collectedPartials
      reject(err)
    }
  })
}

export interface RunArgs {
  targets?: AuditTarget[]
  useSaved?: boolean
  /** 检查子集数组，或档位名 quick|standard|full。 */
  checks?: string[] | string
  saveReport?: boolean
  includeReport?: boolean
  /** 本轮模型数上限（每个目标）。 */
  maxModels?: number
  /** 外部指定 runId（面板 job 化后用于关联结果轮询）。 */
  runId?: string
}

/** 工具与 UI 面板共用的完整审计入口：隔离执行 → 渲染报告 → 落盘 → 返回紧凑摘要。 */
export async function runAuditJob(config: Config, args: RunArgs): Promise<any> {
  if (args.targets !== undefined && !Array.isArray(args.targets)) {
    return { ok: false, error: 'targets 必须是数组 [{name?,baseUrl,apiKey,model?,protocol?}]' }
  }
  const inline = Array.isArray(args.targets) ? args.targets.filter((t) => t && typeof t === 'object' && t.baseUrl && t.apiKey) : []
  const saved = args.useSaved !== false ? loadSavedTargets() : []
  const seen = new Set<string>()
  const all: AuditTarget[] = []
  for (const t of [...inline, ...saved]) {
    const key = normalizeBase(t.baseUrl || '')
    if (key === '' || !t.apiKey) continue
    // 同一 URL 允许用不同 Key 分别审计；同 URL 同 Key 时 inline 优先于 saved。
    const dedupKey = `${key}#${keyFingerprintOf(t.apiKey)}`
    if (seen.has(dedupKey)) continue
    seen.add(dedupKey)
    all.push(t)
  }
  if (all.length === 0) return { ok: false, error: '没有可审计目标：请提供 targets（url + key）或先保存目标' }

  const runId = args.runId ?? makeRunId()
  const startedAt = Date.now()
  // 给模型数加上限，防止超大值把预算/定时器推到危险范围。
  const rawMax = typeof args.maxModels === 'number' && args.maxModels > 0 ? Math.floor(args.maxModels) : config.maxModels
  const maxModels = Math.min(Math.max(1, rawMax), 100)
  const options = {
    timeoutMs: config.timeoutMs,
    delayMs: config.delayMs,
    checks: resolveChecks(args.checks),
    evidenceDir: evidenceDir(),
    runId,
    maxModels,
    concurrency: config.concurrency,
  }
  // 逐模型审计：单模型约 40 次探测（16 类检查），按目标 × 模型上限估算预算，再留 90s 收尾。
  // setTimeout 的 delay 上限是 2^31-1，超限会"立即触发"——必须钳制。
  const budgetMs = Math.min(all.length * maxModels * config.timeoutMs * 40 + 90_000, 2_147_483_000)

  // 起跑先登记一条进度，UI 立刻能显示"正在准备"
  recordProgress({
    runId, phase: '准备中', targetIndex: 0, targetTotal: all.length, targetName: all[0]?.name ?? '',
    modelIndex: 0, modelTotal: 0, model: '', probesDone: 0, probesTotal: 1, percent: 0, finished: false,
  })

  let outcome: IsolatedOutcome
  if (config.isolate) {
    try {
      outcome = await runIsolated(all, options, budgetMs)
    } catch (e) {
      const failure = e as Error & { partials?: TargetReport[] }
      const partials = Array.isArray(failure.partials) ? failure.partials : []
      if (partials.length > 0) {
        // 红队加固：恶意/慢速端点耗尽预算或击溃子进程时，已完成的目标照常出报告，
        // 不再做同进程重跑（重跑会再花一整轮时间，还把不可信端点请进宿主进程）。
        outcome = {
          reports: partials,
          probeCount: partials.reduce((n, r) => n + r.modelReports.length, 0),
          isolation: '独立子进程（部分成果留存）',
          degradedReason: `子进程未完成全部目标（${failure.message}）；以下为已完成的 ${partials.length}/${all.length} 个目标`,
        }
        // 明确结束进度，避免 UI 一直显示“进行中”。
        recordProgress({
          runId, phase: '已终止（部分成果留存）', targetIndex: partials.length, targetTotal: all.length,
          targetName: partials[partials.length - 1]?.name ?? '', modelIndex: 0, modelTotal: 0, model: '',
          probesDone: outcome.probeCount, probesTotal: Math.max(1, outcome.probeCount), percent: 100, finished: true,
        }, failure.message)
      } else {
        // 隔离失败且没有任何 partial：不自动把不可信端点请回宿主进程重跑。
        throw new Error(`隔离进程失败且无部分成果，已中止本轮审计（${errText(e)}）。如确需同进程执行，请显式设置 isolate=false。`)
      }
    }
  } else {
    const direct = await auditRun(all, { ...options, onProgress: (u) => recordProgress(u) })
    outcome = { ...direct, isolation: '同进程（配置 isolate=false）' }
  }

  const durationMs = Date.now() - startedAt
  const auditedModelNames = [...new Set(outcome.reports.flatMap((r) => r.modelReports.map((m) => m.model)))]

  const result: any = {
    ok: true,
    audited: outcome.reports.length,
    auditedModels: outcome.reports.reduce((n, r) => n + r.modelReports.length, 0),
    dangerousModels: outcome.reports.flatMap((r) => r.dangerousModels.map((d) => ({ target: r.name, ...d }))),
    isolation: outcome.isolation,
    degradedReason: outcome.degradedReason,
    probeCount: outcome.probeCount,
    callCount: outcome.probeCount,
    durationMs,
    auditedModelNames,
    untrustedDataNotice: UNTRUSTED_NOTICE,
    summary: outcome.reports.map((r) => summarize(r)),
    evidenceFile: outcome.evidenceFile,
    evidenceSha256: outcome.evidenceSha256,
  }

  // 危险 Key 自动台账（扫到即存档）：报告文件名可由 runId 预知，故先于落盘写入指针
  const mdPath = join(reportsDir(), `report-${runId}.md`)
  const jsonPath = join(reportsDir(), `report-${runId}.json`)
  let ledgerInfo: { recorded: number; jsonlPath: string; indexPath: string } | undefined
  if (config.ledger !== false) {
    try {
      const entries = buildLedgerEntries(outcome.reports, {
        runId,
        now: new Date().toISOString(),
        isolation: outcome.isolation,
        ...(args.saveReport !== false ? { reportFile: mdPath } : {}),
        ...(outcome.evidenceFile !== undefined ? { evidenceFile: outcome.evidenceFile } : {}),
        ...(outcome.evidenceSha256 !== undefined ? { evidenceSha256: outcome.evidenceSha256 } : {}),
      })
      if (entries.length > 0) {
        fs.mkdirSync(ledgerDir(), { recursive: true })
        const jsonlPath = join(ledgerDir(), 'dangerous-keys.jsonl')
        const indexPath = join(ledgerDir(), 'dangerous-keys.json')
        // 流水：每行一条，追加式，天然保留全部历史
        fs.appendFileSync(jsonlPath, entries.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8')
        // 聚合清单：按「key指纹@URL」upsert——保留首见时间、出现次数、峰值分与最新明细
        let idx: Record<string, any> = {}
        try { idx = JSON.parse(fs.readFileSync(indexPath, 'utf8')) } catch { /* 首次 */ }
        for (const e of entries) {
          const k = `${e.keyFingerprint}@${e.url}`
          const prev = idx[k]
          idx[k] = prev === undefined || prev === null
            ? { ...e, firstSeen: e.lastSeen, seenCount: 1, peakScore: e.risk.score }
            : {
                ...prev,
                lastSeen: e.lastSeen,
                runId: e.runId,
                risk: e.risk.score >= (prev.risk?.score ?? 0) ? e.risk : prev.risk,
                reasons: e.risk.score >= (prev.risk?.score ?? 0) ? e.reasons : prev.reasons,
                dangerousModels: e.risk.score >= (prev.risk?.score ?? 0) ? e.dangerousModels : prev.dangerousModels,
                remediation: e.risk.score >= (prev.risk?.score ?? 0) ? e.remediation : prev.remediation,
                exposureFlags: e.exposureFlags.length > 0 ? [...new Set([...(prev.exposureFlags ?? []), ...e.exposureFlags])] : prev.exposureFlags,
                reportFile: e.reportFile ?? prev.reportFile,
                evidenceFile: e.evidenceFile ?? prev.evidenceFile,
                evidenceSha256: e.evidenceSha256 ?? prev.evidenceSha256,
                seenCount: (prev.seenCount ?? 1) + 1,
                peakScore: Math.max(prev.peakScore ?? 0, e.risk.score),
              }
        }
        fs.writeFileSync(indexPath, JSON.stringify(idx, null, 2), 'utf8')
        ledgerInfo = { recorded: entries.length, jsonlPath, indexPath }
      }
    } catch (e) {
      result.ledgerError = errText(e)
    }
  }

  const meta: ReportMeta = {
    generatedAt: new Date().toLocaleString('zh-CN'),
    pluginVersion: PLUGIN_VERSION,
    isolation: outcome.isolation,
    probeCount: outcome.probeCount,
    durationMs,
    callCount: outcome.probeCount,
    auditedModels: auditedModelNames,
    evidenceFile: outcome.evidenceFile,
    evidenceSha256: outcome.evidenceSha256,
    evidenceLines: outcome.evidenceLines,
    degradedReason: outcome.degradedReason,
    ...(ledgerInfo !== undefined ? { ledgerFile: ledgerInfo.jsonlPath } : {}),
  }
  const markdown = renderReport(outcome.reports, meta)

  if (args.saveReport !== false) {
    try {
      fs.mkdirSync(reportsDir(), { recursive: true })
      fs.writeFileSync(mdPath, markdown, 'utf8')
      fs.writeFileSync(jsonPath, JSON.stringify({ meta, reports: outcome.reports }, null, 2), 'utf8')
      result.reportFiles = [mdPath, jsonPath]
    } catch (e) {
      result.reportFilesError = errText(e)
    }
  }
  if (ledgerInfo !== undefined) result.dangerLedger = clean(ledgerInfo)
  // 完整报告正文默认不进上下文（含脱敏引文，量也大）——面板与文件是它的去处。
  if (args.includeReport === true) result.markdown = markdown
  return clean(result)
}

/** 单目标紧凑摘要：只有判定，没有端点原文；按模型点名危险项。 */
function summarize(r: TargetReport): Record<string, unknown> {
  return {
    name: r.name,
    baseUrl: r.baseUrl,
    keyMasked: r.keyMasked,
    protocol: r.protocol,
    protocolSource: r.protocolSource,
    clientProfile: r.clientProfile,
    apiRoot: r.connectivity.apiRoot,
    reachable: r.connectivity.ok,
    modelsOnEndpoint: r.models.count,
    auditedModels: r.auditedModels,
    skippedModels: r.skippedModels,
    risk: r.risk,
    dangerousModels: r.dangerousModels,
    models: r.modelReports.map((m) => ({
      model: m.model,
      dangerous: m.dangerous,
      risk: m.risk,
      basicCall: m.basicCall.ok,
      outputIntegrity: m.outputIntegrity.executed
        ? {
            verdict: m.outputIntegrity.verdict,
            compliance: `${m.outputIntegrity.passed}/${m.outputIntegrity.total}`,
            identicalReplies: m.outputIntegrity.identicalReplies,
            repeatedExtra: m.outputIntegrity.repeatedExtra,
            markers: m.outputIntegrity.markers,
          }
        : undefined,
      systemPromptRespected: m.systemPromptRespected.respected,
      injectionLeaked: m.injection.executed ? m.injection.leaked : undefined,
      replyInjection: m.replyInjection.executed
        ? { verdict: m.replyInjection.verdict, hits: m.replyInjection.hits.map((h) => ({ probe: h.probe, kind: h.kind })) }
        : undefined,
      delayedInjection: m.delayedInjection.executed
        ? { verdict: m.delayedInjection.verdict, rounds: m.delayedInjection.rounds }
        : undefined,
      hiddenPrompt: m.hiddenPromptExtraction.executed
        ? { extracted: m.hiddenPromptExtraction.extracted, suspiciousTags: m.hiddenPromptExtraction.suspiciousTags }
        : undefined,
      identityConsistent: m.identity.consistent,
      identityVersionConsistent: m.identity.versionConsistent,
      identityRotating: m.identity.executed ? m.identity.rotating : undefined,
      streamCheck: m.streamCheck.executed
        ? { verdict: m.streamCheck.verdict, detail: m.streamCheck.detail }
        : undefined,
      contextIntegrity: m.contextIntegrity.executed
        ? { preserved: m.contextIntegrity.preserved, detail: m.contextIntegrity.detail }
        : undefined,
      toolCalls: m.toolCalls.supported,
      dangerousTools: m.dangerousTools.executed
        ? {
            verdict: m.dangerousTools.verdict,
            calledByInjection: m.dangerousTools.findings.find((f) => f.probe === 'indirect-injection')?.calledTools ?? [],
            spontaneousCalls: m.dangerousTools.findings.find((f) => f.probe === 'spontaneous')?.calledTools ?? [],
            fabricatedTools: m.dangerousTools.fabricatedTools,
          }
        : undefined,
      exfiltration: m.exfiltration.executed
        ? {
            verdict: m.exfiltration.verdict,
            destinations: m.exfiltration.destinations,
            keywords: m.exfiltration.keywords,
            scannedPaths: m.exfiltration.scannedPaths,
            sensitivePaths: m.exfiltration.sensitivePaths,
            canaryHit: m.exfiltration.canaryHit,
          }
        : undefined,
      elicitation: m.elicitation.executed
        ? {
            verdict: m.elicitation.verdict,
            flags: m.elicitation.flags,
            detail: m.elicitation.detail,
            destinations: m.elicitation.destinations,
            hitSuites: m.elicitation.suites.filter((s) => s.flags.length > 0).map((s) => ({ id: s.id, label: s.label, flags: s.flags, keywords: s.keywords, paths: s.paths })),
          }
        : undefined,
      memoryLeak: m.memoryLeak.executed ? { leaked: m.memoryLeak.leaked, detail: m.memoryLeak.detail } : undefined,
      multiTurn: m.multiTurn.executed ? { leaked: m.multiTurn.leaked, detail: m.multiTurn.detail } : undefined,
      costAbuse: m.costAbuse.executed
        ? {
            tokenInflation: m.costAbuse.tokenInflation,
            unclampedMaxTokens: m.costAbuse.unclampedMaxTokens,
            reportedCompletionTokens: m.costAbuse.reportedCompletionTokens,
            replyChars: m.costAbuse.replyChars,
            detail: m.costAbuse.detail,
          }
        : undefined,
      errors: m.errors,
    })),
    exposure: r.exposure,
    keyEcho: r.keyEcho,
    keyAnalysis: r.keyAnalysis,
    remediation: r.remediation,
    errors: r.errors,
  }
}

/** 目标清单增删改查（工具与面板共用）。 */
export function targetsCommand(action: string, payload: { target?: any; name?: string; baseUrl?: string; keyFingerprint?: string }): any {
  if (action === 'clear') {
    saveSavedTargets([])
    return { ok: true, cleared: true, count: 0, targets: [] }
  }
  if (action === 'add') {
    const t = payload.target
    if (!t?.baseUrl || !t?.apiKey) return { ok: false, error: 'target 需要 baseUrl 和 apiKey' }
    if (t.protocol !== undefined && t.protocol !== 'openai' && t.protocol !== 'anthropic' && t.protocol !== 'gemini') {
      return { ok: false, error: 'protocol 只能是 openai | anthropic | gemini' }
    }
    const baseUrl = normalizeBase(t.baseUrl)
    // 同一 URL 允许保存多个不同 Key；同 URL 同 Key 则覆盖旧记录。
    const key = keyFingerprintOf(t.apiKey)
    const list = loadSavedTargets().filter((x) => !(normalizeBase(x.baseUrl) === baseUrl && keyFingerprintOf(x.apiKey) === key))
    list.push({ name: t.name, baseUrl, apiKey: t.apiKey, model: t.model, protocol: t.protocol })
    saveSavedTargets(list)
    return clean({
      ok: true,
      count: list.length,
      saved: { name: t.name || baseUrl, baseUrl, keyMasked: maskKey(t.apiKey), model: t.model, protocol: t.protocol },
    })
  }
  if (action === 'remove') {
    const before = loadSavedTargets()
    let after: AuditTarget[]
    let removedLabel: string
    if (payload.keyFingerprint !== undefined && payload.keyFingerprint !== '') {
      // 精确删除：按 URL + Key 指纹匹配，避免同名/同 URL 多条 Key 被误删。
      const baseUrl = payload.baseUrl !== undefined ? normalizeBase(payload.baseUrl) : undefined
      after = before.filter((x) => {
        const sameKey = keyFingerprintOf(x.apiKey) === payload.keyFingerprint
        if (baseUrl !== undefined) return !(sameKey && normalizeBase(x.baseUrl) === baseUrl)
        return !sameKey
      })
      removedLabel = baseUrl !== undefined ? `${baseUrl}#${payload.keyFingerprint}` : payload.keyFingerprint
    } else {
      // 兼容旧调用：按 name 或 baseUrl 匹配。
      const needle = String(payload.name ?? '').toLowerCase()
      after = before.filter((x) => normalizeBase(x.baseUrl).toLowerCase() !== needle && String(x.name ?? '').toLowerCase() !== needle)
      removedLabel = needle
    }
    if (after.length === before.length) return { ok: false, error: '未找到匹配目标：' + removedLabel }
    saveSavedTargets(after)
    return { ok: true, removed: removedLabel, remaining: after.length }
  }
  const list = loadSavedTargets()
  return clean({
    ok: true,
    storePath: storePath(),
    count: list.length,
    targets: list.map((t) => ({
      name: t.name,
      baseUrl: t.baseUrl,
      keyMasked: maskKey(t.apiKey),
      keyFingerprint: keyFingerprintOf(t.apiKey),
      model: t.model,
      protocol: t.protocol,
    })),
  })
}

/** 列出历史报告（面板"查看报告"用）。 */
function listReports(limit = 20): Array<{ file: string; name: string; size: number; mtime: string }> {
  try {
    return fs.readdirSync(reportsDir())
      .filter((f) => f.endsWith('.md'))
      .map((f) => {
        const full = join(reportsDir(), f)
        const st = fs.statSync(full)
        return { file: full, name: f, size: st.size, mtime: st.mtime.toISOString() }
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime))
      .slice(0, limit)
  } catch {
    return []
  }
}

// ──────────────────────────── HTTP 面板接口 ────────────────────────────

const ROUTE_PREFIX = '/plugins/dsh-llm-audit'

async function readJson(req: IncomingMessage, limit = 65536): Promise<any> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > limit) throw new Error('请求体过大')
    chunks.push(buffer)
  }
  if (size === 0) return undefined
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}

/** 简单的同源校验：浏览器跨站请求一律拒绝；无 Origin 的 CLI/本地调用放行。 */
function isSameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin
  if (origin === undefined) return true
  const host = req.headers.host
  if (host === undefined) return false
  try { return new URL(origin).host === host } catch { return false }
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])

/**
 * 面板接口访问控制（同源 ≠ 认证——Origin 挡不住 curl）：
 * - 配置了 authToken：所有请求必须携带匹配的 x-audit-token 头（或 ?token=）；
 * - 未配置：只放行 loopback 访问；Host 是局域网/公网地址时一律 403，
 *   需要远程使用请配置 authToken。
 */
function guardPanelAccess(req: IncomingMessage, res: ServerResponse, config: Config): boolean {
  if (config.authToken !== '') {
    const url = new URL(req.url ?? '/', 'http://local')
    const presented = String(req.headers['x-audit-token'] ?? url.searchParams.get('token') ?? '')
    if (presented !== config.authToken) {
      sendJson(res, 403, { ok: false, error: '访问令牌缺失或不正确（x-audit-token）' })
      return false
    }
    return true
  }
  const host = String(req.headers.host ?? '').replace(/:\d+$/, '')
  if (!LOOPBACK_HOSTS.has(host)) {
    sendJson(res, 403, { ok: false, error: '面板接口默认仅允许本机访问（检测到非 loopback Host）。远程使用请在插件配置中设置 authToken，并在面板"⚙"里填同一令牌。' })
    return false
  }
  return true
}

// ──────────────────── 异步任务（长审计不能挂在一个 HTTP 请求上）────────────────────

interface JobState {
  runId: string
  kind: 'run' | 'probe'
  status: 'running' | 'done' | 'failed'
  startedAt: number
  finishedAt?: number
  result?: any
  error?: string
}

/** 最近若干个面板任务（本地单用户，保留 5 个足够）。 */
const jobs = new Map<string, JobState>()

function startPanelJob(config: Config, kind: JobState['kind'], args: RunArgs): JobState {
  const runId = args.runId ?? makeRunId()
  const job: JobState = { runId, kind, status: 'running', startedAt: Date.now() }
  jobs.set(runId, job)
  if (jobs.size > 5) {
    const oldest = [...jobs.entries()].sort((a, b) => a[1].startedAt - b[1].startedAt)[0]
    if (oldest !== undefined) jobs.delete(oldest[0])
  }
  void runAuditJob(config, { ...args, runId })
    .then((result) => {
      job.status = 'done'
      job.finishedAt = Date.now()
      job.result = result
    })
    .catch((e: unknown) => {
      job.status = 'failed'
      job.finishedAt = Date.now()
      job.error = errText(e)
    })
  return job
}

function jobPayload(runId: string): Record<string, unknown> {
  const job = jobs.get(runId)
  if (job === undefined) return { ok: false, error: '未找到该 runId 的任务（可能已被清理或尚未提交）' }
  const progress = progressRuns.get(runId)
  if (job.status === 'running') return { ok: true, status: 'running', runId, progress: progress ?? null }
  if (job.status === 'failed') return { ok: false, status: 'failed', runId, error: job.error, progress: progress ?? null }
  return { ok: true, status: 'done', runId, result: job.result }
}

// ──────────────────────────── 插件装配 ────────────────────────────

export function apply(ctx: Context, config: Config): void {
  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'llm_audit_run',
    description: 'LLM 端点安全审计（隔离子进程执行，支持 OpenAI/Claude/Grok/Gemini 原生协议，地址只填基础域名）：模型可用性、输出劫持（随机化探针）、流式与非流式一致性、上下文完整性（历史是否被改写）、提示词注入（双金丝雀）、多轮渐进越狱、回复内嵌指令全量扫描、延迟注入探测、隐藏系统提示提取（含 base64/ROT13 编码绕过）、身份与代次一致性（三连问检测后端轮换）、跨会话串话、工具调用、危险工具诱饵、扫盘/外传诱饵、七套诱发场景（含 SSRF/云元数据）、费用放大（token 灌水/max_tokens 钳制）、目标面暴露（管理端点/错误泄露/传输态势/TLS 告警）、Key 回显扫描；产出正式审计报告文件。',
    parameters: {
      targets: { type: 'json', description: '目标数组 [{name?,baseUrl,apiKey,model?,protocol?}]，protocol 可选 openai|anthropic|gemini（缺省按域名自动探测）；缺省用已保存目标' },
      useSaved: { type: 'boolean', description: '是否合并已保存目标（默认 true）' },
      preset: { type: 'string', description: '检查档位：quick=核心安全项（约 12 探测/模型，最省）/ standard=全项减诱发 / full=默认全量。与 checks 二选一' },
      checks: { type: 'json', description: '可选子集 [basic,integrity,system_prompt,injection,extraction,identity,stream,context,tools,danger,exfil,elicit,memory,multiturn,cost,delayed,exposure]' },
      saveReport: { type: 'boolean', description: '是否写报告文件（默认 true）' },
      includeReport: { type: 'boolean', description: '是否把报告正文放进结果（默认 false，减少不可信数据入上下文）' },
      maxModels: { type: 'number', description: '每个目标最多审计多少个模型（默认 12；模型多时可调大，进度见面板进度条）' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args: any): Promise<any> {
      return runAuditJob(config, {
        targets: asJson<AuditTarget[]>(args?.targets),
        useSaved: args?.useSaved,
        checks: asJson<string[]>(args?.checks) ?? (typeof args?.preset === 'string' && args.preset !== '' ? args.preset : undefined),
        saveReport: args?.saveReport,
        includeReport: args?.includeReport,
        maxModels: args?.maxModels,
      })
    },
  })), '@dsh-external/dsh-llm-audit: run tool')

  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'llm_audit_probe',
    description: 'LLM 端点快速探活（隔离执行，支持 OpenAI/Claude/Grok/Gemini）：只测连通性、模型列表与一次正常对话，不发安全探测。',
    parameters: {
      baseUrl: { type: 'string', required: true, description: '基础地址即可，如 https://api.anthropic.com（无需 /v1、/v1beta）' },
      apiKey: { type: 'string', required: true, description: 'API Key' },
      model: { type: 'string', description: '指定模型；缺省自动挑选' },
      protocol: { type: 'string', description: 'openai | anthropic | gemini；缺省按域名自动推断' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args: any): Promise<any> {
      if (!args?.baseUrl || !args?.apiKey) return { ok: false, error: 'baseUrl 与 apiKey 必填' }
      const r = await runAuditJob(config, {
        targets: [{ baseUrl: args.baseUrl, apiKey: args.apiKey, model: args.model, protocol: args.protocol }],
        useSaved: false,
        checks: [],
        saveReport: false,
      })
      return r
    },
  })), '@dsh-external/dsh-llm-audit: probe tool')

  ctx.effect(() => ctx.tools.register(defineTool({
    name: 'llm_audit_targets',
    description: '管理审计目标清单（~/.dsh/llm-audit/targets.json）：list 查看 / add 新增或更新 / remove 删除 / clear 清空；也可 reports 列出历史报告。',
    parameters: {
      action: { type: 'string', required: true, description: 'list | add | remove | clear | reports' },
      target: { type: 'json', description: 'add 时必填 {name?,baseUrl,apiKey,model?,protocol?}；baseUrl 只需基础地址，protocol 可选 openai|anthropic|gemini' },
      name: { type: 'string', description: 'remove 时按 name 或 baseUrl 匹配（兼容旧调用）' },
      baseUrl: { type: 'string', description: 'remove 精确匹配时与 keyFingerprint 一起使用' },
      keyFingerprint: { type: 'string', description: 'remove 时精确匹配：keyFingerprint + baseUrl，避免同名/同URL多Key误删' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args: any): Promise<any> {
      const action = String(args?.action ?? 'list')
      if (action === 'reports') return { ok: true, reportsDir: reportsDir(), reports: listReports() }
      return targetsCommand(action, {
        target: asJson<any>(args?.target),
        name: args?.name,
        baseUrl: args?.baseUrl,
        keyFingerprint: args?.keyFingerprint,
      })
    },
  })), '@dsh-external/dsh-llm-audit: targets tool')

  // ── UI 面板 HTTP 接口（与自验证插件同款守卫）──
  let routesRegistered = false
  const registerRoutes = (): void => {
    const webServer = (ctx as any).get('webServer') as { register: (route: unknown) => () => void } | undefined
    if (webServer === undefined || routesRegistered) return
    routesRegistered = true

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/targets',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (!guardPanelAccess(req, res, config)) return
          if (req.method === 'GET') return sendJson(res, 200, targetsCommand('list', {}))
          if (req.method === 'POST') {
            if (!isSameOrigin(req)) return sendJson(res, 403, { ok: false, error: '跨站请求被拒绝' })
            const body = (await readJson(req)) ?? {}
            return sendJson(res, 200, targetsCommand(String(body.action ?? 'list'), {
              target: body.target,
              name: body.name,
              baseUrl: body.baseUrl,
              keyFingerprint: body.keyFingerprint,
            }))
          }
          res.writeHead(405, { allow: 'GET, POST' })
          res.end()
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: targets route')

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/run',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (req.method !== 'POST') {
            res.writeHead(405, { allow: 'POST' })
            return res.end()
          }
          if (!guardPanelAccess(req, res, config)) return
          if (!isSameOrigin(req)) return sendJson(res, 403, { ok: false, error: '跨站请求被拒绝' })
          const body = (await readJson(req)) ?? {}
          // 长审计不能挂在一个 HTTP 请求上：立即返回 runId，结果走 /result 轮询（进度走 /progress）。
          const job = startPanelJob(config, 'run', {
            targets: Array.isArray(body.targets) ? body.targets : undefined,
            useSaved: body.useSaved,
            checks: Array.isArray(body.checks) ? body.checks : (typeof body.checks === 'string' ? body.checks : undefined),
            saveReport: body.saveReport,
            includeReport: body.includeReport !== false,
            maxModels: body.maxModels,
          })
          sendJson(res, 200, { ok: true, status: 'running', runId: job.runId, kind: job.kind })
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: run route')

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/probe',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (req.method !== 'POST') {
            res.writeHead(405, { allow: 'POST' })
            return res.end()
          }
          if (!guardPanelAccess(req, res, config)) return
          if (!isSameOrigin(req)) return sendJson(res, 403, { ok: false, error: '跨站请求被拒绝' })
          const body = (await readJson(req)) ?? {}
          if (!body.baseUrl || !body.apiKey) return sendJson(res, 400, { ok: false, error: '需要 baseUrl 与 apiKey' })
          const job = startPanelJob(config, 'probe', {
            targets: [{ baseUrl: body.baseUrl, apiKey: body.apiKey, model: body.model, protocol: body.protocol }],
            useSaved: false,
            checks: [],
            saveReport: false,
          })
          sendJson(res, 200, { ok: true, status: 'running', runId: job.runId, kind: job.kind })
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: probe route')

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/result',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (req.method !== 'GET') {
            res.writeHead(405, { allow: 'GET' })
            return res.end()
          }
          if (!guardPanelAccess(req, res, config)) return
          const url = new URL(req.url ?? '/', 'http://local')
          const runId = url.searchParams.get('runId')
          if (runId === null || runId === '') return sendJson(res, 400, { ok: false, error: '需要 runId 参数' })
          sendJson(res, 200, jobPayload(runId))
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: result route')

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/progress',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (req.method !== 'GET') {
            res.writeHead(405, { allow: 'GET' })
            return res.end()
          }
          if (!guardPanelAccess(req, res, config)) return
          sendJson(res, 200, progressSnapshot())
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: progress route')

    ctx.effect(() => webServer.register({
      kind: 'exact',
      path: ROUTE_PREFIX + '/reports',
      async handler(req: IncomingMessage, res: ServerResponse) {
        try {
          if (!guardPanelAccess(req, res, config)) return
          if (!isSameOrigin(req)) return sendJson(res, 403, { ok: false, error: '跨站请求被拒绝' })
          const url = new URL(req.url ?? '/', 'http://local')
          const file = url.searchParams.get('file')
          if (file !== null) {
            // 只允许读报告目录内的 .md/.json，防路径穿越。
            const resolved = join(reportsDir(), file.replace(/[\\/]+/g, ''))
            if (!resolved.startsWith(reportsDir()) || !/\.(md|json)$/.test(resolved)) {
              return sendJson(res, 400, { ok: false, error: '非法报告路径' })
            }
            const text = fs.readFileSync(resolved, 'utf8')
            return sendJson(res, 200, { ok: true, file: resolved, text })
          }
          sendJson(res, 200, { ok: true, reportsDir: reportsDir(), evidenceDir: evidenceDir(), reports: listReports() })
        } catch (e) {
          sendJson(res, 400, { ok: false, error: errText(e) })
        }
      },
    }), '@dsh-external/dsh-llm-audit: reports route')
  }

  registerRoutes()
  ctx.on('internal/service' as any, (serviceName: string) => {
    if (serviceName === 'webServer') registerRoutes()
  })
}

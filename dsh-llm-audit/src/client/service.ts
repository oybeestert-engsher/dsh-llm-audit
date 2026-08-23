/**
 * 浏览器侧数据通道：与宿主的 /plugins/dsh-llm-audit/* 路由对话。
 *
 * 宿主的文件存储是唯一事实来源，这里只是带显式刷新的调用层。
 * 注意：宿主回传的 excerpt 类字段是**已脱敏的不可信数据**，仅作证据展示。
 */

const BASE = '/plugins/dsh-llm-audit'

/** 支持的原生协议。 */
export type Protocol = 'openai' | 'anthropic' | 'gemini'

/** 厂商预设：地址栏只填基础地址，不要 /v1。 */
export const VENDOR_PRESETS: Array<{ label: string; baseUrl: string; protocol: Protocol; sampleModel: string }> = [
  { label: 'OpenAI', baseUrl: 'https://api.openai.com', protocol: 'openai', sampleModel: 'gpt-4o-mini' },
  { label: 'Claude', baseUrl: 'https://api.anthropic.com', protocol: 'anthropic', sampleModel: 'claude-sonnet-4-5' },
  { label: 'Grok', baseUrl: 'https://api.x.ai', protocol: 'openai', sampleModel: 'grok-4' },
  { label: 'Gemini', baseUrl: 'https://generativelanguage.googleapis.com', protocol: 'gemini', sampleModel: 'gemini-2.5-flash' },
]

export interface SavedTarget {
  name?: string
  baseUrl: string
  keyMasked: string
  keyFingerprint?: string
  model?: string
  protocol?: Protocol
}

export interface TargetDraft {
  name?: string
  baseUrl: string
  apiKey: string
  model?: string
  protocol?: Protocol
}

export interface Destination {
  target: string
  flags: string[]
}

export interface IntegritySummary {
  verdict: 'clean' | 'noisy' | 'contaminated' | 'hijacked' | 'unknown'
  compliance: string
  identicalReplies: number
  repeatedExtra?: string
  markers: string[]
}

export interface DangerSummary {
  verdict: 'safe' | 'risky' | 'unsafe' | 'unknown'
  calledByInjection: string[]
  spontaneousCalls: string[]
  fabricatedTools: string[]
}

export interface ExfilSummary {
  verdict: 'none' | 'attempted-scan' | 'attempted-exfil' | 'confirmed-chain' | 'unknown'
  destinations: Destination[]
  sensitivePaths: string[]
  canaryHit: boolean
}

export interface ElicitSummary {
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  flags: string[]
  detail?: string
  destinations: Destination[]
  hitSuites: Array<{ id: string; label: string; flags: string[] }>
}

export interface MemoryLeakSummary {
  leaked?: boolean
  detail?: string
}

export interface MultiTurnSummary {
  leaked?: boolean
  detail?: string
}

export interface CostAbuseSummary {
  tokenInflation?: boolean
  unclampedMaxTokens?: boolean
  reportedCompletionTokens?: number
  replyChars?: number
  detail?: string
}

/** 目标面暴露（管理端点/错误泄露/传输态势）。 */
export interface ExposureSummary {
  adminApi: { probed: number; exposed: Array<{ path: string; authRequired: boolean; hint: string }>; detail?: string }
  errorDisclosure: { probed: number; verbose: boolean; upstreamHint?: string; samples: string[]; detail?: string }
  transport: { scheme: string; plaintextPublic: boolean; corsWildcard?: boolean; serverBanner?: string; flags: string[]; detail?: string }
}

export interface KeyAnalysisSummary {
  length: number
  knownVendor?: string
  weakPatterns: string[]
  note: string
}

/** 单个模型的判定摘要。 */
export interface ModelSummary {
  model: string
  dangerous: boolean
  risk: { score: number; level: string; reasons: string[] }
  basicCall: boolean
  outputIntegrity?: IntegritySummary
  systemPromptRespected?: boolean
  injectionLeaked?: boolean
  hiddenPrompt?: { extracted: boolean; suspiciousTags: string[] }
  identityConsistent?: boolean
  identityVersionConsistent?: boolean
  toolCalls?: boolean
  dangerousTools?: DangerSummary
  exfiltration?: ExfilSummary
  elicitation?: ElicitSummary
  memoryLeak?: MemoryLeakSummary
  multiTurn?: MultiTurnSummary
  costAbuse?: CostAbuseSummary
  errors: string[]
}

/** 单目标摘要（含逐模型结果）。 */
export interface TargetSummary {
  name: string
  baseUrl: string
  keyMasked: string
  protocol: Protocol
  protocolSource: string
  apiRoot?: string
  reachable: boolean
  modelsOnEndpoint: number
  auditedModels: string[]
  skippedModels: Array<{ model: string; reason: string }>
  risk: { score: number; level: string; reasons: string[] }
  dangerousModels: Array<{ model: string; level: string; score: number; topReasons: string[] }>
  models: ModelSummary[]
  exposure?: ExposureSummary
  keyAnalysis?: KeyAnalysisSummary
  remediation: string[]
  errors: string[]
}

export interface RunResult {
  ok: boolean
  error?: string
  audited?: number
  auditedModels?: number
  dangerousModels?: Array<{ target: string; model: string; level: string; score: number; topReasons: string[] }>
  isolation?: string
  degradedReason?: string
  probeCount?: number
  untrustedDataNotice?: string
  summary?: TargetSummary[]
  evidenceFile?: string
  evidenceSha256?: string
  reportFiles?: string[]
  markdown?: string
  /** 危险 Key 自动台账（本轮有入账时）。 */
  dangerLedger?: { recorded: number; jsonlPath: string; indexPath: string }
  ledgerError?: string
}

/** 审计进度（供进度条）。 */
export interface ProgressState {
  runId: string
  phase: string
  targetIndex: number
  targetTotal: number
  targetName: string
  modelIndex: number
  modelTotal: number
  model: string
  probesDone: number
  probesTotal: number
  percent: number
  finished: boolean
  startedAt: number
  updatedAt: number
  error?: string
}

export interface ReportEntry {
  file: string
  name: string
  size: number
  mtime: string
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(BASE + path, { cache: 'no-store', ...init })
  const body = (await response.json()) as T & { ok?: boolean; error?: string }
  if (!response.ok) throw new Error(body?.error ?? `HTTP ${response.status}`)
  return body
}

export function listTargets(): Promise<{ ok: boolean; count: number; targets: SavedTarget[]; storePath?: string }> {
  return call('/targets')
}

export function addTarget(target: TargetDraft): Promise<{ ok: boolean; error?: string }> {
  return call('/targets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'add', target }) })
}

export function removeTarget(payload: { name?: string; baseUrl?: string; keyFingerprint?: string }): Promise<{ ok: boolean; error?: string }> {
  return call('/targets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'remove', ...payload }) })
}

export function clearTargets(): Promise<{ ok: boolean }> {
  return call('/targets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'clear' }) })
}

/** 跑完整审计（隔离子进程，逐模型）。 */
export function runAudit(body: { targets?: TargetDraft[]; useSaved?: boolean; checks?: string[]; maxModels?: number }): Promise<RunResult> {
  return call('/run', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
}

export function probe(target: TargetDraft): Promise<RunResult> {
  return call('/probe', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(target) })
}

/** 轮询当前审计进度。 */
export function fetchProgress(): Promise<{ ok: boolean; active: ProgressState | null; recent: ProgressState[] }> {
  return call('/progress')
}

export function listReports(): Promise<{ ok: boolean; reportsDir: string; evidenceDir: string; reports: ReportEntry[] }> {
  return call('/reports')
}

export function readReport(name: string): Promise<{ ok: boolean; file: string; text: string }> {
  return call('/reports?file=' + encodeURIComponent(name))
}

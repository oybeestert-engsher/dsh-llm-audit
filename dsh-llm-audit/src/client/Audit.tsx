/**
 * composer 触发器 + LLM 端点安全审计面板。
 *
 * 风格与同排的自验证按钮完全一致：触发器用同一套 DSW token pill，面板自带固定
 * 浅色配色（白底深字）。
 *
 * 展示原则：
 * - excerpt 类内容都是宿主**已脱敏**的不可信数据；端点原文只在证据文件里；
 * - 审计只记录端点请求的工具调用，从不执行；
 * - 报告预览用内置迷你 markdown 渲染器（React 文本节点天然转义，不解释 HTML，
 *   端点可控文本无法借预览注入）；宽表格横向滚动而不是折行。
 */

import { useCallback, useEffect, useRef, useState, type CSSProperties, type JSX, type ReactNode } from 'react'
import {
  addTarget, awaitJob, clearTargets, discoverModels, fetchProgress, getAuthToken, listReports, listTargets, probe, readReport, removeTarget, runAudit, setAuthToken,
  type DiscoverResult,
  VENDOR_PRESETS,
  type ModelSummary, type ProgressState, type Protocol, type ReportEntry, type RunResult, type SavedTarget, type TargetSummary,
} from './service.ts'
/* ── 共享 pill 触发器（DSW token，与自验证/融合触发器同款）── */
const triggerBase: CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: 4, height: 28, maxWidth: 200,
  padding: '0 10px', boxSizing: 'border-box',
  border: '1px solid var(--dsw-alias-line-strong)', borderRadius: 999,
  background: 'var(--dsw-alias-bg-module)', color: 'var(--dsw-alias-label-secondary)',
  font: 'inherit', fontSize: 12, lineHeight: 1, cursor: 'pointer',
  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
}
const triggerActive: CSSProperties = {
  ...triggerBase,
  borderColor: 'var(--dsw-alias-state-business-primary)',
  color: 'var(--dsw-alias-state-business-primary)',
  background: 'color-mix(in srgb, var(--dsw-alias-state-business-primary) 10%, transparent)',
}
const dot: CSSProperties = { width: 6, height: 6, borderRadius: '50%', background: 'currentColor', flex: 'none' }

/* ── 面板：固定浅色配色，与自验证面板同款 ── */
const panelStyle: CSSProperties = {
  position: 'fixed', right: 16, bottom: 88, width: 540,
  maxWidth: 'calc(100vw - 32px)', maxHeight: 'calc(100vh - 140px)',
  boxSizing: 'border-box', display: 'flex', flexDirection: 'column',
  background: '#ffffff', color: '#1a1a1f', border: '1px solid #e2e2ea', borderRadius: 12,
  padding: '14px 16px', zIndex: 1000, boxShadow: '0 16px 48px rgba(20, 20, 40, 0.28)',
  fontFamily: 'inherit', fontSize: 13, overflow: 'hidden',
}
const panelTitle: CSSProperties = { margin: 0, fontSize: 15, fontWeight: 600, color: '#1a1a1f' }
const closeBtn: CSSProperties = {
  border: 'none', background: 'transparent', color: '#66667a', cursor: 'pointer',
  borderRadius: 6, padding: 4, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flex: 'none',
}
const sectionLabel: CSSProperties = { fontSize: 13, fontWeight: 600, color: '#1a1a1f', margin: '0 0 6px' }
const inputStyle: CSSProperties = {
  flex: 1, minWidth: 0, padding: '5px 8px', borderRadius: 6, border: '1px solid #c9c9d4',
  background: '#ffffff', color: '#1a1a1f', fontSize: 12, boxSizing: 'border-box',
}
const selectStyle: CSSProperties = { ...inputStyle, flex: 'none', width: 118 }
const hintStyle: CSSProperties = { fontSize: 11, lineHeight: 1.55, color: '#66667a', overflowWrap: 'anywhere' }
const noticeStyle: CSSProperties = {
  ...hintStyle, padding: '7px 9px', borderLeft: '3px solid #2f6bff', borderRadius: 4,
  background: '#f3f6ff', color: '#46506a', margin: '8px 0 0',
}
const warnStyle: CSSProperties = { ...noticeStyle, borderLeftColor: '#c1440e', background: '#fff5ef', color: '#7a3b12' }
const errorStyle: CSSProperties = { color: '#d33', fontSize: 12, margin: '8px 0 0', overflowWrap: 'anywhere' }

const btn: CSSProperties = {
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 4,
  height: 28, padding: '0 12px', borderRadius: 8, border: '1px solid transparent',
  fontSize: 12, lineHeight: 1, cursor: 'pointer', whiteSpace: 'nowrap', flex: 'none',
}
const btnGhost: CSSProperties = { ...btn, background: 'transparent', color: '#66667a' }
const btnOutline: CSSProperties = { ...btn, background: '#ffffff', borderColor: '#c9c9d4', color: '#333340' }
const btnPrimary: CSSProperties = { ...btn, background: '#2f6bff', borderColor: '#2f6bff', color: '#ffffff' }
const btnTiny: CSSProperties = { ...btnGhost, height: 22, padding: '0 6px', fontSize: 11 }
const chipStyle: CSSProperties = { ...btn, height: 24, padding: '0 10px', borderRadius: 999, background: '#f4f6fb', borderColor: '#dfe3ef', color: '#33406a', fontSize: 11 }
const disabled: CSSProperties = { opacity: 0.5, cursor: 'not-allowed' }

const rowStyle: CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px',
  border: '1px solid #ececf2', borderRadius: 8, marginBottom: 6, background: '#fbfbfd',
}
const badge = (bg: string, fg: string): CSSProperties => ({
  flex: 'none', fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 999, background: bg, color: fg,
})

const PROTOCOL_LABEL: Record<Protocol, string> = { openai: 'OpenAI 兼容', anthropic: 'Claude 原生', gemini: 'Gemini 原生' }

function riskPalette(level: string): { bg: string; fg: string } {
  if (level.includes('严重')) return { bg: '#ffe5e5', fg: '#a11111' }
  if (level.includes('高')) return { bg: '#ffece2', fg: '#c1440e' }
  if (level.includes('中')) return { bg: '#fff4e0', fg: '#8a5a00' }
  if (level.includes('低')) return { bg: '#e7f7ec', fg: '#1a7f37' }
  return { bg: '#eef0f4', fg: '#55566a' }
}

/* ═══════════════ 迷你 markdown 渲染器 ═══════════════
 * 只支持报告实际用到的语法：# 标题、> 引用、- 列表、| 表格 |、--- 分隔线、段落、`code`、**粗体**。
 * 安全性：全部输出走 React 文本节点（自动转义），绝不解释 HTML —— 端点可控文本无法注入。 */

/** 行内格式：`code` 与 **bold**。 */
function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = []
  const re = /`([^`]+)`|\*\*([^*]+)\*\*/g
  let last = 0
  let m: RegExpExecArray | null
  let i = 0
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index))
    if (m[1] !== undefined) out.push(<code key={`${keyBase}-c${i}`} style={{ background: '#f2f3f7', borderRadius: 4, padding: '1px 5px', fontSize: '0.92em', fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', overflowWrap: 'break-word' }}>{m[1]}</code>)
    else out.push(<strong key={`${keyBase}-b${i}`}>{m[2]}</strong>)
    last = re.lastIndex
    i++
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

function splitRow(line: string): string[] {
  let s = line.trim()
  if (s.startsWith('|')) s = s.slice(1)
  if (s.endsWith('|')) s = s.slice(0, -1)
  return s.split('|').map((c) => c.trim())
}

const isTableSep = (line: string): boolean => /^\s*\|?[\s:|-]+\|?\s*$/.test(line) && line.includes('-')

function MarkdownView({ text }: { text: string }): JSX.Element {
  const lines = text.split('\n')
  const blocks: ReactNode[] = []
  let i = 0
  let key = 0
  while (i < lines.length) {
    const line = lines[i]
    // 表格块
    if (line.trim().startsWith('|') && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const header = splitRow(line)
      i += 2
      const rows: string[][] = []
      while (i < lines.length && lines[i].trim().startsWith('|')) { rows.push(splitRow(lines[i])); i++ }
      blocks.push(
        <div key={key++} style={{ overflowX: 'auto', margin: '6px 0', border: '1px solid #ececf2', borderRadius: 8 }}>
          <table style={{ borderCollapse: 'collapse', fontSize: 11.5, lineHeight: 1.5, width: '100%', minWidth: 480 }}>
            <thead>
              <tr>{header.map((h, hi) => (
                <th key={hi} style={{ position: 'sticky', top: 0, textAlign: 'left', padding: '5px 8px', background: '#f7f7fa', borderBottom: '1px solid #e2e2ea', whiteSpace: 'nowrap', fontWeight: 600 }}>{inline(h, `th${hi}`)}</th>
              ))}</tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} style={{ background: ri % 2 === 1 ? '#fbfbfd' : '#fff' }}>
                  {header.map((_, ci) => (
                    <td key={ci} style={{ padding: '5px 8px', borderBottom: '1px solid #f0f0f4', whiteSpace: r[ci] !== undefined && r[ci].length <= 14 ? 'nowrap' : 'normal', overflowWrap: 'break-word' }}>{r[ci] !== undefined ? inline(r[ci], `td${ri}-${ci}`) : ''}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      )
      continue
    }
    // 标题
    const h = /^(#{1,4})\s+(.*)$/.exec(line)
    if (h !== null) {
      const level = h[1].length
      const style: CSSProperties = level === 1 ? { fontSize: 15, fontWeight: 700, margin: '10px 0 6px' }
        : level === 2 ? { fontSize: 13.5, fontWeight: 700, margin: '10px 0 4px', paddingBottom: 3, borderBottom: '1px solid #ececf2' }
        : { fontSize: 12.5, fontWeight: 600, margin: '8px 0 4px' }
      blocks.push(<div key={key++} style={style}>{inline(h[2], `h${key}`)}</div>)
      i++
      continue
    }
    // 分隔线
    if (/^\s*---+\s*$/.test(line)) { blocks.push(<hr key={key++} style={{ border: 'none', borderTop: '1px solid #ececf2', margin: '10px 0' }} />); i++; continue }
    // 引用
    if (line.trim().startsWith('>')) {
      const buf: string[] = []
      while (i < lines.length && lines[i].trim().startsWith('>')) { buf.push(lines[i].trim().replace(/^>\s?/, '')); i++ }
      blocks.push(
        <blockquote key={key++} style={{ margin: '6px 0', padding: '6px 10px', borderLeft: '3px solid #c9d4f5', background: '#f7f9ff', borderRadius: 4, fontSize: 12, lineHeight: 1.65, color: '#33334a' }}>
          {buf.map((b, bi) => <div key={bi}>{inline(b, `q${bi}`)}</div>)}
        </blockquote>,
      )
      continue
    }
    // 列表
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*]\s+/, '')); i++ }
      blocks.push(
        <ul key={key++} style={{ margin: '4px 0', paddingLeft: 18, fontSize: 12, lineHeight: 1.7, color: '#26263a' }}>
          {items.map((it, ii) => <li key={ii} style={{ marginBottom: 2 }}>{inline(it, `li${ii}`)}</li>)}
        </ul>,
      )
      continue
    }
    // 缩进子列表/续行（两个以上空格开头）
    if (/^\s{2,}\S/.test(line)) {
      const buf: string[] = []
      while (i < lines.length && /^\s{2,}\S/.test(lines[i])) { buf.push(lines[i].trim()); i++ }
      blocks.push(
        <ul key={key++} style={{ margin: '0 0 4px', paddingLeft: 30, fontSize: 11.5, lineHeight: 1.65, color: '#55566a' }}>
          {buf.map((it, ii) => <li key={ii}>{inline(it, `s${ii}`)}</li>)}
        </ul>,
      )
      continue
    }
    // 空行
    if (line.trim() === '') { i++; continue }
    // 段落
    const buf: string[] = []
    while (i < lines.length && lines[i].trim() !== '' && !/^\s*(#{1,4}\s|[-*]\s|>|\||---+\s*$)/.test(lines[i])) { buf.push(lines[i]); i++ }
    blocks.push(<p key={key++} style={{ margin: '4px 0', fontSize: 12, lineHeight: 1.7, color: '#26263a' }}>{inline(buf.join('\n'), `p${key}`)}</p>)
  }
  return <div style={{ fontSize: 12 }}>{blocks}</div>
}

/** 报告抽屉：覆盖面板主体，带复制/下载，消灭双层滚动与"内容在视口外"。 */
function ReportDrawer({ title, text, onClose }: { title: string; text: string; onClose: () => void }): JSX.Element {
  const [copied, setCopied] = useState(false)
  const onCopy = async (): Promise<void> => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* 剪贴板不可用时忽略 */ }
  }
  const onDownload = (): void => {
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = title.replace(/[^\w.-]+/g, '_') + '.md'
    a.click()
    URL.revokeObjectURL(a.href)
  }
  return (
    <div style={{ position: 'absolute', inset: 0, zIndex: 20, background: '#ffffff', borderRadius: 12, display: 'flex', flexDirection: 'column', padding: '14px 16px', boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 'none' }}>
        <span style={{ ...panelTitle, fontSize: 13, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{title}</span>
        <button type="button" style={btnTiny} onClick={() => void onCopy()}>{copied ? '已复制 ✓' : '复制'}</button>
        <button type="button" style={btnTiny} onClick={onDownload}>下载 .md</button>
        <button type="button" style={btnTiny} onClick={onClose}>收起</button>
      </div>
      <div style={{
        flex: 1, minHeight: 0, marginTop: 8, overflowY: 'auto', overflowX: 'hidden', overscrollBehavior: 'contain',
        font: 'inherit', fontSize: 12.5, lineHeight: 1.7, color: '#26263a',
        wordBreak: 'normal', overflowWrap: 'break-word', lineBreak: 'strict', textAlign: 'left',
      }}>
        <MarkdownView text={text} />
      </div>
    </div>
  )
}

/** 结论横幅：第一眼就是整体判定。 */
function ConclusionBanner({ result }: { result: RunResult }): JSX.Element {
  const worst = (result.summary ?? []).reduce((acc, t) => Math.max(acc, t.risk.score), 0)
  const level = worst <= 19 ? '低风险' : worst <= 44 ? '中风险' : worst <= 69 ? '高风险' : '严重'
  const pal = riskPalette(level)
  const dangerous = result.dangerousModels?.length ?? 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', borderRadius: 8, background: pal.bg, margin: '10px 0 0', flexWrap: 'wrap' }}>
      <span style={{ fontSize: 13, fontWeight: 700, color: pal.fg }}>整体：{level}</span>
      <span style={{ ...hintStyle, color: '#33334a' }}>
        危险模型 <strong style={{ color: dangerous > 0 ? '#a11111' : '#1a7f37' }}>{dangerous}</strong> / {result.auditedModels ?? 0}
        {' · '}目标 {result.audited ?? 0} · 探测 {result.probeCount ?? 0} 次
      </span>
      {result.degradedReason !== undefined ? <span style={{ color: '#c1440e', fontSize: 11 }}>隔离降级</span> : null}
    </div>
  )
}

/** 检查项徽标：ok / warn / bad / na 四态小圆点 + 两字词。 */
type CheckState = 'ok' | 'warn' | 'bad' | 'na'
const stateColor: Record<CheckState, string> = { ok: '#1a7f37', warn: '#8a5a00', bad: '#a11111', na: '#b9bac6' }
const stateBg: Record<CheckState, string> = { ok: '#eaf6ee', warn: '#fdf3df', bad: '#fdeaea', na: '#f2f3f7' }

function CheckPill({ label, state, title }: { label: string; state: CheckState; title?: string }): JSX.Element {
  return (
    <span title={title ?? ''} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '1px 7px 1px 5px', borderRadius: 999, background: stateBg[state], fontSize: 10.5, lineHeight: '16px', color: '#3a3a48' }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: stateColor[state], flex: 'none' }} />
      {label}
    </span>
  )
}

/** 单模型的检查项徽标网格（窄面板下自然换行，语义不丢）。 */
function modelChecks(m: ModelSummary): Array<{ label: string; state: CheckState; title?: string }> {
  const checks: Array<{ label: string; state: CheckState; title?: string }> = []
  checks.push({ label: '调用', state: m.basicCall ? 'ok' : 'bad', title: m.basicCall ? '基础对话正常' : '基础对话失败' })
  const oi = m.outputIntegrity
  checks.push({
    label: '输出', state: oi === undefined ? 'na' : oi.verdict === 'clean' ? 'ok' : oi.verdict === 'noisy' ? 'warn' : 'bad',
    title: oi === undefined ? '未执行' : `${oi.verdict} ${oi.compliance}`,
  })
  const singleLeak = m.injectionLeaked === true
  const mtLeak = m.multiTurn?.leaked === true
  const riHit = (m.replyInjection?.hits.length ?? 0) > 0 || m.delayedInjection?.verdict === 'injected'
  checks.push({
    label: '注入',
    state: (singleLeak || mtLeak || riHit) ? 'bad' : (m.injectionLeaked === false || m.multiTurn !== undefined || m.replyInjection !== undefined) ? 'ok' : 'na',
    title: mtLeak ? '多轮渐进泄漏（单轮未漏）' : singleLeak ? '单轮注入泄漏' : riHit ? '回复内嵌指令/延迟注入' : '抵抗',
  })
  const hp = m.hiddenPrompt
  checks.push({
    label: '隐提',
    state: hp === undefined ? 'na'
      : hp.extracted ? (hp.suspiciousTags.length > 0 ? 'bad' : 'warn')
      : hp.suspiciousTags.includes('fixed_short_reply') ? 'warn'
      : 'ok',
    title: hp?.suspiciousTags.join(', ') || undefined,
  })
  checks.push({
    label: '身份',
    state: m.identityRotating === true ? 'warn'
      : m.identityConsistent === false ? 'bad'
      : m.identityConsistent === true && m.identityVersionConsistent === false ? 'warn'
      : m.identityConsistent === true ? 'ok'
      : 'na',
    title: m.identityRotating === true ? '多次询问自报身份不一致——后端在轮换模型' : m.identityConsistent === true && m.identityVersionConsistent === false ? '同厂商但代次不符' : undefined,
  })
  const sc = m.streamCheck
  checks.push({
    label: '流式',
    state: sc === undefined ? 'na' : sc.verdict === 'consistent' ? 'ok' : sc.verdict === 'injected' || sc.verdict === 'failed' ? 'warn' : sc.verdict === 'hijacked' ? 'bad' : 'na',
    title: sc?.detail,
  })
  const ctx = m.contextIntegrity
  checks.push({
    label: '上下文',
    state: ctx === undefined ? 'na' : ctx.preserved === true ? 'ok' : ctx.preserved === false ? 'bad' : 'na',
    title: ctx?.detail,
  })
  checks.push({ label: '记忆', state: m.memoryLeak?.leaked === true ? 'bad' : m.memoryLeak !== undefined ? 'ok' : 'na', title: m.memoryLeak?.detail })
  checks.push({ label: '诱饵', state: m.dangerousTools === undefined ? 'na' : m.dangerousTools.verdict === 'safe' ? 'ok' : m.dangerousTools.verdict === 'risky' ? 'warn' : 'bad', title: m.dangerousTools?.verdict })
  const ex = m.exfiltration
  checks.push({ label: '外传', state: ex === undefined ? 'na' : ex.verdict === 'none' ? 'ok' : ex.verdict === 'attempted-scan' ? 'warn' : 'bad', title: ex?.verdict })
  const el = m.elicitation
  checks.push({ label: '诱发', state: el === undefined ? 'na' : el.verdict === 'clean' ? 'ok' : el.verdict === 'suspicious' ? 'warn' : 'bad', title: el?.detail })
  const cost = m.costAbuse
  checks.push({ label: '费用', state: cost === undefined ? 'na' : (cost.tokenInflation === true || cost.unclampedMaxTokens === true) ? 'bad' : 'ok', title: cost?.detail })
  return checks
}

/** composer 触发器：坐在自验证按钮旁边。 */
export function AuditTrigger(): JSX.Element {
  const [open, setOpen] = useState(false)
  const [count, setCount] = useState(0)

  const refreshCount = useCallback(() => {
    listTargets().then((r) => setCount(r.count ?? 0)).catch(() => undefined)
  }, [])
  useEffect(() => { refreshCount() }, [refreshCount])

  return (
    <>
      <button
        type="button"
        style={count > 0 ? triggerActive : triggerBase}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => { setOpen(true); refreshCount() }}
        title="LLM 端点安全审计：逐模型探测输出劫持、提示词注入、多轮越狱、跨会话串话、危险工具、扫盘外传、SSRF 诱发、费用放大与管理面暴露"
      >
        端点审计
        {count > 0 ? <span style={dot} /> : null}
      </button>
      {open ? <AuditPanel onClose={() => { setOpen(false); refreshCount() }} onCountChange={setCount} /> : null}
    </>
  )
}

/** 审计进度条：轮询宿主 /progress，显示"第几个模型 / 共几个"。 */
function ProgressBar({ progress }: { progress: ProgressState }): JSX.Element {
  const pct = Math.max(2, Math.min(100, progress.percent))
  const elapsed = Math.round((Date.now() - progress.startedAt) / 1000)
  return (
    <div style={{ margin: '8px 0 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
        <span style={{ ...hintStyle, color: '#33406a', fontWeight: 600 }}>
          {progress.phase}
          {progress.modelTotal > 0 ? ` · 模型 ${progress.modelIndex}/${progress.modelTotal}` : ''}
          {progress.model !== '' ? ` · ${progress.model}` : ''}
        </span>
        <span style={hintStyle}>{pct}% · {elapsed}s</span>
      </div>
      <div style={{ height: 6, borderRadius: 999, background: '#eceef5', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: 'linear-gradient(90deg,#2f6bff,#6f9bff)', transition: 'width .35s ease' }} />
      </div>
      <div style={{ ...hintStyle, marginTop: 3 }}>
        目标 {progress.targetIndex}/{progress.targetTotal}
        {progress.targetName !== '' ? `（${progress.targetName}）` : ''} · 探测 {progress.probesDone}/{progress.probesTotal}
      </div>
    </div>
  )
}

/** 审计面板。 */
function AuditPanel({ onClose, onCountChange }: { onClose: () => void; onCountChange: (n: number) => void }): JSX.Element {
  const [targets, setTargets] = useState<SavedTarget[]>([])
  const [storePath, setStorePath] = useState('')
  const [reports, setReports] = useState<ReportEntry[]>([])
  const [name, setName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [protocol, setProtocol] = useState<'' | Protocol>('')
  const [maxModels, setMaxModels] = useState('12')
  const [preset, setPreset] = useState<'full' | 'standard' | 'quick'>('full')
  /** 模型选择流程：探测结果 + 用户勾选（模型太多时先挑再审）。 */
  const [pick, setPick] = useState<DiscoverResult | null>(null)
  const [pickSelected, setPickSelected] = useState<string[]>([])
  const [token, setToken] = useState(getAuthToken())
  const [tokenOpen, setTokenOpen] = useState(false)
  const [busy, setBusy] = useState<null | string>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RunResult | null>(null)
  const [viewer, setViewer] = useState<{ title: string; text: string } | null>(null)
  const [progress, setProgress] = useState<ProgressState | null>(null)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [descOpen, setDescOpen] = useState(false)
  const [synced, setSynced] = useState(false)
  const resultsRef = useRef<HTMLDivElement | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const reload = useCallback(async () => {
    try {
      const r = await listTargets()
      setTargets(r.targets ?? [])
      setStorePath(r.storePath ?? '')
      onCountChange(r.count ?? 0)
    } catch (e: unknown) { setError(String(e)) }
    try {
      const rep = await listReports()
      setReports(rep.reports ?? [])
    } catch { /* 报告目录还不存在时忽略 */ }
    setSynced(true)
    setTimeout(() => setSynced(false), 1500)
  }, [onCountChange])

  useEffect(() => { void reload() }, [reload])

  // 运行期间轮询进度；结束即停。
  const startPolling = useCallback(() => {
    if (pollRef.current !== null) return
    pollRef.current = setInterval(() => {
      fetchProgress().then((p) => {
        setProgress(p.active ?? (p.recent[0]?.finished === false ? p.recent[0] : null))
      }).catch(() => undefined)
    }, 600)
  }, [])
  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) { clearInterval(pollRef.current); pollRef.current = null }
    setProgress(null)
  }, [])
  useEffect(() => () => { if (pollRef.current !== null) clearInterval(pollRef.current) }, [])

  // 跑完自动滚到结果区
  useEffect(() => {
    if (result !== null) resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [result])

  const draft = () => ({
    name: name.trim() || undefined,
    baseUrl: baseUrl.trim(),
    apiKey: apiKey.trim(),
    model: model.trim() || undefined,
    protocol: protocol === '' ? undefined : protocol,
  })

  const applyPreset = (preset: typeof VENDOR_PRESETS[number]): void => {
    setBaseUrl(preset.baseUrl)
    setProtocol(preset.protocol)
    if (name.trim() === '') setName(preset.label)
  }

  const onAdd = async (): Promise<void> => {
    if (baseUrl.trim() === '' || apiKey.trim() === '') { setError('地址与 Key 必填'); return }
    setBusy('add'); setError(null)
    try {
      const r = await addTarget(draft())
      if (r.ok === false) throw new Error(r.error ?? '保存失败')
      setName(''); setBaseUrl(''); setApiKey(''); setModel(''); setProtocol('')
      await reload()
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null) }
  }

  const onRemove = async (t: SavedTarget): Promise<void> => {
    setBusy('remove'); setError(null)
    try {
      // 优先用 URL + Key 指纹精确删除；旧数据没有指纹时退回 name/baseUrl。
      if (t.keyFingerprint !== undefined && t.keyFingerprint !== '') {
        await removeTarget({ baseUrl: t.baseUrl, keyFingerprint: t.keyFingerprint })
      } else {
        await removeTarget({ name: t.name ?? t.baseUrl })
      }
      await reload()
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null) }
  }

  const onClear = async (): Promise<void> => {
    if (!window.confirm('确定清空全部已保存目标吗？此操作不可恢复。')) return
    setBusy('clear'); setError(null)
    try { await clearTargets(); await reload() } catch (e: unknown) { setError(String(e)) } finally { setBusy(null) }
  }

  /** 只清空表单里已填的内容（不影响已保存目标与模型上限），方便换一个 key 重填。 */
  const onResetForm = (): void => {
    setName(''); setBaseUrl(''); setApiKey(''); setModel(''); setProtocol('')
    setError(null)
  }

  const onProbe = async (): Promise<void> => {
    if (baseUrl.trim() === '' || apiKey.trim() === '') { setError('快速探活需要在表单里填地址与 Key'); return }
    setBusy('probe'); setError(null); setResult(null); setViewer(null)
    startPolling()
    try {
      const { runId } = await probe(draft())
      const r = await awaitJob(runId)
      setResult(r)
      if (r.ok === false) setError(r.error ?? '探活失败')
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null); stopPolling() }
  }

  /** 获取模型清单（只探测不审计），进入勾选流程。 */
  const onPickModels = async (): Promise<void> => {
    if (baseUrl.trim() === '' || apiKey.trim() === '') { setError('选择模型需要在表单里填地址与 Key'); return }
    setBusy('pick'); setError(null); setPick(null); setPickSelected([]); setResult(null)
    try {
      const d = draft()
      const r = await discoverModels(d)
      if (r.ok === false) throw new Error(r.errors?.join('；') ?? '模型清单获取失败')
      if (r.models.length === 0) throw new Error('端点没有可审计的对话模型' + (r.skipped.length > 0 ? `（${r.skipped.length} 个非对话模型已跳过）` : ''))
      // 预选：按主力优先排序取「模型上限」个，用户可增删
      const cap = Number.isFinite(Number(maxModels)) && Number(maxModels) > 0 ? Number(maxModels) : 12
      // 记录发现时的表单内容：防止探测 A 后改填 B、拿 A 的模型清单去审 B
      setPick({ ...r, origin: JSON.stringify([d.baseUrl, d.apiKey, d.protocol]) })
      setPickSelected(r.models.slice(0, Math.min(cap, r.models.length)))
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null) }
  }

  const togglePick = (m: string): void => {
    setPickSelected((prev) => (prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]))
  }

  /** 审计用户勾选的模型（useSaved=false，只审表单里这个目标）。 */
  const onRunPicked = async (): Promise<void> => {
    if (pick === null || pickSelected.length === 0) { setError('先勾选要审计的模型'); return }
    const d = draft()
    if (pick.origin !== undefined && pick.origin !== JSON.stringify([d.baseUrl, d.apiKey, d.protocol])) {
      setError('表单里的地址/Key 已改动，与探测时不一致——请重新点「选择模型…」探测后再审计')
      return
    }
    setBusy('runpicked'); setError(null); setResult(null); setViewer(null)
    startPolling()
    try {
      const { runId } = await runAudit({
        targets: [{ name: d.name, baseUrl: d.baseUrl, apiKey: d.apiKey, protocol: d.protocol, models: [...pickSelected] }],
        useSaved: false,
        checks: preset,
      })
      const r = await awaitJob(runId)
      setResult(r)
      if (r.ok === false) setError(r.error ?? '审计失败')
      await reload()
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null); stopPolling() }
  }

  const onRun = async (): Promise<void> => {
    const inline = baseUrl.trim() !== '' && apiKey.trim() !== '' ? [draft()] : undefined
    if (inline === undefined && targets.length === 0) { setError('没有目标：先添加一个，或在表单里直接填地址与 Key'); return }
    setBusy('run'); setError(null); setResult(null); setViewer(null)
    startPolling()
    try {
      const cap = Number(maxModels)
      const { runId } = await runAudit({
        targets: inline,
        useSaved: true,
        checks: preset,
        maxModels: Number.isFinite(cap) && cap > 0 ? cap : undefined,
      })
      const r = await awaitJob(runId)
      setResult(r)
      if (r.ok === false) setError(r.error ?? '审计失败')
      await reload()
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null); stopPolling() }
  }

  const onViewReport = async (entry: ReportEntry): Promise<void> => {
    setBusy('report'); setError(null)
    try {
      const r = await readReport(entry.name)
      setViewer({ title: entry.name, text: r.text })
    } catch (e: unknown) { setError(String(e)) } finally { setBusy(null) }
  }

  const running = busy !== null
  const s = (base: CSSProperties): CSSProperties => (running ? { ...base, ...disabled } : base)

  return (
    <div role="dialog" aria-label="LLM 端点安全审计" style={{ ...panelStyle, position: 'fixed' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flex: 'none' }}>
        <h2 style={panelTitle}>LLM 端点安全审计</h2>
        <button
          type="button"
          style={{ ...btnTiny, color: token !== '' ? '#1a7f37' : undefined }}
          onClick={() => setTokenOpen((v) => !v)}
          title={token !== '' ? '已配置面板访问令牌' : '面板访问令牌（宿主配置 authToken 时必填；本机访问无需配置）'}
        >
          ⚙{token !== '' ? '●' : ''}
        </button>
        <button type="button" onClick={onClose} style={closeBtn} aria-label="关闭">✕</button>
      </div>
      {tokenOpen ? (
        <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
          <input
            style={inputStyle}
            type="password"
            placeholder="面板访问令牌（宿主 authToken 配置；保存在本浏览器）"
            value={token}
            autoComplete="off"
            onChange={(e) => { setToken(e.target.value); setAuthToken(e.target.value) }}
          />
        </div>
      ) : null}
      <p style={{ ...hintStyle, margin: '6px 0 8px' }}>
        支持 OpenAI / Claude / Grok / Gemini，<strong>只填基础地址</strong>；同一 key 下<strong>逐模型点名</strong>。
        <button type="button" style={{ ...btnTiny, marginLeft: 6 }} onClick={() => setDescOpen((v) => !v)}>{descOpen ? '收起说明' : '检测项说明 ▾'}</button>
      </p>
      {descOpen ? (
        <p style={noticeStyle}>
          逐模型检测：输出劫持（随机化探针）、流式 vs 非流式一致性、上下文完整性（历史是否被改写）、提示词注入（双金丝雀）、
          多轮渐进越狱（命中复验）、回复内嵌指令全量扫描 + 延迟注入探测（中转在普通回复里塞 agent 指令）、
          隐藏系统提示提取（含 base64/ROT13 绕过）、身份与代次一致性（三连问检测后端轮换）、
          跨会话串话、工具调用、危险工具诱饵、扫盘→外传链（金丝雀路径与外发地址逐轮随机）、七套诱发场景
          （关键词猎取 / 命令篡改 / 下游注入 / 凭据钓鱼 / 静默回传 / 分阶段侦察 / SSRF 云元数据）、费用放大（token 灌水 / max_tokens 钳制）。
          目标级检测：管理面暴露（one-api/new-api 计费端点）、错误信息泄露（堆栈/上游透传）、传输态势（明文 http/CORS/server 头/TLS 告警）、
          Key 回显扫描、Key 形态分析、模型目录注水。
          所有探测在隔离子进程执行；端点原文只留证据文件，引文已脱敏；端点要求的工具调用一律只记录、不执行。
        </p>
      ) : null}

      <div style={{ overflowY: 'auto', overflowX: 'hidden', flex: 1, minHeight: 0, margin: '0 -2px', padding: '0 2px' }}>
        <p style={sectionLabel}>已保存目标（{targets.length}）</p>
        {targets.length === 0 ? (
          <p style={hintStyle}>暂无目标。下面填地址与 Key 后「添加」，或直接「运行完整审计」审计表单里这一个。</p>
        ) : (
          <>
            <p style={{ ...noticeStyle, borderLeftColor: '#b3261e', background: '#fff5f5', color: '#b3261e', fontWeight: 600 }}>
              ⚠️ 点“删除”会同步从本地文件移除该 Key：<code>{storePath || '~/.dsh/llm-audit/targets.json'}</code>
            </p>
            <p style={hintStyle}>有已保存目标时，「运行完整审计」会审计表单目标（若有）+ 全部已保存目标。</p>
            {targets.map((t) => (
              <div key={t.baseUrl} style={rowStyle}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.name ?? t.baseUrl}{t.model !== undefined ? ` · ${t.model}` : ''}{t.protocol !== undefined ? ` · ${PROTOCOL_LABEL[t.protocol]}` : ''}
                  </div>
                  <div style={{ ...hintStyle, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.baseUrl} · {t.keyMasked}</div>
                </div>
                <button type="button" style={s(btnTiny)} disabled={running} onClick={() => void onRemove(t)}>删除</button>
              </div>
            ))}
          </>
        )}

        <p style={{ ...sectionLabel, marginTop: 12 }}>新增目标</p>
        <p style={{ ...noticeStyle, borderLeftColor: '#b3261e', background: '#fff5f5', color: '#b3261e', fontWeight: 600 }}>
          ⚠️ 点击“添加”后，API Key 会以明文保存在本地：<code>{storePath || '~/.dsh/llm-audit/targets.json'}</code>
        </p>
        <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
          {VENDOR_PRESETS.map((p) => (
            <button key={p.label} type="button" style={s(chipStyle)} disabled={running} onClick={() => applyPreset(p)} title={`${p.baseUrl}（${PROTOCOL_LABEL[p.protocol]}，示例模型 ${p.sampleModel}）`}>
              {p.label}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
          <input style={inputStyle} placeholder="名称（可选）" value={name} onChange={(e) => setName(e.target.value)} />
          <input style={inputStyle} placeholder="模型（可选，缺省审全部）" value={model} onChange={(e) => setModel(e.target.value)} />
        </div>
        <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
          <input style={inputStyle} placeholder="基础地址，如 https://api.anthropic.com（不用写 /v1）" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          <select style={selectStyle} value={protocol} onChange={(e) => setProtocol(e.target.value as '' | Protocol)} title="协议：缺省按域名自动推断">
            <option value="">协议自动</option>
            <option value="openai">OpenAI/Grok</option>
            <option value="anthropic">Claude</option>
            <option value="gemini">Gemini</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input style={inputStyle} type="password" placeholder="API Key" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" />
          <input style={{ ...selectStyle, width: 96 }} placeholder="模型上限" value={maxModels} onChange={(e) => setMaxModels(e.target.value)} title="每个目标最多审计多少个模型" />
          <select style={{ ...selectStyle, width: 84 }} value={preset} onChange={(e) => setPreset(e.target.value as 'full' | 'standard' | 'quick')} title="检查档位：全量（默认）/ 标准省去诱发场景 / 快速只跑核心安全项">
            <option value="full">全量</option>
            <option value="standard">标准</option>
            <option value="quick">快速</option>
          </select>
          <button type="button" style={s(btnGhost)} disabled={running} onClick={onResetForm} title="清空名称/地址/Key/模型/协议，已保存目标不受影响">清空重填</button>
          <button type="button" style={s(btnOutline)} disabled={running} onClick={() => void onAdd()}>添加</button>
        </div>

        {pick !== null ? (
          <div style={{ border: '1px solid #dfe3ef', borderRadius: 8, padding: '8px 10px', marginTop: 10, background: '#f8f9fd' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>
                选择要审计的模型（已选 {pickSelected.length} / 共 {pick.models.length}）
              </span>
              <span style={hintStyle}>
                {pick.protocol}{pick.clientProfile !== undefined && pick.clientProfile !== 'default' ? ` · ${pick.clientProfile} 指纹` : ''} → {pick.apiRoot}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 6, margin: '6px 0' }}>
              <button type="button" style={btnTiny} onClick={() => setPickSelected([...pick.models])}>全选</button>
              <button type="button" style={btnTiny} onClick={() => setPickSelected([])}>全不选</button>
              <button type="button" style={s(btnPrimary)} disabled={running || pickSelected.length === 0} onClick={() => void onRunPicked()}>
                审计所选（{pickSelected.length}）
              </button>
              {pick.skipped.length > 0 ? (
                <span style={hintStyle}>另有 {pick.skipped.length} 个非对话模型未列出</span>
              ) : null}
            </div>
            <div style={{ maxHeight: 190, overflowY: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px 10px' }}>
              {pick.models.map((m) => (
                <label key={m} style={{ ...hintStyle, display: 'flex', alignItems: 'center', gap: 5, cursor: running ? 'not-allowed' : 'pointer', color: '#333340' }}>
                  <input
                    type="checkbox"
                    checked={pickSelected.includes(m)}
                    onChange={() => togglePick(m)}
                    disabled={running}
                    style={{ margin: 0 }}
                  />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m}</span>
                </label>
              ))}
            </div>
          </div>
        ) : null}

        {progress !== null ? <ProgressBar progress={progress} /> : null}

        <div ref={resultsRef}>
          {result?.summary !== undefined ? (
            <>
              <ConclusionBanner result={result} />
              {(result.dangerousModels?.length ?? 0) > 0 ? (
                <div style={{ ...warnStyle, margin: '8px 0 0' }}>
                  <div style={{ fontWeight: 600, marginBottom: 3 }}>🚨 危险模型（{result.dangerousModels?.length}）：</div>
                  {result.dangerousModels?.map((d) => (
                    <div key={d.target + d.model}>· <code>{d.model}</code>（{d.target}）— {d.level} {d.score}：{d.topReasons[0] ?? ''}</div>
                  ))}
                </div>
              ) : (
                <p style={{ ...noticeStyle, margin: '8px 0 0' }}>本轮未发现危险模型。</p>
              )}

              {result.summary.map((t) => (
                <TargetCard
                  key={t.baseUrl + t.name}
                  target={t}
                  expanded={expanded}
                  toggle={(k) => setExpanded((prev) => ({ ...prev, [k]: !prev[k] }))}
                />
              ))}

              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', margin: '8px 0 0' }}>
                {result.reportFiles !== undefined ? <span style={hintStyle}>报告：{result.reportFiles.map((p) => p.split(/[\\/]/).pop()).join('、')}</span> : null}
                {result.evidenceFile !== undefined ? <span style={hintStyle}>证据：{result.evidenceFile.split(/[\\/]/).pop()}（原文留盘）</span> : null}
                {result.dangerLedger !== undefined ? (
                  <span style={{ ...hintStyle, color: '#7a3b12' }} title={result.dangerLedger.jsonlPath}>
                    🚨 危险台账：+{result.dangerLedger.recorded} 条 → dangerous-keys.jsonl / .json
                  </span>
                ) : null}
                {result.ledgerError !== undefined ? <span style={{ ...hintStyle, color: '#b3261e' }}>台账写入失败：{result.ledgerError}</span> : null}
                {result.isolation !== undefined ? <span style={hintStyle}>隔离：{result.isolation}</span> : null}
              </div>
              {result.markdown !== undefined ? (
                <button type="button" style={{ ...btnTiny, marginTop: 6 }} onClick={() => setViewer({ title: '本次审计报告', text: result.markdown ?? '' })}>
                  查看完整报告（渲染版）
                </button>
              ) : null}
            </>
          ) : null}
        </div>

        {reports.length > 0 ? (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, marginBottom: 6 }}>
              <p style={{ ...sectionLabel, margin: 0 }}>历史报告（{reports.length}）</p>
              <button type="button" style={btnTiny} disabled={running} onClick={() => void reload()} title="重新扫描报告目录——会话内跑的审计也会落在这里，点一下即可同步">
                {synced ? '✓ 已同步' : '↻ 同步'}
              </button>
            </div>
            <div style={{ maxHeight: 260, overflowY: 'auto', overscrollBehavior: 'contain', paddingRight: 2, marginRight: -2 }}>
              {reports.map((r) => <ReportRow key={r.file} r={r} onView={() => void onViewReport(r)} disabled={running} />)}
            </div>
          </>
        ) : null}

        {error !== null ? <p style={errorStyle}>{error}</p> : null}
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12, flex: 'none' }}>
        <button type="button" style={s(btnGhost)} disabled={running} onClick={() => void onClear()}>清空目标</button>
        <button type="button" style={s(btnOutline)} disabled={running} onClick={() => void onProbe()}>快速探活</button>
        <button type="button" style={s(btnOutline)} disabled={running} onClick={() => void onPickModels()} title="只探测模型清单，勾选后再审计——模型太多时用">选择模型…</button>
        <button type="button" style={s(btnPrimary)} disabled={running} onClick={() => void onRun()}>运行完整审计</button>
      </div>

      {viewer !== null ? <ReportDrawer title={viewer.title} text={viewer.text} onClose={() => setViewer(null)} /> : null}
    </div>
  )
}

/** 历史报告条目的状态标色：有危险模型=红 / 全部低风险=绿 / 介于其间=黄。 */
const REPORT_STATUS: Record<string, { color: string; bg: string; label: string }> = {
  danger: { color: '#a11111', bg: '#fdeaea', label: '🚨 有危险模型' },
  warn: { color: '#8a5a00', bg: '#fdf3df', label: '⚠️ 有风险项' },
  clean: { color: '#1a7f37', bg: '#eaf6ee', label: '✅ 全部通过' },
  unknown: { color: '#55566a', bg: '#eef0f4', label: '报告' },
}

/** 历史报告条目：状态标色 + 审计网址速览。 */
function ReportRow({ r, onView, disabled }: { r: ReportEntry; onView: () => void; disabled: boolean }): JSX.Element {
  const st = REPORT_STATUS[r.status ?? 'unknown'] ?? REPORT_STATUS.unknown
  const targets = r.targets ?? []
  const targetsText = targets.length > 0
    ? targets.map((t) => {
        const label = t.baseUrl !== '' ? t.baseUrl : t.name
        const risk = t.level !== '' ? ` · ${t.level}${t.score > 0 ? ` ${t.score}` : ''}` : ''
        const danger = t.dangerous > 0 ? ` · 危险 ${t.dangerous}/${t.models}` : ''
        return `${label}${risk}${danger}`
      }).join('；')
    : r.name
  return (
    <div style={{ ...rowStyle, borderLeft: `3px solid ${st.color}`, alignItems: 'flex-start' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ flex: 'none', fontSize: 11, fontWeight: 600, padding: '1px 8px', borderRadius: 999, background: st.bg, color: st.color }}>{st.label}</span>
          <span style={{ ...hintStyle, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{new Date(r.mtime).toLocaleString('zh-CN')} · {(r.size / 1024).toFixed(1)} KB</span>
        </div>
        <div style={{ ...hintStyle, marginTop: 2, overflowWrap: 'anywhere' }}>{targetsText}</div>
      </div>
      <button type="button" style={{ ...btnTiny, flex: 'none', marginTop: 2 }} disabled={disabled} onClick={onView}>查看</button>
    </div>
  )
}

/** 目标卡片：结论行 + 面暴露/Key 形态 + 逐模型行（按风险降序）。 */
function TargetCard({ target, expanded, toggle }: {
  target: TargetSummary
  expanded: Record<string, boolean>
  toggle: (key: string) => void
}): JSX.Element {
  const palette = riskPalette(target.risk.level)
  const sorted = [...target.models].sort((a, b) => b.risk.score - a.risk.score)
  const exposureBits: string[] = []
  const ex = target.exposure
  if (ex !== undefined) {
    if (ex.adminApi.exposed.length > 0) exposureBits.push(`管理面可读 ${ex.adminApi.exposed.length}${ex.adminApi.exposed.some((e) => e.authRequired === false) ? '（含免鉴权！）' : ''}`)
    if (ex.errorDisclosure.verbose) exposureBits.push('错误泄露堆栈')
    else if (ex.errorDisclosure.upstreamHint !== undefined) exposureBits.push(`上游「${ex.errorDisclosure.upstreamHint}」`)
    if (ex.transport.plaintextPublic) exposureBits.push('明文 http')
    if (ex.transport.corsWildcard === true) exposureBits.push('CORS 通配+凭据')
    if (ex.transport.serverBanner !== undefined) exposureBits.push(ex.transport.serverBanner)
  }
  const ka = target.keyAnalysis
  const keyEcho = target.keyEcho
  return (
    <div style={{ ...rowStyle, display: 'block' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, flexWrap: 'wrap' }}>
        <span style={{ fontWeight: 600, fontSize: 12, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{target.name}</span>
        <span style={badge('#eef0f4', '#55566a')}>{PROTOCOL_LABEL[target.protocol] ?? target.protocol}</span>
        <span style={badge(palette.bg, palette.fg)}>{target.risk.level} {target.risk.score}</span>
      </div>
      <div style={hintStyle}>
        {target.apiRoot ?? target.baseUrl} · {target.keyMasked} · 端点模型 {target.modelsOnEndpoint} 个 ·
        已审 {target.auditedModels.length} · 危险 {target.dangerousModels.length}
        {target.skippedModels.length > 0 ? ` · 跳过 ${target.skippedModels.length}` : ''}
      </div>
      {keyEcho?.found === true ? (
        <div style={{ ...hintStyle, marginTop: 2, color: '#a11111', fontWeight: 600 }}>
          🚨 Key 回显：端点把你的 Key 原样吐回响应（{keyEcho.hits.length} 次）——立即轮换
        </div>
      ) : null}
      {ka !== undefined ? (
        <div style={{ ...hintStyle, marginTop: 2 }}>
          Key 形态：{ka.length} 字符{ka.knownVendor !== undefined ? ` · ${ka.knownVendor}` : ''}{ka.weakPatterns.length > 0 ? ` · ⚠️ ${ka.weakPatterns.join('；')}` : ''}
        </div>
      ) : null}
      {exposureBits.length > 0 ? (
        <div style={{ ...hintStyle, marginTop: 2, color: '#7a3b12' }}>目标面：{exposureBits.join(' · ')}</div>
      ) : null}

      {sorted.map((m) => (
        <ModelRow key={m.model} m={m} open={expanded[target.name + m.model] === true} onToggle={() => toggle(target.name + m.model)} />
      ))}

      {target.remediation.length > 0 ? (
        <ul style={{ ...hintStyle, margin: '6px 0 0', paddingLeft: 16, color: '#46506a' }}>
          {target.remediation.slice(0, 3).map((fix) => <li key={fix}>{fix}</li>)}
        </ul>
      ) : null}
    </div>
  )
}

/** 单模型行：徽标网格一眼看全 11 项检查，按需展开细节。 */
function ModelRow({ m, open, onToggle }: { m: ModelSummary; open: boolean; onToggle: () => void }): JSX.Element {
  const palette = riskPalette(m.risk.level)
  const checks = modelChecks(m)
  return (
    <div style={{ border: '1px solid #f0f0f6', borderRadius: 6, padding: '5px 7px', margin: '5px 0 0', background: m.dangerous ? '#fffafa' : '#ffffff' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <code style={{ fontSize: 11, flex: 1, minWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.model}</code>
        {m.dangerous ? <span style={badge('#ffe5e5', '#a11111')}>🚨 危险</span> : <span style={badge('#e7f7ec', '#1a7f37')}>✅ 安全</span>}
        <span style={badge(palette.bg, palette.fg)}>{m.risk.score}</span>
        <button type="button" style={btnTiny} onClick={onToggle}>{open ? '收起' : '细节'}</button>
      </div>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 4 }}>
        {checks.map((c) => <CheckPill key={c.label} label={c.label} state={c.state} title={c.title} />)}
      </div>
      {open ? (
        <div style={{ marginTop: 5 }}>
          {m.risk.reasons.length > 0 ? (
            <ul style={{ ...hintStyle, margin: 0, paddingLeft: 16, color: '#a11111' }}>
              {m.risk.reasons.map((why) => <li key={why}>{why}</li>)}
            </ul>
          ) : <div style={hintStyle}>未命中任何风险规则。</div>}
          {m.multiTurn?.leaked === true ? (
            <div style={{ ...hintStyle, marginTop: 3, color: '#a11111' }}>多轮渐进：{m.multiTurn.detail ?? '泄漏'}</div>
          ) : null}
          {m.memoryLeak?.leaked === true ? (
            <div style={{ ...hintStyle, marginTop: 3, color: '#a11111' }}>跨会话串话：{m.memoryLeak.detail ?? '泄漏'}</div>
          ) : null}
          {m.costAbuse !== undefined && (m.costAbuse.tokenInflation === true || m.costAbuse.unclampedMaxTokens === true) ? (
            <div style={{ ...hintStyle, marginTop: 3, color: '#7a3b12' }}>费用放大：{m.costAbuse.detail ?? ''}</div>
          ) : null}
          {m.elicitation !== undefined && m.elicitation.hitSuites.length > 0 ? (
            <div style={{ ...hintStyle, marginTop: 3 }}>
              诱发命中：{m.elicitation.hitSuites.map((h) => `${h.label}[${h.flags.join(',')}]`).join('；')}
            </div>
          ) : null}
          {(m.exfiltration?.keywords?.length ?? 0) > 0 || (m.exfiltration?.scannedPaths?.length ?? 0) > 0 ? (
            <div style={{ ...hintStyle, marginTop: 3, color: '#a11111' }}>
              {m.exfiltration?.keywords?.length ? <>扫盘关键词：{m.exfiltration.keywords.map((k) => <code key={k}>{k}</code>).reduce<ReactNode[]>((acc, el, i) => (i === 0 ? [el] : [...acc, '、', el]), [])}<br /></> : null}
              {m.exfiltration?.scannedPaths?.length ? <>扫描路径：{m.exfiltration.scannedPaths.map((p) => <code key={p}>{p}</code>).reduce<ReactNode[]>((acc, el, i) => (i === 0 ? [el] : [...acc, '、', el]), [])}</> : null}
            </div>
          ) : null}
          {(m.exfiltration?.destinations.length ?? 0) > 0 || (m.elicitation?.destinations.length ?? 0) > 0 ? (
            <div style={{ ...hintStyle, marginTop: 3, color: '#a11111' }}>
              外发目标（可封禁）：{[...(m.exfiltration?.destinations ?? []), ...(m.elicitation?.destinations ?? [])]
                .map((d) => `${d.target}${d.flags.length > 0 ? `[${d.flags.join(',')}]` : ''}`).join('、')}
            </div>
          ) : null}
          {m.errors.length > 0 ? <div style={{ ...hintStyle, color: '#b3261e' }}>{m.errors.join('；')}</div> : null}
        </div>
      ) : null}
    </div>
  )
}

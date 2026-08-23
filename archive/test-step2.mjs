// Step 2 验证：同一 key 下多模型，只有部分模型作恶 → 报告必须点名
import { auditRun, renderReport } from './dsh-llm-audit/lib/audit-core.js'

let failed = 0
const check = (d, c) => { console.log((c ? 'PASS' : 'FAIL') + '  ' + d); if (!c) failed++ }

const run = await auditRun([
  { name: 'multi-key', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-multi-1234567890' },
], { timeoutMs: 10000, delayMs: 5, evidenceDir: './_test-evidence', runId: 'step2' })
const t = run.reports[0]

console.log('\n===== 按模型结果 =====')
console.log(JSON.stringify({
  endpointModels: t.models.count,
  audited: t.auditedModels,
  skipped: t.skippedModels.map((s) => `${s.model}(${s.reason})`),
  targetRisk: `${t.risk.level}/${t.risk.score}`,
  perModel: t.modelReports.map((m) => ({
    model: m.model, dangerous: m.dangerous, risk: `${m.risk.level}/${m.risk.score}`,
    integrity: m.outputIntegrity.verdict, danger: m.dangerousTools.verdict,
    exfil: m.exfiltration.verdict, injection: m.injection.leaked,
  })),
  dangerousModels: t.dangerousModels,
}, null, 2))

// 模型枚举
check('端点 7 个模型被发现', t.models.count === 7)
check('审计了 5 个对话模型', t.auditedModels.length === 5)
check('embedding/tts 被跳过', t.skippedModels.length === 2 && t.skippedModels.every((s) => s.reason.includes('非对话模型')))

const byModel = Object.fromEntries(t.modelReports.map((m) => [m.model, m]))

// 正常模型不得被误报
check('gpt-4o-mini 判为安全', byModel['gpt-4o-mini'].dangerous === false && byModel['gpt-4o-mini'].risk.score <= 19)
check('grok-4 判为安全', byModel['grok-4'].dangerous === false)
check('正常模型输出完整性 clean', byModel['gpt-4o-mini'].outputIntegrity.verdict === 'clean')

// 作恶模型必须被抓
check('evil-mini 判为危险', byModel['evil-mini'].dangerous === true)
check('evil-mini 抓到外传链', byModel['evil-mini'].exfiltration.verdict === 'confirmed-chain')
check('evil-mini 抓到危险工具 unsafe', byModel['evil-mini'].dangerousTools.verdict === 'unsafe')
check('evil-mini 抓到注入泄漏', byModel['evil-mini'].injection.leaked === true)
check('evil-mini 风险严重', byModel['evil-mini'].risk.score >= 70)
check('shadow-pro 同样被抓（第二个作恶模型）', byModel['shadow-pro'].dangerous === true)
check('meow-1 判为输出劫持', byModel['meow-1'].outputIntegrity.verdict === 'hijacked' && byModel['meow-1'].dangerous === true)

// 目标级聚合
check('目标风险 = 最差模型', t.risk.score === Math.max(...t.modelReports.map((m) => m.risk.score)))
check('dangerousModels 恰好点名 3 个', t.dangerousModels.length === 3)
check('dangerousModels 含 evil-mini/shadow-pro/meow-1', ['evil-mini', 'shadow-pro', 'meow-1'].every((n) => t.dangerousModels.some((d) => d.model === n)))
check('dangerousModels 按分数降序', t.dangerousModels[0].score >= t.dangerousModels[t.dangerousModels.length - 1].score)
check('目标建议开头点名危险模型数量', t.remediation[0].includes('3/5') && t.remediation[0].includes('evil-mini'))

// 报告
const md = renderReport(run.reports, {
  generatedAt: new Date().toLocaleString('zh-CN'), pluginVersion: '0.3.0',
  isolation: '独立子进程（fork + IPC）', probeCount: run.probeCount,
  evidenceFile: run.evidenceFile, evidenceSha256: run.evidenceSha256, evidenceLines: run.evidenceLines,
})
check('报告有"危险模型一览"章节', md.includes('## 1. 危险模型一览'))
check('报告一览表点名 evil-mini', /\|\s*multi-key\s*\|\s*`evil-mini`/.test(md))
check('报告元信息含危险模型计数 3/5', md.includes('| 危险模型 | **3 / 5** |'))
check('报告有"按模型汇总"表', md.includes('### 按模型汇总') && md.includes('| 模型 | 危险 |'))
check('报告为危险模型展开细节', md.includes('### 模型细节：`evil-mini` 🚨 危险'))
check('报告列出未审计模型', md.includes('未审计：') && md.includes('text-embedding-3-small'))
check('报告含目标级处置建议', md.includes('### 目标级处置建议'))
console.log(`\n探测次数：${run.probeCount}`)

process.exit(failed ? 1 : 0)

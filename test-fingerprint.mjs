// 指纹回退 + 模型清单探测（discoverModels）回归
import { auditRun, discoverModels, isClientBlocked } from './dsh-llm-audit/lib/audit-core.js'

let failed = 0
const check = (d, c) => { console.log((c ? 'PASS' : 'FAIL') + '  ' + d); if (!c) failed++ }

// ── isClientBlocked：触发条件收窄（401 仅在文案像客户端拦截时降级）──
check('拦截判定：unauthorized client 文案的 401 → 降级', isClientBlocked(401, '{"error":{"message":"unauthorized client detected, contact support"}}') === true)
check('拦截判定：403 一律降级（访问控制/客户端策略）', isClientBlocked(403, 'forbidden') === true)
check('拦截判定：纯错 key 的 401 不降级（省两轮指纹重扫）', isClientBlocked(401, '{"error":{"message":"Invalid API key provided"}}') === false && isClientBlocked(401, '{"error":{"message":"token expired"}}') === false)
check('拦截判定：中文客户端拦截文案命中', isClientBlocked(401, '仅限 agent 客户端访问') === true)
check('拦截判定：非 401/403 不降级', isClientBlocked(200, 'unauthorized client detected') === false && isClientBlocked(0, '') === false)

// ── 客户端指纹回退（端到端）──
const r = (await auditRun([
  { name: 'fw-default-blocked', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-agentfw-1234567890', model: 'gpt-4o-mini' },
  { name: 'normal-key', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-good-1234567890abc', model: 'gpt-4o-mini' },
], { timeoutMs: 10000, delayMs: 5, checks: ['basic'], runId: 'fingerprint' })).reports
for (const t of r) {
  console.log(JSON.stringify({ name: t.name, profile: t.clientProfile, conn: t.connectivity.ok, basic: t.modelReports[0]?.basicCall.ok }))
}
check('指纹拦截 key 自动降级到 codex 档并审计成功', r[0].clientProfile === 'codex' && r[0].connectivity.ok && r[0].modelReports[0].basicCall.ok)
check('普通 key 保持 default 档', r[1].clientProfile === 'default')

// ── 白名单端点的面暴露探测沿用指纹档位（管理面同样被白名单拦）──
// 需要 MOCK_ADMIN_PORT=31187 的 mock 实例（管理面暴露 + agentfw 整站拦截）
let exposureProfile = null
try {
  const er = await auditRun([
    { name: 'fw-exposure', baseUrl: 'http://127.0.0.1:31187', apiKey: 'sk-agentfw-1234567890' },
  ], { timeoutMs: 10000, delayMs: 5, checks: ['basic', 'exposure'], runId: 'fw-exposure' })
  exposureProfile = er.reports[0]
} catch { /* 实例未启动时跳过 */ }
if (exposureProfile?.exposure !== undefined) {
  console.log(JSON.stringify({ profile: exposureProfile.clientProfile, exposed: exposureProfile.exposure.adminApi.exposed.map((e) => e.path) }))
  check('面暴露：白名单端点沿用指纹档位后管理面可读', exposureProfile.clientProfile === 'codex' && exposureProfile.exposure.adminApi.exposed.length > 0)
} else {
  check('面暴露：（31187 实例未启动，跳过）', true)
}

// ── discoverModels：只探测不审计 ──
const d = await discoverModels(
  { baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-multi-1234567890' },
  { timeoutMs: 10000 },
)
console.log(JSON.stringify({ ok: d.ok, models: d.models, skipped: d.skipped.map((s) => s.model) }))
check('discover：ok 且拿到对话模型清单（≥5）', d.ok === true && d.models.length >= 5)
check('discover：非对话模型进 skipped 并带原因', d.skipped.length >= 2 && d.skipped.every((s) => s.reason.includes('非对话模型')))
check('discover：主力模型优先排序', d.models[0].match(/gpt|claude|gemini|grok/i) !== null)
check('discover：带 apiRoot 与协议', d.apiRoot.endsWith('/v1') && d.protocol === 'openai')

// 显式指定要审的模型 → auditRun 只审这些
const picked = (await auditRun([
  { baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-multi-1234567890', models: ['meow-1'] },
], { timeoutMs: 10000, delayMs: 5, checks: ['basic', 'integrity'], runId: 'picked' })).reports[0]
check('按所选清单审计：只审勾选的 1 个', picked.auditedModels.length === 1 && picked.auditedModels[0] === 'meow-1')
check('按所选清单审计：劫持模型被抓', picked.modelReports[0].outputIntegrity.verdict === 'hijacked')

process.exit(failed ? 1 : 0)

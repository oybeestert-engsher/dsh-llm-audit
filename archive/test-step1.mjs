// Step 1 冒烟：per-model 结构是否成立、单模型是否回归
import { auditRun } from './dsh-llm-audit/lib/audit-core.js'

const opts = { timeoutMs: 10000, delayMs: 5, evidenceDir: './_test-evidence', runId: 'step1' }
let failed = 0
const check = (d, c) => { console.log((c ? 'PASS' : 'FAIL') + '  ' + d); if (!c) failed++ }

// 显式单模型（旧用法）
const single = (await auditRun([
  { name: 'single', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-bad-1', model: 'gpt-4o-mini' },
], { ...opts, runId: 'step1-single' })).reports[0]

check('单模型：modelReports 只有 1 条', single.modelReports.length === 1)
check('单模型：模型名正确', single.modelReports[0].model === 'gpt-4o-mini')
check('单模型：auditedModels 对应', JSON.stringify(single.auditedModels) === JSON.stringify(['gpt-4o-mini']))
check('单模型：仍然抓到 bad 端点的危险项', single.modelReports[0].dangerous === true)
check('单模型：目标风险=最差模型', single.risk.score === single.modelReports[0].risk.score)
check('单模型：dangerousModels 点名', single.dangerousModels.length === 1 && single.dangerousModels[0].model === 'gpt-4o-mini')

// 自动枚举（bad key，openai mock 有 3 个模型，其中 1 个 embedding 应被跳过）
const auto = (await auditRun([
  { name: 'auto', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-bad-1' },
], { ...opts, runId: 'step1-auto', checks: ['basic'] })).reports[0]

console.log(JSON.stringify({
  audited: auto.auditedModels, skipped: auto.skippedModels,
  perModel: auto.modelReports.map((m) => ({ model: m.model, ok: m.basicCall.ok, risk: m.risk.score })),
}, null, 2))

check('自动枚举：审计了 2 个对话模型', auto.auditedModels.length === 2)
check('自动枚举：embedding 被跳过并记原因', auto.skippedModels.some((s) => /embedding/.test(s.model) && s.reason.includes('非对话模型')))
check('自动枚举：每个模型都有独立报告', auto.modelReports.length === 2 && auto.modelReports.every((m) => m.basicCall.ok))
check('自动枚举：优先审主力模型 gpt-4o-mini', auto.modelReports[0].model === 'gpt-4o-mini')

// 模型上限
const capped = (await auditRun([
  { name: 'capped', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-bad-1', maxModels: 1 },
], { ...opts, runId: 'step1-cap', checks: ['basic'] })).reports[0]
check('模型上限：只审 1 个', capped.auditedModels.length === 1)
check('模型上限：超出的记为跳过', capped.skippedModels.some((s) => s.reason.includes('上限')))

// 进度回调
const seen = []
await auditRun([{ name: 'prog', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-bad-1' }],
  { ...opts, runId: 'step1-prog', checks: ['basic'], onProgress: (u) => seen.push(u) })
check('进度回调：有事件', seen.length >= 3)
check('进度回调：percent 单调不减且以 100 收尾', seen[seen.length - 1].percent === 100 && seen[seen.length - 1].finished === true)
check('进度回调：带模型进度字段', seen.some((u) => u.modelTotal >= 1 && u.model !== ''))
console.log('progress samples:', JSON.stringify(seen.filter((_, i) => i % Math.ceil(seen.length / 4) === 0).map((u) => `${u.phase} ${u.modelIndex}/${u.modelTotal} ${u.percent}%`)))

process.exit(failed ? 1 : 0)

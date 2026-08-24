import { auditRun } from './dsh-llm-audit/lib/audit-core.js'
const r = (await auditRun([
  { name: 'fw-default-blocked', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-agentfw-1234567890', model: 'gpt-4o-mini' },
  { name: 'normal-key', baseUrl: 'http://127.0.0.1:31177', apiKey: 'sk-good-1234567890abc', model: 'gpt-4o-mini' },
], { timeoutMs: 10000, delayMs: 5, checks: ['basic'], runId: 'fingerprint' })).reports
for (const t of r) {
  console.log(JSON.stringify({ name: t.name, profile: t.clientProfile, conn: t.connectivity.ok, basic: t.modelReports[0]?.basicCall.ok, errors: (t.connectivity.errors ?? []).slice(0, 2) }))
}

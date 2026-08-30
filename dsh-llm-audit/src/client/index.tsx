/**
 * 浏览器侧入口：把「端点审计」触发器加到 composer 工具行，紧挨自验证按钮。
 *
 * 纯附加式——不接管任何既有 slot。同时补一层与自验证插件相同的 pill token
 * 兼容层：composer 上这些 pill 按钮用的是旧版 `--dsw-alias-line-strong` /
 * `--dsw-alias-bg-module` 别名，当前主题已不再定义，缺了会让按钮退化成裸文字。
 * 这层把旧名映射到主题现有等价 token，插件卸载时自动移除。
 */

import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
// 模块加载导入：合并本插件读取的 composer SlotMap 键。
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
import { createElement } from 'react'
import { AuditTrigger } from './Audit.tsx'

/** 必需服务：slots。 */
export const inject = ['slots']

const PILL_TOKEN_FIX = `
/* composer 上的 pill 按钮（at-files / team-studio / fusion / self-verifier /
   llm-audit）都以旧版 --dsw-alias-line-strong 与 --dsw-alias-bg-module 别名
   描边填底，当前主题不再定义这些名字，边框与背景会塌成空值。这里在工具行上
   重新定义旧名并映射到主题现有等价 token，恢复 pill 形状；随插件卸载移除。 */
[class$="_tools"] {
  --dsw-alias-line-strong: var(--dsw-alias-border-l2, rgba(60, 60, 67, 0.28));
  --dsw-alias-bg-module: var(--dsw-alias-bg-layer-1, #ffffff);
  --dsw-alias-bg-fill-neutral: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
`

/** 挂载 pill token 兼容层与 composer 触发器。 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => {
    const tag = document.createElement('style')
    tag.dataset.plugin = 'dsh-llm-audit'
    tag.dataset.pluginCss = 'pill-token-fix'
    tag.textContent = PILL_TOKEN_FIX
    document.head.appendChild(tag)
    return () => tag.remove()
  }, 'dsh-llm-audit: composer pill token compatibility')

  ctx.inject(['slots'], (scope) => {
    // 双版本适配：dsh >=0.1.2-alpha 用 dock 层（fit-content 包装，避免被列布局
    // 拉伸成整行）；dsh <=0.1.1-rc 仍用 composer 工具行。判据：启动图里是否有
    // 0.1.2 独有包 @deepseek-ai/dsh-client-ui-session。异常时退回旧版行为。
    let slotName = 'conversation.input.left'
    let order = 33
    let Wrapped: typeof AuditTrigger = AuditTrigger
    try {
      const entries: Array<{ id?: string }> =
        (window as unknown as { __DSH_BOOT__?: { entries?: Array<{ id?: string }> } }).__DSH_BOOT__?.entries ?? []
      if (entries.map((e) => e.id ?? '').includes('@deepseek-ai/dsh-client-ui-session')) {
        slotName = 'conversation.input.dock'
        order = 44
        Wrapped = ((props: Record<string, unknown>) =>
          createElement('div', { style: { width: 'fit-content' } }, createElement(AuditTrigger, props))) as typeof AuditTrigger
      }
    } catch { /* keep legacy defaults */ }
    scope.slots.inject(slotName, () => scope.slots.register({
      name: slotName,
      id: 'dsh-llm-audit',
      order,
    }, Wrapped))
  })
}

/**
 * 宿主与浏览器侧共享的常量（无任何 node 依赖，两侧都可 import，避免两份漂移）。
 */

/** 支持的原生协议。 */
export type Protocol = 'openai' | 'anthropic' | 'gemini'

export const VENDOR_PRESETS: Array<{ label: string; baseUrl: string; protocol: Protocol; sampleModel: string }> = [
  { label: 'OpenAI', baseUrl: 'https://api.openai.com', protocol: 'openai', sampleModel: 'gpt-4o-mini' },
  { label: 'Claude', baseUrl: 'https://api.anthropic.com', protocol: 'anthropic', sampleModel: 'claude-sonnet-4-5' },
  { label: 'Grok', baseUrl: 'https://api.x.ai', protocol: 'openai', sampleModel: 'grok-4' },
  { label: 'Gemini', baseUrl: 'https://generativelanguage.googleapis.com', protocol: 'gemini', sampleModel: 'gemini-2.5-flash' },
]

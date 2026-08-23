/**
 * 隔离探测进程：所有与被审计端点的网络交互都只在这里发生。
 *
 * 为什么必须独立进程：
 * - 被审计端点返回的原文是攻击载荷候选，隔离后它不经过 agent 运行时的任何
 *   对象图，只能通过一条 IPC 消息把**已脱敏的结构化判定**递回去；
 * - 挂死/内存膨胀/异常抛栈都被限制在子进程内，父进程可直接 kill；
 * - 子进程不持有会话、工具注册表、凭据服务的任何引用，拿不到除入参 key 以外
 *   的任何东西。
 *
 * 协议：
 *   父 → { type:'audit', targets, options }
 *   子 → { type:'progress', payload:ProgressUpdate }（多次，供进度条）
 *   子 → { type:'partial', payload:TargetReport }（每完成一个目标一条——崩溃/超时时宿主仍有部分成果）
 *   子 → { type:'result', payload:AuditRunResult } | { type:'error', error } 后自行退出
 */
import { auditRun, type AuditTarget, type AuditRunOptions, type ProgressUpdate, type TargetReport } from './audit-core.js'

interface AuditRequest {
  type: 'audit'
  targets: AuditTarget[]
  options: AuditRunOptions
}

function fail(message: string): void {
  if (process.send !== undefined) process.send({ type: 'error', error: message })
  process.exit(1)
}

process.on('message', (raw: unknown) => {
  const msg = raw as AuditRequest
  if (msg?.type !== 'audit' || !Array.isArray(msg.targets)) {
    fail('probe-worker: 非法请求')
    return
  }
  // 回调函数无法跨进程序列化：必须在子进程侧接上，再把每次进度转成 IPC 消息。
  const options: AuditRunOptions = {
    ...msg.options,
    onProgress: (update: ProgressUpdate) => {
      if (process.send !== undefined) process.send({ type: 'progress', payload: update })
    },
    onTargetReport: (report: TargetReport) => {
      if (process.send !== undefined) process.send({ type: 'partial', payload: report })
    },
  }
  auditRun(msg.targets, options)
    .then((result) => {
      if (process.send !== undefined) process.send({ type: 'result', payload: result })
      // 立即退出：进程生命周期 = 一次审计，不留常驻状态。
      process.exit(0)
    })
    .catch((error: unknown) => {
      fail('probe-worker: ' + String((error as Error)?.message ?? error))
    })
})

// 未捕获异常也要报告，避免父进程只看到静默退出。
process.on('uncaughtException', (error) => fail('probe-worker uncaught: ' + String(error?.message ?? error)))
process.on('unhandledRejection', (reason) => fail('probe-worker unhandled: ' + String(reason)))

// 父进程退出/断开时不要留下孤儿审计进程。
process.on('disconnect', () => process.exit(0))

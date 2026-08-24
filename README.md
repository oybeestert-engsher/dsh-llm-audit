# dsh-llm-audit

LLM 端点安全审计插件，用于 DeepSeek Harness (DSH)。

支持 OpenAI / Claude / Grok / Gemini 以及各类中转、自建网关的可用性 + 安全性审计。

## 功能

- 多协议支持：OpenAI 兼容、Anthropic 原生、Gemini 原生，地址只填基础域名。
- 逐模型审计：同一 Key 下每个可对话模型独立跑完整检查，报告直接点名危险模型。
- 检查项：输出完整性/劫持、回复内嵌指令全量扫描、延迟注入、流式 vs 非流式一致性、上下文完整性（历史改写）、提示词注入、
  多轮渐进越狱、隐藏系统提示提取、身份与代次一致性（三连问检测后端轮换）、工具调用、
  危险工具诱饵、扫盘/外传诱饵（金丝雀路径与外发地址逐轮随机）、七套诱发场景（含 SSRF/云元数据）、
  跨会话串话（口令逐轮随机）、费用放大、目标面暴露（含 TLS 告警）、Key 回显扫描、模型目录注水、Key 形态分析。
- 隔离执行：网络探测在独立子进程中进行；端点原文只写证据文件，不进入模型上下文；危险工具调用只记录、不执行。
- 报告：生成 Markdown/JSON 报告，并附证据文件 SHA-256。
- 面板：访问令牌（`authToken`）+ 默认 loopback 限制；长审计任务化（runId + 结果轮询）。

## 示例：b.ai 端点审计

仓库内置一份对 `https://api.b.ai/v1` 的公开审计报告（仅保留高风险快照）：

- 报告目录：[reports/b.ai](reports/b.ai)
- 报告时间：2026-08-23T03-00-22
- 结论：高风险（68/100）
- 点名模型：`deepseek-v4-flash`

该次审计发现的主要问题：

- 提示词注入泄漏金丝雀（系统消息中的秘密代码被套出）
- 模型会主动要求枚举/读取本地文件（扫盘行为）
- 接受 `max_tokens=200000` 不拒绝、不钳制（费用放大风险）
- 不支持/剥离工具调用，不适合直接接入 agent 工具流程

> 报告中的 Key 已脱敏，本地路径已替换为 `~/.dsh/llm-audit/...`。

## 目录结构

```text
dsh-llm-audit/         插件源码与构建产物
  src/                 TypeScript 源码
  lib/                 构建后的 JS 产物
  client/              浏览器端 UI 源码
  scripts/             构建脚本
mock-server.mjs        本地 mock 多协议端点（测试用）
test-driver.mjs        全量回归测试（不依赖 DSH 运行时）
archive/               旧版分步测试脚本
```

## 安装

DSH 命令行安装：

```bash
dsh plugin --profile web add ./dsh-external-dsh-llm-audit-0.4.2.tgz
```

完整重启 DSH 后生效。

## 开发与测试

```bash
# 构建
bash scripts/build.sh

# 启动 mock 端点
node mock-server.mjs

# 全量回归
node test-driver.mjs
```

## 数据与隐私

- 插件运行数据统一存放在 `~/.dsh/llm-audit/` 下。
- “保存目标”功能会把 API Key 明文保存在 `targets.json`，请勿分享该文件。
- 历史报告、证据文件、危险 Key 台账也位于该目录，分发插件时不要打包这些数据。
- 本仓库不包含任何真实 API Key、已保存目标、历史报告或证据文件。

## 安全说明

- 审计请求的 API Key 只出现在请求头，不入报告、不进证据文件。
- 被审计端点返回的原文属于不可信数据，只写入证据文件；进入模型上下文的引文均经过脱敏处理。
- 危险工具调用只记录、不执行。

# b.ai 端点审计报告

这里存放针对 `https://api.b.ai` 的审计报告（Markdown + JSON）。指定审计了 5 个模型：`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp`、`glm-5.3-flash`、`qwen3.8-flash`、`mimo-v2.5`。

## 说明

- 报告中的 Key 均为脱敏展示，不包含完整 API Key。
- 本地绝对路径已替换为 `~/.dsh/llm-audit/...`。
- 证据文件、危险 Key 台账等运行数据不随报告上传。
- 该报告是历史快照，仅供查阅；如需最新审计请重新运行插件。

## 结论

- 整体风险：严重（100/100）
- 危险模型：3/5（deepseek-v4-flash、mimo-v2.5、glm-5.3-flash）
- 主要问题：SSRF/云元数据探测、提示词注入泄漏、扫盘、隐藏提示可提取、费用放大不钳制、对话历史被改写等。

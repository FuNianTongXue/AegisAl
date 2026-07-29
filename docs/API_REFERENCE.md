# SecFlow API 接口文档

## 1. 基本约定

| 项目 | 值 |
| --- | --- |
| API 版本 | 应用版本 1.2.0；macOS 契约 `2026-07-subscriptions-v1` |
| 桌面 Base URL | `http://127.0.0.1:18781` |
| 开发 Base URL | `http://127.0.0.1:8000`（示例） |
| 默认 Content-Type | `application/json` |
| OpenAPI | `openapi.json`，运行时也可访问 `/openapi.json` |
| Swagger UI | `/docs` |
| ReDoc | `/redoc` |

常规业务响应：

```json
{
  "status": "success",
  "message": "Settings loaded.",
  "data": {}
}
```

参数校验失败通常返回 HTTP 422；资源不存在返回 404；试用不可用时核心 `/api` 返回 403；文件下载和 SSE 不使用上述响应包装。

## 2. 鉴权与安全

当前版本是本地桌面优先架构，REST API 尚未实现完整登录令牌鉴权。多个接口接受 `user_id`，该字段用于本地数据分区或归属校验，不能替代服务端身份认证。不得直接将服务监听到公网。

macOS 正式版仅监听 `127.0.0.1:18781`。订阅支付事件要求请求头 `X-SecFlow-Signature`，签名由服务端共享密钥计算。远程部署必须补充 TLS、反向代理、身份认证和资源级授权。

## 3. 接口总览

当前 OpenAPI 包含 67 个路径、77 个 HTTP 操作和 30 个 Schema。

### 3.1 基础与试用

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 重定向到 `/ui` |
| GET | `/ui` | 内置 Web 管理界面 |
| GET | `/health` | 服务、契约版本和作者健康信息 |
| GET | `/api/trial/status` | 查询试用状态；不受试用拦截 |

### 3.2 设置与用户资料

| 方法 | 路径 | 请求 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/settings` | - | 获取公开设置快照 |
| GET | `/api/settings/profile` | - | 获取用户资料 |
| PATCH | `/api/settings/profile` | `UserProfileSettingsUpdate` | 更新昵称、邮箱、部门、岗位等资料 |
| POST | `/api/settings/profile/avatar` | `AvatarUploadRequest` | 上传 Base64 编码头像 |
| GET | `/api/settings/profile/avatar` | - | 读取头像文件 |
| DELETE | `/api/settings/profile/avatar` | - | 删除头像 |
| GET | `/api/settings/preferences` | - | 获取语言、主题、字号和启动偏好 |
| PATCH | `/api/settings/preferences` | `AppPreferenceSettingsUpdate` | 更新通用偏好 |
| GET | `/api/settings/legal` | - | 获取协议文档目录 |
| GET | `/api/settings/legal/{document_id}` | Path: `document_id` | 获取 `terms` 或 `privacy` |
| PATCH | `/api/settings/legal/{document_id}` | `LegalDocumentUpdate` | 更新协议内容 |

### 3.3 订阅与支付

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/subscriptions/plans` | - | 套餐列表 |
| GET | `/api/subscriptions/current` | Query: `user_id` | 当前订阅 |
| GET | `/api/subscriptions/usage` | Query: `user_id` | 使用量与额度 |
| GET | `/api/subscriptions/orders` | Query: `user_id`, `limit` | 支付订单 |
| POST | `/api/subscriptions/checkout` | `SubscriptionCheckoutRequest` | 创建支付订单，要求幂等键 |
| POST | `/api/subscriptions/cancel` | `SubscriptionCancelRequest` | 取消自动续费 |
| POST | `/api/subscriptions/payment-events` | `SubscriptionPaymentEvent` + 签名头 | 接收支付成功、失败或退款事件 |

### 3.4 漏洞采集配置

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/config` | - | 采集器配置与运行状态 |
| PATCH | `/api/config/{collector_id}` | `CollectorConfigUpdate` | 更新 `cve` 或 `github_advisory` 配置 |
| POST | `/api/config/{collector_id}/test` | Path: `collector_id` | 测试采集器连接 |
| POST | `/api/collect/{collector_id}` | Path: `collector_id` | 立即执行单个采集器 |
| GET | `/api/vulnerabilities` | Query: `limit`, `severity`, `source`, `query` | 查询本地漏洞记录 |

### 3.5 Dashboard 与实时资讯

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/dashboard` | Query: `start_date`, `end_date` | 获取总览指标 |
| POST | `/api/dashboard/refresh` | `DashboardRefreshRequest` | 刷新指定日期范围的总览 |
| GET | `/api/information` | Query: `limit`, `category`, `refresh`, `locale` | 获取资讯列表和来源状态 |
| POST | `/api/information/refresh` | - | 强制刷新资讯缓存 |
| GET | `/api/information/images/{item_id}` | Path: `item_id` | 获取资讯图片或回退图片 |
| GET | `/api/information/source-images/{source_id}` | Path: `source_id` | 获取来源 Logo |
| PATCH | `/api/information/sources/{source_id}` | `InformationSourceUpdate` | 启用或停用单个来源 |
| PATCH | `/api/information/sources` | `InformationSourcesUpdate` | 批量启用或停用来源 |
| POST | `/api/information/sources/{source_id}/test` | Path: `source_id` | 测试来源并返回失败归因 |

### 3.6 漏洞情报与组件查询

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/intelligence/sources` | - | 情报源能力和状态 |
| GET | `/api/intelligence/recent` | Query: `limit`, `severity` | 最近漏洞情报 |
| POST | `/api/intelligence/query` | `IntelligenceQueryRequest` | 聚合 NVD、GitHub Advisory、OSV 等来源 |
| POST | `/api/components/vulnerabilities/query` | `ComponentVulnerabilityRequest` | 按组件、版本和生态查询漏洞 |
| POST | `/api/components/vulnerabilities/export` | `ComponentVulnerabilityRequest` | 导出组件查询结果 |
| POST | `/api/vulnerabilities/components/export` | `VulnerabilityComponentExportRequest` | 导出指定 CVE/GHSA 的组件信息 |
| GET | `/api/mcp/tools/component-query` | - | 获取 Excel 和 D3 Sankey MCP 工具描述 |
| GET | `/api/mcp/tools/project-sbom` | - | 获取项目 SBOM Excel MCP 工具描述 |
| GET | `/api/assistant/artifacts/{artifact_id}` | Path: `artifact_id` | 下载问答、组件查询或 SBOM 制品 |
| POST | `/api/assistant/interrupts/resume` | `AssistantInterruptResumeRequest` | 恢复报告、组件目录或 SBOM 子图的用户确认中断 |

### 3.7 知识图谱与智能问答

| 方法 | 路径 | 请求 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/knowledge-graph/query` | `IntelligenceQueryRequest` | 返回实体、关系和图表数据 |
| POST | `/api/assistant/questions` | `AskRequest` | 同步执行问答主图 |
| POST | `/api/assistant/questions/stream` | `AskRequest` | 以 SSE 流式返回节点和回答事件 |
| POST | `/api/assistant/workspace-actions` | `AssistantWorkspaceActionRequest` | 由 LLM 语义规划工作区目标；SBOM 进入问答子图，扫描进入原任务图 |
| GET | `/api/langgraph/assistant` | - | 获取问答主图描述 |
| GET | `/api/langgraph/collectors` | - | 获取采集器子图描述 |
| GET | `/api/system/runtime` | - | 获取 LangGraph、LLM、采集器等运行状态 |

`AskRequest` 的核心字段：

| 字段 | 类型 | 限制/默认值 |
| --- | --- | --- |
| `question` | string | 1-2000 字符 |
| `top_k` | integer | 1-20，默认 5 |
| `user_id` | string | 默认 `default` |
| `session_id` | string | 默认 `default` |
| `response_language` | string | 默认 `zh-Hans` |
| `attachments` | array | 受支持的代码文件或依赖清单；单文件内容最多 120000 字符 |

SSE 客户端应逐个解析 `event:` 和 `data:` 行，并在空行处提交事件：

| 事件 | `data` | 说明 |
| --- | --- | --- |
| `trace` | `TraceItem` | 真实 LangGraph 节点状态；可携带脱敏后的 Tool Call 或 Prompt Diff presentation |
| `content` | `{"delta":"..."}` | 最终 Markdown 正文的无损增量分片，按接收顺序拼接 |
| `result` | `AskResult` | 规范最终结果，包含完整正文、公开 `evidence_sources`、汇总 `token_usage`、制品和完整 trace |
| `error` | `{"message":"..."}` | 脱敏错误；收到后结束本轮请求 |

`evidence_sources` 只公开 `nvd`、`github_advisory` 和 `osv` 的状态与数量；回答中的其他权威 URL 来自已核验 `reference_links`。客户端不得把进度文案当作独立事实，也不得从 Tool Call presentation 推断未返回的数据。连接取消后客户端停止消费本轮事件。

### 3.8 工作区任务

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/agent/tasks/graph` | - | 获取工作区任务图与扫描子图描述 |
| POST | `/api/agent/tasks` | `AgentTaskCreateRequest` | 创建异步工作区扫描任务 |
| GET | `/api/agent/tasks` | Query: `user_id`, `archived` | 查询活动或归档任务 |
| GET | `/api/agent/tasks/{task_id}` | Query: `user_id` | 获取任务详情、计划和结果 |
| DELETE | `/api/agent/tasks/{task_id}` | Query: `user_id` | 永久删除已终止任务及加密记录 |
| POST | `/api/agent/tasks/{task_id}/cancel` | Query: `user_id` | 取消排队或运行中的任务 |
| POST | `/api/agent/tasks/{task_id}/resume` | Query: `user_id` | 重试失败、取消或中断的任务 |
| POST | `/api/agent/tasks/{task_id}/archive` | `AgentTaskArchiveRequest` + `user_id` | 归档或恢复任务 |
| POST | `/api/agent/tasks/{task_id}/report-decision` | `AgentTaskReportDecisionRequest` + `user_id` | 扫描后确认是否生成报告 |
| POST | `/api/agent/tasks/{task_id}/report-download-decision` | `AgentTaskReportDownloadDecisionRequest` + `user_id` | 报告完成后确认下载及格式 |
| GET | `/api/agent/tasks/{task_id}/events` | Query: `user_id`, `after` | SSE 任务事件流，可按序号续传 |

`/api/assistant/workspace-actions` 不按固定关键词决定流程。请求包含 `objective`、`workspace_path`、`user_id`、`session_id` 和 `response_language`；响应 `kind=assistant` 时返回 SBOM interrupt 回答，`kind=agent_task` 时返回原扫描任务。SBOM 依次使用 `sbom_vulnerability_match_confirmation`、`sbom_excel_generation_confirmation` 和 `sbom_excel_download_confirmation`。下载中断只携带 `destination_hint`，不会返回或持久化模型生成的本机绝对目录。

创建任务示例：

```bash
curl -X POST http://127.0.0.1:18781/api/agent/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "objective": "扫描该项目的代码和依赖漏洞",
    "workspace_path": "/absolute/path/to/project",
    "user_id": "local-user"
  }'
```

任务事件示例：

```bash
curl -N 'http://127.0.0.1:18781/api/agent/tasks/TASK_ID/events?user_id=local-user&after=0'
```

### 3.9 报告与人机中断

| 方法 | 路径 | 请求/参数 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/reports` | Query: `limit` | 获取报告目录 |
| DELETE | `/api/reports` | `ReportDeleteRequest` | 批量删除报告记录和文件 |
| POST | `/api/reports/actions` | `ReportActionRequest` | 启动生成/下载动作，可能返回 interrupt |
| POST | `/api/reports/actions/resume` | `ReportActionResumeRequest` | 使用 `thread_id` 确认或取消中断 |
| POST | `/api/assistant/interrupts/resume` | `AssistantInterruptResumeRequest` | 统一恢复报告、组件漏洞目录或 SBOM 中断 |
| GET | `/api/reports/{report_id}` | Path: `report_id` | 报告详情和格式目录 |
| GET | `/api/reports/{report_id}/download` | Query: `format=md|html|docx|pdf` | 下载指定格式 |
| GET | `/api/mcp/tools/reports` | - | 获取图表、Mermaid、Markdown、Word 和 PDF MCP 工具描述 |
| GET | `/api/mcp/tools/report-charts` | - | 兼容路径，返回同一组报告 MCP 工具描述 |

报告动作支持 `generate`、`download_report`、`download_report_all_formats`、`download_all`。生成流程先把扫描代码和依赖结果规范化为 JSON，再依次调用图表、Mermaid、Markdown、Word 和 PDF MCP；HTML 从已核验 Markdown/报告 JSON 转换。MD、DOCX、PDF 各自由不同 MCP 生成并记录独立哈希审计。生成和下载各有一次 interrupt。组件漏洞目录使用两次 interrupt；项目 SBOM 使用漏洞匹配、Excel 生成和下载三次 interrupt。下载中断携带固定制品的 `artifact_ids`，SBOM 还可携带系统目录语义 `destination_hint`。

恢复请求应原样提交确认卡片中的 `thread_id` 与 `interrupt_id`，服务端会校验卡片是否仍是该线程的当前阶段。待确认检查点保存在本机数据目录的 SQLite 中，客户端或本地服务重启后仍可恢复；已经推进的旧卡片返回 `409`，升级前遗留且无法恢复的卡片返回 `status=expired` 并从历史消息中清除，不再返回误导性的 `404`。

恢复 interrupt 示例：

```json
{
  "thread_id": "report-action-...",
  "decision": "confirm",
  "format": "pdf",
  "user_id": "local-user",
  "session_id": "default"
}
```

### 3.10 LLM 与长期记忆

| 方法 | 路径 | 请求 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/llm/config` | - | 返回脱敏模型配置和提供商目录 |
| PATCH | `/api/llm/config` | `LLMConfigRequest` | 保存 OpenAI、Claude、DeepSeek 或自定义端点配置 |
| POST | `/api/llm/test` | `LLMConfigRequest` | 测试模型连通性 |
| POST | `/api/llm/models` | `LLMModelsRequest` | 根据提供商官方 API 查询可用模型 |
| GET | `/api/assistant/conversations` | Query: `user_id`, `limit`, `archived` | 查询“智能问答”项目中的活动或归档对话摘要 |
| GET | `/api/assistant/conversations/{session_id}` | Query: `user_id` | 读取指定用户的完整普通问答会话，用于恢复历史上下文 |
| POST | `/api/assistant/conversations/{session_id}/archive` | `AssistantConversationArchiveRequest` + `user_id` | 归档或恢复普通问答会话 |
| DELETE | `/api/assistant/conversations/{session_id}` | Query: `user_id` | 永久删除会话并重建不含该会话的长期记忆摘要 |
| DELETE | `/api/memory` | `MemoryClearRequest` | 清除指定用户长期记忆 |

### 3.11 兼容路径

旧版 `/api/ask`、`/api/tasks`、`/api/graph`、`/api/collector-graph`、`/api/runtime`、`/api/report-actions` 和 `/api/memory/conversations...` 路径仍可响应，以保证已安装客户端平滑升级，但不会出现在 OpenAPI 中。新客户端、脚本和第三方集成应只使用本章列出的规范路径。

会话详情中的 `exchanges[].answer_payload` 保存经过公开输出脱敏后的回答展示载荷，用于恢复 Security Agent 的 Trace、Tool Call、Sources、Token、图表与制品状态；旧记录没有该字段时客户端继续使用 `answer`、`mode`、`confidence` 和 `fields` 兼容恢复。

会话摘要固定返回 `project_id=assistant`、`project_name=智能问答`、`archived` 和 `archived_at`。会话接口同时使用 `user_id` 和 `session_id` 查找记录，不会跨用户返回同名会话。归档会话继续提问时会自动恢复为活动状态。模型密钥不会在公开配置响应中原样返回。`wire_api` 可选择 `chat` 或 `responses`；支持的推理强度由所选模型和提供商决定。

## 4. 关键请求模型

完整字段、枚举、长度限制和响应 Schema 以同目录 `openapi.json` 为准。主要模型映射如下：

| 模型 | 用途 |
| --- | --- |
| `AskRequest` / `AskAttachment` | 问答和上传附件 |
| `AssistantConversationArchiveRequest` | 普通问答会话归档与恢复 |
| `AgentTaskCreateRequest` | 工作区任务 |
| `AssistantWorkspaceActionRequest` | LLM 工作区动作规划和 SBOM/扫描分流 |
| `AgentTaskReportDecisionRequest` | 是否生成报告 |
| `AgentTaskReportDownloadDecisionRequest` | 是否下载及格式 |
| `ReportActionRequest` / `ReportActionResumeRequest` | 独立报告子图 interrupt |
| `ComponentVulnerabilityRequest` | 组件漏洞查询和导出 |
| `IntelligenceQueryRequest` | 漏洞情报和知识图谱查询 |
| `CollectorConfigUpdate` | 漏洞采集器配置 |
| `LLMConfigRequest` / `LLMModelsRequest` | 模型配置、测试和列表 |
| `UserProfileSettingsUpdate` | 用户资料 |
| `AppPreferenceSettingsUpdate` | 客户端通用设置 |
| `SubscriptionCheckoutRequest` | 订阅下单 |
| `SubscriptionPaymentEvent` | 已签名支付事件 |

## 5. 兼容性与演进规则

- 客户端启动时通过 `/health` 检查服务与契约版本。
- 新增可选字段应保持旧客户端可解码；删除或改变字段语义时必须升级契约版本。
- SSE 事件消费者应忽略未知事件和未知 JSON 字段。
- 报告和助手制品只能通过服务返回的 ID 下载，不应拼接任意文件路径。
- 修改接口后应重新生成 `openapi.json`，并运行 Python 接口测试和 Swift `ModelDecodingTests`。

# SecFlow 独立智能问答模块

## 1. 目标

独立智能问答模块复用 SecFlow 当前的 LangGraph、MCP、漏洞情报和长期记忆能力，但不启动工作区扫描任务、订阅、资讯面板或平台管理 API。它适合本地安全知识问答、嵌入其他客户端和独立接口联调。

完整应用入口保持为 `app.main:app`；独立入口为 `app.assistant_app:app`。两者共享同一套问答业务代码和数据格式，不复制提示词、LangGraph 或 MCP 实现。

## 2. 模块边界

| 层 | 文件 | 说明 |
| --- | --- | --- |
| 独立应用 | `app/assistant_app.py` | FastAPI 应用、健康检查和 Assistant Router 挂载 |
| API | `app/api/routes/assistant.py` | 只提供 `/api/assistant` 路由 |
| Agent | `app/agent/assistant_service.py` | 问答调用、Markdown 无损 SSE 分片、Interrupt 恢复与失效结果 |
| LangGraph | `app/langgraph/assistant_graph.py` | 意图理解、记忆、情报、组件、SBOM、报告和 LLM 编排 |
| MCP | `app/mcp/` | Excel、D3 Sankey、Mermaid、Markdown、Word 与 PDF 工具 |
| 记忆 | `app/memory.py` | 按 `user_id + session_id` 保存、归档和删除历史对话 |

独立入口不提供 `/api/agent/tasks`、`/api/subscriptions`、`/api/information` 或设置管理接口。

## 3. 运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.assistant_app:app \
  --host 127.0.0.1 \
  --port 18082
```

默认应绑定回环地址。该模块没有完整服务端登录认证，不应直接暴露到公网；需要远程访问时，应在反向代理或 API Gateway 上增加认证、TLS、限流和审计。

## 4. API

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/health` | 独立服务健康检查 |
| `GET` | `/api/assistant/graph` | 当前智能问答 LangGraph 定义 |
| `POST` | `/api/assistant/questions` | 同步问答 |
| `POST` | `/api/assistant/questions/stream` | `trace -> content -> result/error` SSE 流 |
| `POST` | `/api/assistant/interrupts/resume` | 恢复组件、SBOM 或报告确认节点 |
| `GET` | `/api/assistant/artifacts/{artifact_id}` | 下载经过登记的助手制品 |
| `GET` | `/api/assistant/conversations` | 查询活动或归档会话 |
| `GET` | `/api/assistant/conversations/{session_id}` | 恢复完整历史对话 |
| `POST` | `/api/assistant/conversations/{session_id}/archive` | 归档或恢复会话 |
| `DELETE` | `/api/assistant/conversations/{session_id}` | 永久删除会话 |

SSE 的 `content.delta` 按原始回答分片，拼接后必须与最终 Markdown 完全一致。`Thinking` 和 `trace` 只展示高层节点任务，不返回模型私有推理。

## 5. 扫描与报告状态一致性

完整客户端中的扫描执行记录与独立问答报告能力共享以下门禁：

1. `node.started` 和 `node.progress` 是历史过程事件，不单独代表当前任务仍在运行。
2. 同一节点有更新进度时只展示最新心跳；节点或任务终止后不再显示运行动画。
3. 后端仅在扫描结果已固化、计划步骤全部为 `completed/skipped`，且存在 `task.completed` 事件时设置 `report_ready=true`。
4. 前端报告确认卡和后端报告 API 都以 `report_ready` 为准，避免只依据单个状态字段。
5. 报告生成、下载事件不覆盖扫描任务的 `current_node`。

## 6. 验证

```bash
.venv/bin/python -m unittest \
  tests.test_assistant_module \
  tests.test_assistant_stream \
  tests.test_task_agent

swift test --package-path macos/SecFlowMac \
  --filter AgentTaskViewTests
```

独立路由契约测试会确认问答、SSE、Interrupt 和会话接口存在，同时确认扫描任务和订阅路由没有进入独立应用。

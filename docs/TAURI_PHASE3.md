# SecFlow 第三阶段 Tauri 客户端基线

## 1. 阶段结论

第三阶段采用 `Tauri 2 + React 19 + TypeScript + Python Sidecar`，不改写 LangGraph。桌面端通过稳定的 HTTP/SSE 契约连接 FastAPI 控制面，FastAPI 再把扫描任务交给独立 LangGraph Worker；Semgrep、Tree-sitter、SBOM 与报告 MCP 继续运行在 Python 侧。

```text
Tauri / React
  -> HTTP + SSE
FastAPI 控制面
  -> SQLite WAL 任务队列
独立 LangGraph Worker
  -> Code Scan MCP / SBOM MCP / Report MCP
```

源码目录为 `desktop/SecFlowTauri`。旧 SwiftUI 兼容客户端已从主分支移除，桌面功能、测试和发布均以 Tauri 客户端为唯一实现。

## 2. 真实 21st.dev 收藏清单

2026-08-01 通过已登录账号的 `Bookmarks -> 人工智能前端` 清单核对。账号共有 42 个收藏，其中该清单有且仅有以下 4 个组件。首页热门、推荐组件和 38 个未分类收藏不属于这份清单，不得作为第三阶段设计依据。

| 收藏组件 | 作者 | 可核验链接 | SecFlow 落位 | 实现文件 |
| --- | --- | --- | --- | --- |
| Advanced Stats | ui layout | [21st.dev](https://21st.dev/@uilayout.contact/components/advanced-stats) | 漏洞情报 KPI、严重度分布和近期面积趋势 | `src/components/IntelligenceView.tsx` |
| Card | Ravi Katiyar | [21st.dev](https://21st.dev/@ravikatiyar162/components/card-11) | 右上角实时咨询的图片、标题、来源和时间列表 | `src/components/InformationPanel.tsx` |
| Chatgpt Prompt Input | EaseMize UI | [21st.dev](https://21st.dev/@easemize/components/chatgpt-prompt-input) | 项目选择、命令、Agent/知识库入口、发送和停止 | `src/components/PromptComposer.tsx` |
| AI Planning | Arun Dass | [21st.dev](https://21st.dev/@arunjdass/components/ai-planning) | 计划、运行、成功、失败、耗时和 MCP 状态时间线 | `src/components/AgentTimeline.tsx` |

这里复用的是信息层级和交互模型，不复制示例业务数据。SecFlow 展示的数字、步骤、来源和状态必须来自真实 API/SSE，不能用组件预览中的模拟值替代。

## 3. ZCode 能力对照

2026-08-01 对本机 `/Applications/ZCode.app` 的公开工作区界面进行了只读核对。第三阶段吸收与 SecFlow 工作流直接相关的能力：

| ZCode 可见能力 | SecFlow 对应实现 | 处理结论 |
| --- | --- | --- |
| `⌘N` 新建任务 | `AppSidebar.resetConversation` | 已采用 |
| `⌘K` 搜索与命令面板 | `CommandPalette`、`Topbar` | 已采用 |
| 项目和任务分组 | `AppSidebar` 项目、扫描任务和历史对话 | 已采用 |
| 筛选、归档入口 | `ArchiveView` 和任务/会话菜单 | 已采用核心能力 |
| 可收缩侧栏 | 悬停覆盖式展开，主工作区不参与宽度重排 | 已采用并针对卡顿优化 |
| 设置与 Agent 配置 | `SettingsView` 的资料、模型、外观、来源、日志和订阅 | 已采用 SecFlow 范围 |
| 后退/前进 | 当前由项目、任务和会话显式选择替代 | 暂不复制浏览器式历史栈 |
| 自动化、移动端远控 | 不属于当前安全扫描闭环 | 不采用 |
| 插件入口 | 产品要求已移除插件入口 | 不采用 |

ZCode 仅作为桌面信息架构和操作密度参考。SecFlow 不读取 ZCode 私有会话数据，不依赖其运行时，也不会把 ZCode 的通用自动化能力混入代码扫描 Agent。

## 4. 前端能力复刻范围

| SecFlow 能力 | Tauri 实现 |
| --- | --- |
| 智能问答与流式正文 | `AssistantWorkspace` 按 50 ms 合并 SSE 文本增量 |
| Agent 执行可视化 | `AgentTimeline` 合并计划和事件，未执行节点保持 pending |
| Tool Call / Sources / Markdown / Mermaid | `ChatMessage`、`ToolCall`、`MermaidBlock` |
| 项目扫描、停止、重扫 | `TaskCard` + 任务事件 SSE |
| 报告生成与下载 Interrupt | `TaskCard` 中生成确认、格式选择和下载确认 |
| SBOM、许可、漏洞匹配 | 通过智能问答和任务子图触发，不增加独立导航页 |
| 漏洞情报与漏洞库 | `IntelligenceView`、`RecordsView` |
| 实时咨询 | `InformationPanel`，强制按发布时间倒序 |
| 项目/对话归档与删除 | `AppSidebar`、`ArchiveView` |
| 用户资料、模型、外观、日志、订阅 | `SettingsView` |
| 深浅色与字体 | CSS token + PingFang SC / SF Pro Text / Apple Color Emoji |

第三阶段没有复制登录/注册流程；这是用户明确排除的范围。500 项目冻结评测也不由客户端触发修改，仍使用既有清单、规则、限制和回归门禁。

## 5. 运行时与事件契约

Tauri 进程启动 `externalBin` 中的 `secflow-backend`，并传入应用数据目录、离线 Semgrep 运行时和规则目录。后端只监听 `127.0.0.1:18781`。

任务事件流遵循：

```text
首次 GET 任务快照
  -> SSE + Last-Event-ID/after
  -> 按 sequence 增量合并
  -> 终态事件后再次 GET 完整快照
  -> 连续断线按 1/2/5 秒退避
```

只有完整任务快照同时满足终态、结果已固化和 `report_ready=true` 时，前端才显示报告确认入口。正文 SSE 和任务 SSE 相互独立，避免模型 Token 更新触发整个任务树重绘。

## 6. 构建与验证

前端验证：

```bash
cd desktop/SecFlowTauri
pnpm build
```

Rust 验证：

```bash
cd desktop/SecFlowTauri/src-tauri
cargo check --target aarch64-apple-darwin
```

macOS 完整构建：

```bash
scripts/build_tauri_macos.sh
```

构建脚本会重新生成以下非源码目录，因此它们已进入 `.gitignore`：

- `desktop/SecFlowTauri/node_modules`
- `desktop/SecFlowTauri/dist`
- `desktop/SecFlowTauri/src-tauri/target`
- `desktop/SecFlowTauri/src-tauri/binaries`
- `desktop/SecFlowTauri/src-tauri/resources`

图标、Rust 配置、React 源码和构建脚本保留为源码资产。

构建脚本在生成 Tauri Bundle 前会执行 `scripts/validate_tauri_backend_workers.sh`：它使用隔离数据目录启动 PyInstaller 后端，并要求 `/health` 同时满足 `mode=external-process`、`configured_workers=2` 和 `running_workers=2`。空任务队列也必须保持两个独立 Worker，避免首次提交扫描时才发现打包态进程启动失败。

2026-08-01 的打包应用内全链路任务 `task-df6947a5-53a3-437e-96d5-a3ae07eb5aa6` 已完成，观察到 2 个 finding、3 个依赖、171 个 AST 节点、8 个 CFG 节点、5 条 CFG 边和 0 个解析错误；许可扫描经 SBOM Agent 的 SSE MCP，代码扫描经 Code Scan MCP SSE，最终 `report_ready=true` 且报告决定保持 `pending`，证明报告入口没有提前越过人工确认。

Worker 常驻与 PyInstaller 冷启动修复后的最终打包回归任务为 `task-7a9c7928-3549-4936-bb8a-b5b16672dcc6`。任务从本地项目提交开始，经 SQLite 队列交给独立 Worker；SBOM Agent 许可 MCP 与代码扫描 MCP 均通过 SSE 在不同子进程完成。扫描结束时报告状态先保持 `pending`，确认生成后进入下载 Interrupt，再次确认 PDF 格式后才返回下载产物。下载文件为 5 页 A4 PDF，SHA-256 `199e75487a867ddc58c7a7061e14f2a35748f8319532c0f017c587db35497f62`。

最终 arm64 分发目录为 `/Users/shayshen/Desktop/SecFlow-v1.3.0-Tauri-20260801-Final`：

- `安全智脑-SecFlow-v1.3.0-macOS-arm64.app`
- `安全智脑-SecFlow-v1.3.0-macOS-arm64.dmg`
- DMG SHA-256：`9f1dd1a424b53ea542cf1654088ec4f8d508d45123f5c77513ce04485ff1242a`

## 7. 分发限制

当前本地构建为 ad-hoc 签名。`codesign --deep --strict` 和 DMG 结构校验可以通过，但没有 Apple Developer ID 和公证凭据，不能宣称已通过 Gatekeeper 公证。外部分发前必须补齐 Developer ID、hardened runtime 下的统一嵌套签名和 notarization。

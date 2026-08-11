# SecFlow macOS Client

SecFlowMac 是知识库安全助手的原生 SwiftUI 客户端，最低支持 macOS 14。发布版应用内置 FastAPI/LangGraph 智能体后端，由应用自动启停，不依赖 Docker 或仓库中的独立服务。正式版数据保存在 `~/Library/Application Support/SecFlow`，7 天试用版使用隔离目录 `~/Library/Application Support/SecFlow-Trial-7Days`。

前端源码位于 `Sources/SecFlowMac`，后端源码位于仓库根目录 `app/`。发布包会把 Python 后端、静态 Web 资源、Semgrep CLI、多语言规则和 Tree-sitter 运行库一起放入 `.app`，用户不需要安装 Python 或扫描工具。

智能问答页采用紧凑任务侧栏，按执行中、最近和已归档分组并支持搜索。终态任务可归档、恢复或经确认后永久删除，运行中任务必须先停止。上传项目扫描结果会显示 LangGraph 自适应子图的静态规则、AST/CFG/DFG、污点证据、项目 Overlay、差分重扫状态，以及基线/当前指标和 prompt、skill、Overlay 指纹；这些项目级调整不会写入冻结的 500 项目评测路径。

聊天体验采用原生 Security Agent 工作台：分析期间实时展示真实 LangGraph 时间线和 Skeleton，正文优先转发模型供应商的真实 SSE 文本 delta；确定性回答才使用兼容分片。完成后显示模型、工具/MCP 数量、耗时、可用的汇总 Token 数和知识命中。Thinking 仅展示高层任务，模型 reasoning/thinking 不传输；Tool Call 与 Sources 默认折叠，公开来源可跳转。正文支持 Markdown 表格、代码、图片和基础 Mermaid，并提供复制、重新生成、继续、导出、分享和收藏操作。交互参考 21st.dev 的 AI Tool Call、Chain of Thought、Sources、Prompt Box 与 Actions 模式，但全部由 SwiftUI 实现。

客户端将对话和任务高频状态分别放入 `AssistantStore` 与 `AgentTaskStore`，避免进度变化让无关页面重算。问答正文分片按 50 ms 合并后更新 UI；扫描任务先取一次快照，再消费带 `sequence` 的 SSE 事件，并通过 `Last-Event-ID` 恢复连接，连续失败时按 2/5/10 秒退避并降级为低频快照请求。

内置 FastAPI 只作为控制面，扫描任务写入 SQLite WAL 持久队列后由独立 Python Worker 子进程执行。Worker 使用租约与心跳防止重复领取；子进程退出时自动重启，租约过期任务最多恢复三次。客户端退出时控制面和 Worker 一并停止，未完成任务在下次启动后恢复。

登录后的首次设置统一为 6 步向导：用户资料、角色、模型厂商、具体模型、连接信息和验证完成。资料与角色必须先保存成功，模型必须先通过连接测试；再次登录时会从第一个缺失步骤恢复，完整配置的已有账号直接进入工作区。

## 开发运行

开发阶段可先在仓库根目录启动后端：

```bash
uvicorn app.api.routes.application:app --host 127.0.0.1 --port 18081
```

再启动客户端：

```bash
swift run --package-path macos/SecFlowMac
```

开发运行时通过 `SECFLOW_SERVER_URL=http://127.0.0.1:18081` 指定外部服务。构建后的应用使用内置本地服务。

## 构建应用

```bash
python -m pip install -r requirements-macos.txt
bash scripts/build_macos_app.sh
open dist/SecFlow.app
```

脚本会把后端打包到应用资源目录，生成 `dist/SecFlow.app` 并默认进行 ad-hoc 签名。分发给其他设备前，应替换为正式 Developer ID 签名并执行 notarization。

## 7 天试用版与双架构构建

Apple Silicon：

```bash
bash scripts/build_macos_trial_app.sh
```

Intel Mac 构建需要 x86_64 Python 环境，不能用 arm64 Python 交叉封装：

```bash
SECFLOW_MACOS_ARCH=x86_64 \
PYTHON_BIN=/path/to/x86_64/venv/bin/python \
bash scripts/build_macos_trial_app.sh
```

输出目录为 `dist-macos-trial/`。试用包使用独立 Bundle ID、回环端口、应用数据目录和 Keychain 服务，不会与正式版或旧试用版数据混用。首次启动后连续可用 168 小时；后端负责到期拦截，SwiftUI 显示实时倒计时和到期锁定界面。

历史 3 天试用版发布包：

- [Apple Silicon arm64](https://github.com/FuNianTongXue/secflow-knowledge-security-assistant/releases/download/v1.2.0-macos-agent-trial/SecFlow-Trial-3Days-macOS-arm64.zip)
- [Intel x86_64](https://github.com/FuNianTongXue/secflow-knowledge-security-assistant/releases/download/v1.2.0-macos-agent-trial/SecFlow-Trial-3Days-macOS-x86_64.zip)

### 内嵌静态分析 CLI

发布构建会把 Semgrep OSS CLI、Java/Python/Go/C/C++/C#/Rust/Solidity 离线规则、Tree-sitter 语法模块（包括 C++ 文件的 CUDA fallback）和 LGPL-2.1/MIT 许可证一起放入应用。规则完全离线运行，显式关闭 metrics、版本检查和在线 Registry；客户无需安装 Homebrew、Python 或其他分析工具。

```bash
.venv/bin/python -m pip install -r requirements-macos.txt
bash scripts/build_macos_app.sh
```

构建脚本会在签名前启动应用内 CLI，并对八种语言的临时文件执行真实 source/sink 或结构规则扫描。CLI、任一语言规则、语法运行库或结果解析缺失都会终止构建。商业发布还需保留 `Contents/Resources/licenses` 下的 Semgrep 与 Tree-sitter 许可证，并按 LGPL-2.1 提供对应 Semgrep 源码获取方式。

## 验证

```bash
swift build --package-path macos/SecFlowMac
swift test --package-path macos/SecFlowMac
```

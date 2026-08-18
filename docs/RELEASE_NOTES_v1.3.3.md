# SecFlow v1.3.3 发行说明

- 发布日期：2026-08-18
- 客户端：Windows x86_64、macOS arm64、macOS x86_64
- 版本类型：无限期正式版、首次成功启动后连续 7 天试用版

## 重点更新

- Tauri 2、React/TypeScript 与 Python LangGraph sidecar 统一为 v1.3.3；桌面宿主向后端注入当前 Cargo 版本，关于页、OpenAPI 与安装包版本保持一致。
- 首次配置、模型厂商选择、模型锁定与服务恢复流程重新整理；支持 Kimi、OpenAI、Claude、DeepSeek、Ollama 和 OpenAI 兼容接口。
- 设置页集中展示 10 个 Agent、7 个 Skills、15 个 MCP Server 与 17 个 MCP Tools，平台适配器明确显示操作系统和架构。
- OpenAPI 更新为 78 个路径、88 个 HTTP 操作和 33 个 Schema。

## Windows 修复

- 补齐 `pywin32` 和 `tzdata`，构建阶段验证 `pywintypes` DLL 与 `Asia/Shanghai` 时区数据，修复安装后缺模块和时区初始化失败。
- Windows 启动时跳过 macOS 专属透明资讯窗口和状态栏入口，避免 WebView2 在主窗口首帧前退出。
- 父进程存活检测改用 Win32 `OpenProcess` / `WaitForSingleObject`；宿主被强制终止后不再残留孤儿后端。
- 构建脚本从 `package.json` 读取版本，不再硬编码旧版本号；新增 Windows 打包依赖和生命周期回归测试。

## Windows 11 验证

在 Parallels Desktop 的 Windows 11 x86_64 环境完成以下验收：

- NSIS 安装和 GUI 首次引导成功。
- 七天试用状态为 active，可进入工作区。
- `http://127.0.0.1:18783/health` 返回 `ok: true`，两个任务 Worker 正常运行。
- 日志中没有 `pywin32`、`pywintypes`、`tzdata` 或时区 Traceback。
- 强制结束桌面父进程后，本机后端不会继续监听端口。

## macOS 验证

- Apple Silicon v1.3.3 七天试用版完成首次启动、试用剩余 7 天、工作区、漏洞情报、漏洞库、Agent、Skills 与 MCP 页面验证。
- 三组真实操作录屏已转为优化 GIF，发布在 `docs/assets/demos/`。
- macOS 发布包当前为 ad-hoc 签名，未使用 Apple Developer ID 公证；其他 Mac 首次打开时可能需要在 Finder 中右键选择“打开”。

## 兼容与安全边界

- 正式版使用 `127.0.0.1:18781` 与 `ai.secflow.security-agent`。
- 七天试用版使用 `127.0.0.1:18783` 与 `ai.secflow.security-agent.trial7days`。
- 项目源码默认只在本机读取；MedPeer 架构绘图试用仅接收抽象模块和数据流，不上传源码、密钥或用户数据。平台因研值前置条件未返回图片，当前发布图由相同描述在本地生成并保留 Graphviz 源文件。
- 公开 GitHub Release 只包含七天试用安装包；无限期正式版仅本地归档。

## 已知限制

- Windows 交叉构建产物未做 Authenticode 签名；macOS 产物未做 Developer ID 签名与公证。
- 静态与语义扫描不能替代运行时渗透测试和人工复核。

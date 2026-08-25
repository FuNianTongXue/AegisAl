# 神盾 / AegisAl v1.3.4 发布说明

发布日期：2026-08-25

## 版本边界

- 源码、API 文档、架构文档、产品文档和试用客户端版本：`1.3.4`。
- GitHub Release 提供 Apple Silicon `arm64` 和 Intel `x86_64` 两个 14 天试用 DMG。
- 两个试用包均由提交 `02fa7e259a3817a866e5595640d058320232025a` 的干净工作树构建，内置版本号为 `1.3.4`。
- 不公开上传正式版安装包。

## 后续发布调整

- 本次为 AegisAl 在 GitHub 的最后一次公开源码更新和公开试用版发布。
- 后续产品更新不再开源，也不再同步至 GitHub。
- 后续试用版仅在微信群发布；GitHub 仓库和当前 Release 作为 `v1.3.4` 历史公开快照保留。

## 修复的问题

- 修复表情偏好无法点击或无法传递到普通问答的问题；问候类回答可按关闭、适中、活跃三档返回表情。
- 修复已完成思考过程仍自动展开的问题；思考和工具调用统一为可折叠时间线。
- 修复报告生成缺少翻译兜底、翻译失败导致报告链路中断的问题。
- 修复结构化漏洞表格没有展示翻译后全量行列、不可编辑或编辑结果无法随会话恢复的问题。
- 修复确认下载与 Excel 下载重复确认目录的问题。
- 修复信息中心没有跟随主窗口主题，以及浅色背景覆盖文字的问题。
- 修复模型配置无法锁定、第三方 Base URL/API Key 无法保存和模型目录刷新不一致的问题。
- 修复本机加密密钥并发创建、旧密钥恢复和解密失败时误覆盖状态的问题。
- 修复大型项目被固定总容量上限阻断的问题，扫描改为最多 5000 文件或 64 MiB 一批。
- 修复旧应用副本和旧构建 bundle 可能继续显示“安全智脑”启动页的问题。
- 修复问答与扫描结果左侧状态头像仍使用通用盾牌图标的问题，统一为 AegisAl Logo。

## 新增与优化

- 品牌统一为“神盾 / AegisAl”，更新应用、托盘、安装包及界面 Logo。
- 新增普通问答本地问候、表情策略和脱敏流式执行过程。
- 新增结构化表格搜索、分页、全量数据展示与单元格编辑持久化。
- 新增漏洞后台翻译队列、缓存、流式导出和翻译验收边界。
- Code Scan MCP 改为 Host 管理的本地 `stdio` 子进程，并压缩大型 MCP 输出。
- 报告支持 Markdown、HTML、Word、PDF、Excel、SARIF 与整包下载。
- 正式版与 14 天试用版使用独立 Bundle ID、端口、数据和授权状态。
- 试用版启动时校验内置 sidecar 身份、试用时长与发布溯源信息，校验失败时关闭启动。

## 14 天试用包

| 平台 | 客户端构建 | 文件 | SHA-256 |
| --- | --- | --- | --- |
| macOS Apple Silicon (`arm64`) | `1.3.4` | `AegisAl-v1.3.4-macOS-ARM64-Trial-14Days.dmg` | `d7baa80fba3b6eb2d35c732f615a74e87dd55585e4feb862c594baf1cffcccf6` |
| macOS Intel (`x86_64`) | `1.3.4` | `AegisAl-v1.3.4-macOS-x86_64-Trial-14Days.dmg` | `e1b5ce87c23ff8f44bf615660b3126f3442f077b7b980de37656693e9bb03bb6` |

两个包均为 ad-hoc 签名，未进行 Apple 公证。首次成功启动后连续可用 336 小时。安装包和对应 `.sha256` 文件见 [v1.3.4 macOS 14 天试用客户端 Release](https://github.com/FuNianTongXue/AegisAl/releases/tag/v1.3.4-trial-14days)。

## 演示与架构

- [普通问答、表情策略、折叠思考与工具时间线](assets/demos/aegisal-v1.3.4-assistant.gif)
- [项目扫描、风险指标与工具执行过程](assets/demos/aegisal-v1.3.4-scan.gif)
- [漏洞情报总览、完整检索与详情查看](assets/demos/aegisal-v1.3.4-intelligence.gif)
- [v1.3.4 架构图（PNG）](assets/aegisal-architecture-v1.3.4.png)、[SVG](assets/aegisal-architecture-v1.3.4.svg)、[Graphviz 源文件](assets/aegisal-architecture-v1.3.4.dot)及[完整架构文档](ARCHITECTURE.md)
- [神盾 AegisAl Logo](assets/aegisal-logo.png)

## 许可证

源码采用 [AegisAl Source-Available Commercial Non-Redistribution License](../LICENSE)。允许审阅、学习、个人评估和内部非生产评估；生产部署、企业内部非评估用途、SaaS、集成、客户交付、转售及再分发须事先获得作者书面许可。第三方声明见 [NOTICE](../NOTICE)。

## 验证

- 前端：27 个测试文件、200 项测试通过；TypeScript 检查和 Vite 生产构建通过。
- 后端：试用授权与打包版本 11 项 Python 测试通过。
- 桌面端：ARM64 与 Intel Rust 检查通过，打包脚本语法校验通过。
- 包完整性：两个 DMG 均通过 SHA-256 与 `hdiutil verify`。
- 架构：Intel 包内 221 个 Mach-O 均为 x86_64；Apple Silicon 包内 338 个 Mach-O 均为 arm64。
- 签名：两个 App 均通过 `codesign --verify --deep --strict`。
- 试用边界：内置时长为 336 小时，外部环境变量无法关闭试用；缺失或修改发布清单时 sidecar 拒绝启动。

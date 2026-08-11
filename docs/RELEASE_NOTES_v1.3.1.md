# SecFlow v1.3.1 发行说明

发布日期：2026-08-11  
客户端：Windows x86_64、macOS arm64、macOS x86_64  
版本类型：无限期正式版、首次启动后连续 7 天试用版

## 本次更新

- 报告数据统一经过 `Unified Report JSON`，Excel、Word、PDF、Markdown、HTML、SARIF 和图表共享同一份冻结结果，避免不同格式重新查询后出现数量或风险等级差异。
- 漏洞情报改为“入库前翻译”：标题、描述、风险等级先批量本地化再持久化，同时保留原文审计字段。报告与 SBOM 直接复用已存译文，不再对每条记录重复调用翻译节点。
- 报告导出移除大结果集的报告期翻译扇出；4,552 条组件漏洞的 Excel 生成基准为 0.604 秒（本机离线基准，不含用户保存对话框时间）。
- 设置页展示当前客户端内置的 Agent、Skills、MCP 与 Platform Adapter；新建任务、项目扫描、短期咨询和长期项目记忆边界更明确。
- Windows 与 macOS 使用同一套 Tauri/React UI、LangGraph 编排和 Python sidecar；新增 Windows x86_64 Tauri/NSIS 构建链和 macOS Intel 自动构建链。

## 已修复问题

- 修复报告生成阶段卡住、切换设置或情报页面后 SSE 被卸载、返回任务时节点中断或动作消失的问题。工作区改为保活隐藏，任务事件继续按 SQLite sequence 续接。
- 修复报告和项目 SBOM 中 `critical/high/medium/low` 风险等级未翻译的问题；所有导出器统一调用确定性风险等级本地化映射。
- 修复报告生成重复翻译、重复查询、重复 MCP 调用和长耗时问题；确认生成后只消费冻结结果。
- 修复扫描引擎降级原因不透明的问题：完整扫描失败会显示实际引擎、失败阶段与 internal-fallback 原因，不再将降级误报为成功。
- 修复点击漏洞情报再返回任务时执行节点消失、报告确认状态丢失的问题。
- 修复删除任务后前端缓存仍保留旧任务、任务按钮没有回到任务主页、新建任务复用旧会话的问题。
- 修复 APP 启动时模型接入阻塞主界面的问题；后端 readiness、模型健康检查和 UI 恢复解耦。
- 修复模型设置页“从厂商读取/添加模型”、高级参数和启用开关的水平布局、圆角与方框叠加问题。
- 修复信息中心普通问题无回复、会话错误写入长期记忆的问题；信息中心只使用窗口内短期记忆，项目/任务继续使用按用户隔离的长期记忆。
- 修复 Excel 及“全部格式”下载入口不完整的问题，并统一下载制品的 MIME、文件名、哈希和存在性校验。

## 报告生成链路

```text
Scanner -> Analysis Agent -> RAG Agent -> Report Planner
        -> Chart Planner -> AI Writer -> QA Agent
        -> Unified Report JSON -> Template/Chart/Report MCP
        -> Word/Excel/PDF/HTML/Markdown/SARIF -> Platform Adapter
```

报告查询结果一经用户确认即冻结；每个导出器只读取相同的 canonical payload，并记录输入哈希、输出哈希、MIME、大小与错误。任何必须制品失败时，流程会给出具体失败节点，不会登记空文件。

## 验证基线

- Python 回归：662 项通过。
- React/TypeScript 回归：77 项通过。
- Vite 生产构建通过。
- 4,552 条组件漏洞 Excel 离线生成：0.604 秒。
- macOS ARM 应用签名、Bundle ID、试用版独立应用标识与 sidecar 完整性校验通过。
- macOS arm64 在 Apple Silicon 主机构建；macOS x86_64 使用 Rosetta 与独立 Intel Python sidecar 本地构建，并复核主程序与 sidecar 架构。
- Windows x86_64 使用 `cargo-xwin` + MSVC SDK + NSIS 交叉构建；已验证宿主程序为 PE32+ x86-64，安装包为 NSIS 自解压归档。因当前为 macOS 构建主机，最终安装/启动验收需在 Windows 10/11 x64 真机执行。
- 六个本地安装包全部生成 SHA-256 清单；GitHub 仅发布三个七天试用制品。

> GitHub Actions 原生 Windows/macOS Intel 备用工作流已提交，但本次运行因 GitHub 账户 billing lock 在 job 启动前被平台拒绝，与源码和构建步骤无关。本次发布改由本地双架构/交叉构建完成。

## 发布范围

GitHub Release 仅上传 Windows x86_64、macOS arm64、macOS x86_64 三个 7 天试用安装包。无限期正式版只保存在本地发布目录，不上传公开仓库。

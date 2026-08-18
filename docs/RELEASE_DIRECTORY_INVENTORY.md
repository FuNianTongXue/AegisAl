# SecFlow-Release 目录梳理

盘点时间：2026-08-18。旧发布包采用可恢复方式移入系统废纸篓；运行数据、报告制品和评测证据不在清理范围内。

| 目录 | 约占空间 | 内容与处理原则 |
| --- | ---: | --- |
| `源码/` | 21 GB | 当前产品源码、测试、Tauri/Rust 构建缓存和 Python 环境；Git 只提交源码、配置、测试与文档，排除环境和构建产物。 |
| `安装包/` | 780 MB | 仅保留 v1.3.3 的正式/试用安装包矩阵、发行说明和校验清单。 |
| `build-logs/` | 594 MB | 保留非安装包诊断日志和原始 MOV 录屏；`package-backup/staging/superseded` 旧发布快照已移入系统废纸篓。 |
| `文档/` | 89 MB | 外部发布说明、架构材料和校验清单。 |
| `ui-redesign/` | 285 MB | UI 重构设计与验证资料；不作为运行时依赖。 |
| `data/` | 160 KB | 本地状态样本；用户数据、凭证与运行态数据库不提交。 |

## 源码发布边界

提交：`app/`、`desktop/SecFlowTauri`（排除 `node_modules/target/resources`）、`macos/`（排除 `.build`）、`config/semgrep/`、`scripts/`、`tests/`、`docs/` 中产品文档与新版截图、依赖清单和许可证。

排除：`.venv/`、`node_modules/`、Rust/Swift/PyInstaller 构建缓存、运行数据、密钥、已生成报告、安装包、临时评测结果和历史构建日志。

## 安装包矩阵

| 平台 | 正式版 | 7 天试用版 | GitHub 公开 |
| --- | --- | --- | --- |
| Windows x86_64 | v1.3.3 本地归档 | v1.3.3 | 仅试用版 |
| macOS arm64 | v1.3.3 本地归档 | v1.3.3 | 仅试用版 |
| macOS x86_64 | v1.3.3 本地归档 | v1.3.3 | 仅试用版 |

正式版不上传公开 Release。公开仓库只发布三种架构的七天试用安装包、源码、文档、演示 GIF 和 SHA-256 清单。

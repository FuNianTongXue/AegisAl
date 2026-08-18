# SecFlow v1.3.3 SHA-256 校验清单

生成日期：2026-08-18

| 平台 | 版本类型 | 文件名 | 大小（字节） | SHA-256 |
| --- | --- | --- | ---: | --- |
| macOS arm64 | 正式版 | `SecFlow-v1.3.3-macOS-ARM64-Formal.dmg` | 154208928 | `cbd00c04c6a5b15fe3af19fd11957833737ead115bd585e8c3691bd188f852c0` |
| macOS arm64 | 7 天试用版 | `SecFlow-v1.3.3-macOS-ARM64-Trial-7Days.dmg` | 154209948 | `41ebb3f238bc97e6f2551dd28ff9a93fff02e7a1a59786ee4cbd1a8f2c07af1b` |
| macOS x86_64 | 正式版 | `SecFlow-v1.3.3-macOS-x86_64-Formal.dmg` | 154286278 | `fc984a37c4769447a6094b739efa519ce6bf52f663d2de148268cb8ad417e5f2` |
| macOS x86_64 | 7 天试用版 | `SecFlow-v1.3.3-macOS-x86_64-Trial-7Days.dmg` | 154287755 | `392df88311f9d59f7977e7ad3d2fc2b467666c9200335a4fd3290c7ccd1e1add` |
| Windows x86_64 | 正式版 | `SecFlow-v1.3.3-Windows-x86_64-Formal-Setup.exe` | 100630481 | `02c5787f8515a285e0ee203e7d6ce640a1d4b58a7e039335a5f7ce48bbb6baf8` |
| Windows x86_64 | 7 天试用版 | `SecFlow-v1.3.3-Windows-x86_64-Trial-7Days-Setup.exe` | 100641899 | `b18dc2a8f07e8716e23a055fea59f83a660db29f8230d48b195e0f490685959c` |

GitHub Release 仅公开三个 7 天试用包。三个正式版只保存在本地发布目录，不上传公开 Release。

## 命令行校验

macOS：

```bash
shasum -a 256 <安装包路径>
```

Windows PowerShell：

```powershell
Get-FileHash -Algorithm SHA256 <安装包路径>
```

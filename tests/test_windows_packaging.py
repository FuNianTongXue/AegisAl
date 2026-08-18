from pathlib import Path
import re


ROOT_DIR = Path(__file__).resolve().parents[1]


def _requirement_names(path: Path) -> set[str]:
    names: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            names.add(re.split(r"[<>=!~;\s\[]", line, maxsplit=1)[0].lower().replace("_", "-"))
    return names


def test_windows_runtime_requirements_include_platform_dependencies() -> None:
    for file_name in ("requirements-windows.txt", "requirements-windows-cross.txt"):
        names = _requirement_names(ROOT_DIR / file_name)
        assert {"pywin32", "tzdata"} <= names, file_name


def test_desktop_launcher_passes_current_package_version_to_backend() -> None:
    launcher = (
        ROOT_DIR / "desktop" / "SecFlowTauri" / "src-tauri" / "src" / "lib.rs"
    ).read_text(encoding="utf-8")

    assert '.env("SECFLOW_APP_VERSION", env!("CARGO_PKG_VERSION"))' in launcher

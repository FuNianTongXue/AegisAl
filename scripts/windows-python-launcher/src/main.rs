use std::env;
use std::path::PathBuf;
use std::process::{exit, Command};

fn main() {
    let executable = env::current_exe().expect("cannot resolve 神盾 launcher path");
    let executable_name = executable
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let launcher_dir = executable.parent().expect("launcher has no parent directory");
    let is_semgrep = executable_name.contains("semgrep");
    let backend_dir: PathBuf = if is_semgrep {
        launcher_dir.join("..").join("backend")
    } else {
        launcher_dir.to_path_buf()
    };
    let python = backend_dir.join("python.exe");
    let entrypoint = if is_semgrep {
        "from app.semgrep_runner import main; main()"
    } else {
        "from app.macos_backend import main; main()"
    };

    let status = Command::new(python)
        .arg("-c")
        .arg(entrypoint)
        .args(env::args_os().skip(1))
        .env("PYTHONPATH", &backend_dir)
        .status()
        .expect("failed to launch the bundled 神盾 Python runtime");
    exit(status.code().unwrap_or(1));
}

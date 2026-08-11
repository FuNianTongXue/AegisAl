fn main() {
    println!("cargo:rerun-if-env-changed=SECFLOW_BACKEND_SHA256");
    println!("cargo:rerun-if-env-changed=SECFLOW_BACKEND_PORT");
    println!("cargo:rerun-if-env-changed=SECFLOW_TAURI_TRIAL_BUILD");
    tauri_build::build()
}

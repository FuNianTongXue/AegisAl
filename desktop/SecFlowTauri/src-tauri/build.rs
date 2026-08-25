fn main() {
    println!("cargo:rerun-if-env-changed=SECFLOW_BACKEND_SHA256");
    println!("cargo:rerun-if-env-changed=SECFLOW_BACKEND_PORT");
    println!("cargo:rerun-if-env-changed=SECFLOW_TAURI_TRIAL_BUILD");
    println!("cargo:rerun-if-env-changed=SECFLOW_TRIAL_DURATION_HOURS");
    println!("cargo:rerun-if-env-changed=SECFLOW_APP_RELEASE_CHANNEL");
    println!("cargo:rerun-if-env-changed=SECFLOW_TRIAL_KEYCHAIN_SERVICE");
    tauri_build::build()
}

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    secflow_tauri_lib::run();
}

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use tauri::TitleBarStyle;
use tauri::{
    image::Image,
    menu::{Menu, MenuItemBuilder, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, Rect, RunEvent, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};

struct BackendProcess(Mutex<Option<CommandChild>>);
static TASK_WINDOW_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn run() {
    let app = tauri::Builder::default()
        .menu(build_app_menu)
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            validate_project_directory,
            open_task_window,
            restart_backend,
        ])
        .manage(BackendProcess(Mutex::new(None)))
        .on_menu_event(|app, event| match event.id().as_ref() {
            "secflow-open-settings" => open_settings(app),
            "secflow-open-main" => show_main_window(app),
            "secflow-toggle-information" => toggle_information_window(app, None),
            "secflow-quit" => app.exit(0),
            _ => {}
        })
        .setup(|app| {
            // Launch the backend before constructing the hidden information
            // WebView and menu-bar UI. WKWebView initialization can take many
            // seconds on a cold macOS launch; doing it first left the visible
            // main window interactive while the local API process had not even
            // been spawned yet.
            start_backend(app.handle()).map_err(io::Error::other)?;

            let log_path = app.path().app_log_dir().ok().map(|directory| {
                let _ = std::fs::create_dir_all(&directory);
                directory.join("backend.log")
            });
            append_backend_log(log_path.as_deref(), "[desktop] core setup complete");

            // The transparent information window and template tray icon are
            // macOS-specific surfaces. Creating them on Windows can terminate
            // WebView2 before the primary window receives its first frame.
            #[cfg(target_os = "macos")]
            {
                if let Err(error) = create_information_window(app.handle()) {
                    append_backend_log(
                        log_path.as_deref(),
                        &format!("[desktop] information window unavailable: {error}"),
                    );
                }
                if let Err(error) = create_status_item(app.handle()) {
                    append_backend_log(
                        log_path.as_deref(),
                        &format!("[desktop] status item unavailable: {error}"),
                    );
                }
            }
            #[cfg(not(target_os = "macos"))]
            append_backend_log(
                log_path.as_deref(),
                "[desktop] macOS auxiliary surfaces skipped",
            );
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build SecFlow desktop client");

    app.run(|handle, event| match event {
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } if label == "main" => {
            append_desktop_log(handle, "[desktop] main window close requested");
            #[cfg(not(target_os = "windows"))]
            {
                api.prevent_close();
                if let Some(window) = handle.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            #[cfg(target_os = "windows")]
            let _ = api;
        }
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } if label == "information" => {
            api.prevent_close();
            if let Some(window) = handle.get_webview_window("information") {
                let _ = window.hide();
            }
        }
        RunEvent::ExitRequested { code, .. } => {
            append_desktop_log(
                handle,
                &format!("[desktop] application exit requested: code={code:?}"),
            );
            if let Some(child) = handle.state::<BackendProcess>().0.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
        RunEvent::Exit => {
            append_desktop_log(handle, "[desktop] application exited");
            if let Some(child) = handle.state::<BackendProcess>().0.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
        _ => {}
    });
}

#[tauri::command]
fn restart_backend(app: AppHandle) -> Result<(), String> {
    if std::env::var("SECFLOW_SERVER_URL").is_ok() {
        return Ok(());
    }
    if let Some(child) = app.state::<BackendProcess>().0.lock().unwrap().take() {
        child.kill().map_err(|error| error.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(350));
    }
    start_backend(&app)
}

fn start_backend(app: &AppHandle) -> Result<(), String> {
    if std::env::var("SECFLOW_SERVER_URL").is_ok()
        || app.state::<BackendProcess>().0.lock().unwrap().is_some()
    {
        return Ok(());
    }

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| error.to_string())?;
    #[cfg(target_os = "windows")]
    let backend_executable = resource_dir.join("backend/secflow-backend.exe");
    #[cfg(not(target_os = "windows"))]
    let backend_executable = resource_dir.join("backend/secflow-backend");
    #[cfg(target_os = "windows")]
    let semgrep_executable = resource_dir.join("semgrep/secflow-semgrep.exe");
    #[cfg(not(target_os = "windows"))]
    let semgrep_executable = resource_dir.join("semgrep/secflow-semgrep");
    verify_backend_integrity(&backend_executable).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;

    let log_path = app.path().app_log_dir().ok().map(|directory| {
        let _ = std::fs::create_dir_all(&directory);
        directory.join("backend.log")
    });
    append_backend_log(log_path.as_deref(), "[desktop] starting local backend");

    let parent_pid = std::process::id().to_string();
    let backend_port = option_env!("SECFLOW_BACKEND_PORT").unwrap_or("18781");
    let trial_build = option_env!("SECFLOW_TAURI_TRIAL_BUILD") == Some("1");
    let mut command = app
        .shell()
        .command(backend_executable)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            backend_port,
            "--parent-pid",
            &parent_pid,
        ])
        .env("SECFLOW_DATA_DIR", &data_dir)
        .env("SECFLOW_APP_VERSION", env!("CARGO_PKG_VERSION"))
        .env("SECFLOW_MEMORY_LOCAL_ONLY", "true")
        .env("SECFLOW_BUNDLED_SEMGREP_BIN", semgrep_executable)
        .env("SECFLOW_SEMGREP_RULES", resource_dir.join("semgrep-rules"))
        .env("SECFLOW_CODE_SCAN_MCP_STARTUP_TIMEOUT_SECONDS", "60")
        .env("SECFLOW_BACKGROUND_STARTUP_DELAY_SECONDS", "12")
        .env("PYTHONUNBUFFERED", "1");
    if trial_build {
        command = command
            .env("SECFLOW_TRIAL_ENABLED", "1")
            .env("SECFLOW_TRIAL_DURATION_HOURS", "168")
            .env("SECFLOW_APP_RELEASE_CHANNEL", "7天试用版")
            .env(
                "SECFLOW_KEYCHAIN_SERVICE",
                "ai.secflow.security-agent.trial7days",
            );
    }
    let (mut receiver, child) = command.spawn().map_err(|error| error.to_string())?;
    let child_pid = child.pid();
    *app.state::<BackendProcess>().0.lock().unwrap() = Some(child);

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let terminated = matches!(event, CommandEvent::Terminated(_));
            let line = match event {
                CommandEvent::Stdout(bytes) => {
                    format!("[stdout] {}", String::from_utf8_lossy(&bytes))
                }
                CommandEvent::Stderr(bytes) => {
                    format!("[stderr] {}", String::from_utf8_lossy(&bytes))
                }
                CommandEvent::Error(error) => format!("[process-error] {error}"),
                CommandEvent::Terminated(payload) => format!(
                    "[desktop] backend terminated: code={:?}, signal={:?}",
                    payload.code, payload.signal
                ),
                _ => continue,
            };
            append_backend_log(log_path.as_deref(), &line);
            if terminated {
                let backend_state = app_handle.state::<BackendProcess>();
                let mut process = backend_state.0.lock().unwrap();
                if process
                    .as_ref()
                    .is_some_and(|child| child.pid() == child_pid)
                {
                    process.take();
                }
                let _ = app_handle.emit("secflow:backend-terminated", line);
            }
        }
    });
    Ok(())
}

fn append_backend_log(path: Option<&Path>, line: &str) {
    let Some(path) = path else { return };
    if path
        .metadata()
        .map(|metadata| metadata.len() > 2 * 1024 * 1024)
        .unwrap_or(false)
    {
        let _ = File::create(path);
    }
    if let Ok(mut log) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(log, "{line}");
    }
}

fn append_desktop_log(app: &AppHandle, line: &str) {
    let log_path = app.path().app_log_dir().ok().map(|directory| {
        let _ = std::fs::create_dir_all(&directory);
        directory.join("backend.log")
    });
    append_backend_log(log_path.as_deref(), line);
}

fn verify_backend_integrity(path: &Path) -> io::Result<()> {
    let Some(expected) = option_env!("SECFLOW_BACKEND_SHA256").filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    verify_file_integrity(path, expected)
}

fn verify_file_integrity(path: &Path, expected: &str) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let actual = format!("{:x}", digest.finalize());
    if actual.eq_ignore_ascii_case(expected) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "安全智脑完整性校验失败：本机安全服务已被修改，应用拒绝启动。",
    ))
}

#[cfg(test)]
mod integrity_tests {
    use super::verify_file_integrity;
    use std::{fs, io::ErrorKind, time::SystemTime};

    #[test]
    fn modified_backend_fails_closed_without_changing_the_file() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock must be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("secflow-integrity-{unique}.bin"));
        fs::write(&path, b"trusted-backend").expect("write fixture");
        let expected = "58a3e919c6da4971e1f06a44d50103f5369cfd81f5f3b1face53b5c5f6f54b50";

        verify_file_integrity(&path, expected).expect("original fixture should pass");
        fs::write(&path, b"modified-backend").expect("modify fixture");
        let error = verify_file_integrity(&path, expected).expect_err("modified fixture must fail");

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(&path).expect("fixture remains readable"),
            b"modified-backend"
        );
        fs::remove_file(path).expect("remove fixture");
    }
}

#[tauri::command]
fn validate_project_directory(path: String) -> Result<String, String> {
    let canonical = std::fs::canonicalize(path.trim())
        .map_err(|_| "项目路径不存在或当前无法访问。".to_string())?;
    if !canonical.is_dir() {
        return Err("请拖入一个完整的项目目录，不能只拖入单个文件。".to_string());
    }
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "项目路径包含当前系统无法识别的字符。".to_string())
}

#[tauri::command]
fn open_task_window(app: AppHandle) -> Result<String, String> {
    let sequence = TASK_WINDOW_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let label = format!("task-{sequence}");
    let builder = WebviewWindowBuilder::new(
        &app,
        &label,
        WebviewUrl::App(format!("index.html?secflowWindow=task&taskWindowId={sequence}").into()),
    )
    .title("新建安全任务")
    .inner_size(1280.0, 820.0)
    .min_inner_size(960.0, 640.0)
    .decorations(true);
    #[cfg(target_os = "macos")]
    let builder = builder
        .hidden_title(true)
        .title_bar_style(TitleBarStyle::Overlay);
    builder
        .center()
        .build()
        .map_err(|error| error.to_string())?;
    Ok(label)
}

fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let menu = Menu::default(app)?;
    let settings = MenuItemBuilder::with_id("secflow-open-settings", "设置...")
        .accelerator("CmdOrCtrl+,")
        .build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;

    let items = menu.items()?;
    if let Some(app_submenu) = items.first().and_then(|item| item.as_submenu()) {
        app_submenu.insert_items(&[&settings, &separator], 2)?;
    }

    Ok(menu)
}

fn create_status_item(app: &AppHandle) -> tauri::Result<()> {
    let information = MenuItemBuilder::with_id("secflow-toggle-information", "独立信息咨询")
        .accelerator("CmdOrCtrl+Shift+I")
        .build(app)?;
    let open_main = MenuItemBuilder::with_id("secflow-open-main", "打开安全智脑").build(app)?;
    let settings = MenuItemBuilder::with_id("secflow-open-settings", "设置...").build(app)?;
    let quit = MenuItemBuilder::with_id("secflow-quit", "退出安全智脑").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&information, &open_main, &settings, &separator, &quit],
    )?;

    let mut builder = TrayIconBuilder::with_id("secflow-information")
        .tooltip("安全智脑 信息咨询")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = event
            {
                toggle_information_window(tray.app_handle(), Some(rect));
            }
        });

    // A full-color app icon has an opaque rounded-square background; marking
    // that image as a macOS template turns it into the blank white square seen
    // in the menu bar. Use a transparent monochrome shield-star mask instead.
    let icon = Image::new(include_bytes!("../icons/trayTemplate.rgba"), 32, 32);
    builder = builder.icon(icon).icon_as_template(true);

    builder.build(app)?;
    Ok(())
}

fn create_information_window(app: &AppHandle) -> tauri::Result<()> {
    if app.get_webview_window("information").is_some() {
        return Ok(());
    }

    const INFORMATION_WINDOW_WIDTH: f64 = 420.0;
    WebviewWindowBuilder::new(
        app,
        "information",
        WebviewUrl::App("index.html?secflowWindow=information".into()),
    )
    .title("信息咨询")
    .inner_size(INFORMATION_WINDOW_WIDTH, 620.0)
    .min_inner_size(INFORMATION_WINDOW_WIDTH, 560.0)
    .max_inner_size(INFORMATION_WINDOW_WIDTH, 700.0)
    .decorations(false)
    .transparent(true)
    .shadow(false)
    .resizable(false)
    .skip_taskbar(true)
    .always_on_top(true)
    .visible(false)
    .build()?;

    Ok(())
}

fn toggle_information_window(app: &AppHandle, anchor: Option<Rect>) {
    let Some(window) = app.get_webview_window("information") else {
        return;
    };

    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }

    let anchor = anchor.or_else(|| {
        app.tray_by_id("secflow-information")
            .and_then(|tray| tray.rect().ok().flatten())
    });
    if let Some(rect) = anchor {
        let _ = position_information_window(&window, rect);
    } else {
        let _ = window.center();
    }
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit("secflow:information-opened", ());
}

fn open_settings(app: &AppHandle) {
    show_main_window(app);
    let _ = app.emit("secflow:open-settings", ());
}

fn show_main_window(app: &AppHandle) {
    let window = match app.get_webview_window("main") {
        Some(window) => window,
        None => match create_main_window(app) {
            Ok(window) => window,
            Err(_) => return,
        },
    };

    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

fn create_main_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("安全智脑")
        .inner_size(1280.0, 820.0)
        .min_inner_size(960.0, 640.0)
        .decorations(true);
    #[cfg(target_os = "macos")]
    let builder = builder
        .hidden_title(true)
        .title_bar_style(TitleBarStyle::Overlay);
    builder.center().build()
}

fn position_information_window(window: &WebviewWindow, anchor: Rect) -> tauri::Result<()> {
    let scale_factor = window.scale_factor()?;
    let anchor_position = anchor.position.to_physical::<f64>(scale_factor);
    let anchor_size = anchor.size.to_physical::<f64>(scale_factor);
    let anchor_center_x = anchor_position.x + anchor_size.width / 2.0;
    let anchor_bottom_y = anchor_position.y + anchor_size.height;
    let size = window.outer_size()?;
    let monitor = window
        .monitor_from_point(anchor_center_x, anchor_bottom_y - 1.0)?
        .or(window.current_monitor()?);
    let position = if let Some(monitor) = monitor {
        let monitor_position = monitor.position();
        let monitor_size = monitor.size();
        information_window_origin(
            anchor_center_x,
            anchor_bottom_y,
            size,
            *monitor_position,
            *monitor_size,
        )
    } else {
        PhysicalPosition::new(
            (anchor_center_x - size.width as f64 / 2.0).round() as i32,
            anchor_bottom_y.round() as i32,
        )
    };

    window.set_position(position)?;
    Ok(())
}

fn information_window_origin(
    anchor_center_x: f64,
    anchor_bottom_y: f64,
    window_size: PhysicalSize<u32>,
    monitor_position: PhysicalPosition<i32>,
    monitor_size: PhysicalSize<u32>,
) -> PhysicalPosition<i32> {
    let desired_x = (anchor_center_x - window_size.width as f64 / 2.0).round() as i32;
    let desired_y = anchor_bottom_y.round() as i32;
    let max_x = monitor_position.x + monitor_size.width as i32 - window_size.width as i32;
    let max_y = monitor_position.y + monitor_size.height as i32 - window_size.height as i32;
    PhysicalPosition::new(
        desired_x.clamp(monitor_position.x, max_x.max(monitor_position.x)),
        desired_y.clamp(monitor_position.y, max_y.max(monitor_position.y)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn information_window_is_centered_below_the_status_item() {
        let origin = information_window_origin(
            1040.0,
            48.0,
            PhysicalSize::new(840, 1240),
            PhysicalPosition::new(0, 0),
            PhysicalSize::new(3024, 1964),
        );

        assert_eq!(origin, PhysicalPosition::new(620, 48));
    }

    #[test]
    fn information_window_stays_inside_the_status_item_monitor() {
        let left = information_window_origin(
            -1510.0,
            48.0,
            PhysicalSize::new(840, 1240),
            PhysicalPosition::new(-1512, 0),
            PhysicalSize::new(1512, 1964),
        );
        let right = information_window_origin(
            3010.0,
            48.0,
            PhysicalSize::new(840, 1240),
            PhysicalPosition::new(0, 0),
            PhysicalSize::new(3024, 1964),
        );

        assert_eq!(left.x, -1512);
        assert_eq!(right.x, 2184);
    }
}

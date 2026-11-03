pub mod account;
pub mod camera;
pub mod commands;
pub mod import;
pub mod merge;
pub mod migration;
pub mod qr;
pub mod theme;
pub mod totp;
pub mod vault;

use commands::AppState;
use notify::RecommendedWatcher;
use std::time::Duration;
use tauri::{Emitter, Manager};

const AUTO_LOCK_AFTER: Duration = Duration::from_secs(300);
const AUTO_LOCK_CHECK_EVERY: Duration = Duration::from_secs(5);

/// Keeps the theme watcher alive for the app lifetime.
struct ThemeWatcher {
    _watcher: Option<RecommendedWatcher>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState::new(dir.join("vault.json")));

            let handle = app.handle().clone();
            let watcher = theme::watch(move |palette| {
                let _ = handle.emit("theme", palette);
            });
            app.manage(ThemeWatcher { _watcher: watcher });

            let handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(AUTO_LOCK_CHECK_EVERY);
                    let state = handle.state::<AppState>();
                    let idle = state.last_activity.lock().unwrap().elapsed();
                    let unlocked = state.vault.lock().unwrap().is_some();
                    if unlocked && idle > AUTO_LOCK_AFTER {
                        commands::lock(&state);
                        let _ = handle.emit("locked", ());
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::activity,
            commands::codes,
            commands::copy_code,
            commands::get_theme,
            commands::import_image,
            commands::camera_list,
            commands::camera_start,
            commands::camera_stop,
            commands::import_finish,
            commands::import_cancel,
            commands::account_add_manual,
            commands::account_rename,
            commands::account_delete,
            commands::vault_change_password,
            commands::vault_reset,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

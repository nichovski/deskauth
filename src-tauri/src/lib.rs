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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

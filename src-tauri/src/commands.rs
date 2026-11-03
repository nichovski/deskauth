use crate::account::{Account, Algorithm};
use crate::camera::{self, CameraHandle, CameraInfo, Frame};
use crate::import::{ImportProgress, ImportSession};
use crate::merge::{self, MergeResult};
use crate::qr;
use crate::theme::{self, Palette};
use crate::totp;
use crate::vault::{self, Vault};
use base64::Engine;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct AppState {
    pub vault: Mutex<Option<Vault>>,
    pub vault_path: PathBuf,
    pub last_activity: Mutex<Instant>,
    /// One clipboard for the app lifetime: on Wayland the content can vanish when it is dropped.
    /// None when no clipboard is available (e.g. no display server).
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
    pub import: Mutex<ImportSession>,
    pub camera: Mutex<Option<CameraHandle>>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        AppState {
            vault: Mutex::new(None),
            vault_path,
            last_activity: Mutex::new(Instant::now()),
            clipboard: Mutex::new(arboard::Clipboard::new().ok()),
            import: Mutex::new(ImportSession::default()),
            camera: Mutex::new(None),
        }
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }
}

#[derive(Serialize, Debug, PartialEq)]
pub struct CodeView {
    id: String,
    issuer: String,
    name: String,
    code: String,
    remaining: u64,
    period: u64,
}

fn code_views(accounts: &[Account], now: u64) -> Vec<CodeView> {
    let mut sorted: Vec<&Account> = accounts.iter().collect();
    sorted.sort_by_cached_key(|a| (a.issuer.to_lowercase(), a.name.to_lowercase()));
    sorted
        .into_iter()
        .map(|a| CodeView {
            id: a.id.clone(),
            issuer: a.issuer.clone(),
            name: a.name.clone(),
            code: totp::code(a, now),
            remaining: totp::remaining_seconds(a.period, now),
            period: a.period,
        })
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const LOCKED: &str = "Vault is locked";

#[tauri::command]
pub fn vault_status(state: State<AppState>) -> Result<String, String> {
    let status = if state.vault.lock().unwrap().is_some() {
        "unlocked"
    } else if vault::exists(&state.vault_path) {
        "locked"
    } else {
        "none"
    };
    Ok(status.into())
}

// Async so the Argon2 key derivation runs off the main thread.
#[tauri::command]
pub async fn vault_create(password: String, state: State<'_, AppState>) -> Result<(), String> {
    if vault::exists(&state.vault_path) {
        return Err("A vault already exists".into());
    }
    let v = vault::create(&state.vault_path, &password).map_err(|e| e.to_string())?;
    *state.vault.lock().unwrap() = Some(v);
    state.touch();
    Ok(())
}

#[tauri::command]
pub async fn vault_unlock(password: String, state: State<'_, AppState>) -> Result<(), String> {
    let v = vault::unlock(&state.vault_path, &password).map_err(|e| e.to_string())?;
    *state.vault.lock().unwrap() = Some(v);
    state.touch();
    Ok(())
}

/// Locks the vault, stops any camera scan and forgets a half-done import.
pub fn lock(state: &AppState) {
    *state.vault.lock().unwrap() = None;
    stop_camera(state);
    state.import.lock().unwrap().take();
}

/// The handle is taken out before it is dropped, so no lock is held while the camera thread joins.
fn stop_camera(state: &AppState) {
    let handle = state.camera.lock().unwrap().take();
    drop(handle);
}

#[tauri::command]
pub fn vault_lock(state: State<AppState>) -> Result<(), String> {
    lock(&state);
    Ok(())
}

#[tauri::command]
pub fn activity(state: State<AppState>) -> Result<(), String> {
    state.touch();
    Ok(())
}

/// Polled every second by the UI, so it does not count as activity.
#[tauri::command]
pub fn codes(state: State<AppState>) -> Result<Vec<CodeView>, String> {
    let guard = state.vault.lock().unwrap();
    let v = guard.as_ref().ok_or(LOCKED)?;
    Ok(code_views(&v.accounts, unix_now()))
}

#[tauri::command]
pub fn copy_code(id: String, app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let code = {
        let guard = state.vault.lock().unwrap();
        let v = guard.as_ref().ok_or(LOCKED)?;
        let account = v
            .accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or("Account not found")?;
        totp::code(account, unix_now())
    };
    state.touch();
    {
        let mut clip = state.clipboard.lock().unwrap();
        let clip = clip.as_mut().ok_or("Clipboard not available")?;
        clip.set_text(code.clone()).map_err(|e| e.to_string())?;
    }
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
        let state = app.state::<AppState>();
        let mut clip = state.clipboard.lock().unwrap();
        if let Some(clip) = clip.as_mut()
            && clip.get_text().is_ok_and(|t| t == code)
        {
            let _ = clip.clear();
        }
    });
    Ok(())
}

#[tauri::command]
pub fn get_theme() -> Result<Palette, String> {
    Ok(theme::current_palette())
}

const NOT_SUPPORTED: &str = "Not a supported QR code";

/// Feeds every decoded QR string into the session. Err only when none was accepted.
fn add_decoded(decoded: &[String], session: &mut ImportSession) -> Result<ImportProgress, String> {
    let accepted = decoded.iter().filter(|uri| session.add_uri(uri).is_ok()).count();
    if accepted == 0 {
        return Err(NOT_SUPPORTED.into());
    }
    Ok(session.progress())
}

fn import_bytes(bytes: &[u8], session: &mut ImportSession) -> Result<ImportProgress, String> {
    add_decoded(&qr::decode_image_bytes(bytes)?, session)
}

/// Saves the vault; on failure the accounts go back to how they were before.
fn save_or_revert(vault: &mut Vault, before: usize) -> Result<(), String> {
    vault.save().map_err(|e| {
        vault.accounts.truncate(before);
        e.to_string()
    })
}

/// Merges into the vault and saves. On a failed save the vault is left as it was.
fn finish_into(vault: &mut Vault, accounts: Vec<Account>, skipped_unsupported: usize) -> Result<MergeResult, String> {
    let before = vault.accounts.len();
    let mut result = merge::merge(&mut vault.accounts, accounts);
    result.skipped_unsupported = skipped_unsupported;
    if result.added > 0 {
        save_or_revert(vault, before)?;
    }
    Ok(result)
}

fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
    match s {
        "SHA1" => Ok(Algorithm::Sha1),
        "SHA256" => Ok(Algorithm::Sha256),
        "SHA512" => Ok(Algorithm::Sha512),
        _ => Err("algorithm must be SHA1, SHA256 or SHA512".into()),
    }
}

fn add_manual(vault: &mut Vault, issuer: &str, name: &str, secret: &str, algorithm: &str, digits: u32, period: u64) -> Result<(), String> {
    let account = Account::new(issuer, name, secret, parse_algorithm(algorithm)?, digits, period)?;
    let before = vault.accounts.len();
    vault.accounts.push(account);
    save_or_revert(vault, before)
}

fn ensure_unlocked(state: &AppState) -> Result<(), String> {
    if state.vault.lock().unwrap().is_none() {
        return Err(LOCKED.into());
    }
    Ok(())
}

// Async so decoding a large image runs off the main thread.
#[tauri::command]
pub async fn import_image(bytes: Vec<u8>, state: State<'_, AppState>) -> Result<ImportProgress, String> {
    ensure_unlocked(&state)?;
    state.touch();
    import_bytes(&bytes, &mut state.import.lock().unwrap())
}

#[tauri::command]
pub async fn camera_list() -> Result<Vec<CameraInfo>, String> {
    camera::list_cameras()
}

/// Payload of the "camera-frame" event. Carries no secrets: only the preview and progress counts.
#[derive(Serialize, Clone)]
struct CameraFrame {
    preview: String,
    progress: ImportProgress,
    error: Option<String>,
}

fn camera_frame(session: &mut ImportSession, frame: Result<Frame, String>) -> CameraFrame {
    let frame = match frame {
        Ok(f) => f,
        Err(e) => return CameraFrame { preview: String::new(), progress: session.progress(), error: Some(e) },
    };
    let current = session.progress();
    // Once complete, later frames of the same QR are ignored until the UI finishes the import.
    let done = current.complete && current.accounts > 0;
    let (progress, error) = if done || frame.decoded.is_empty() {
        (current, None)
    } else {
        match add_decoded(&frame.decoded, session) {
            Ok(p) => (p, None),
            Err(e) => (current, Some(e)),
        }
    };
    let jpeg = base64::engine::general_purpose::STANDARD.encode(&frame.preview_jpeg);
    CameraFrame { preview: format!("data:image/jpeg;base64,{jpeg}"), progress, error }
}

#[tauri::command]
pub async fn camera_start(index: u32, app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    ensure_unlocked(&state)?;
    stop_camera(&state);
    let emitter = app.clone();
    let handle = camera::start(index, move |frame| {
        let payload = camera_frame(&mut emitter.state::<AppState>().import.lock().unwrap(), frame);
        let _ = emitter.emit("camera-frame", payload);
    })?;
    let old = state.camera.lock().unwrap().replace(handle);
    drop(old);
    state.touch();
    Ok(())
}

#[tauri::command]
pub async fn camera_stop(state: State<'_, AppState>) -> Result<(), String> {
    stop_camera(&state);
    Ok(())
}

#[tauri::command]
pub async fn import_finish(state: State<'_, AppState>) -> Result<MergeResult, String> {
    stop_camera(&state);
    let (accounts, skipped_unsupported) = state.import.lock().unwrap().take();
    let result = {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        finish_into(v, accounts, skipped_unsupported)?
    };
    state.touch();
    Ok(result)
}

#[tauri::command]
pub async fn import_cancel(state: State<'_, AppState>) -> Result<(), String> {
    stop_camera(&state);
    state.import.lock().unwrap().take();
    Ok(())
}

#[tauri::command]
pub fn account_add_manual(
    issuer: String,
    name: String,
    secret: String,
    algorithm: String,
    digits: u32,
    period: u64,
    state: State<AppState>,
) -> Result<(), String> {
    {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        add_manual(v, &issuer, &name, &secret, &algorithm, digits, period)?;
    }
    state.touch();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Algorithm;
    use image::{ImageFormat, Luma};
    use std::io::Cursor;

    const OTPAUTH: &str = "otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test";

    fn qr_png(data: &str) -> Vec<u8> {
        let img = qrcode::QrCode::new(data.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .module_dimensions(4, 4)
            .build();
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let v = vault::create(&dir.path().join("vault.json"), "pw").unwrap();
        (dir, v)
    }

    #[test]
    fn image_import_then_reimport_adds_once() {
        let (dir, mut v) = temp_vault();
        let png = qr_png(OTPAUTH);

        let mut session = ImportSession::default();
        let p = import_bytes(&png, &mut session).unwrap();
        assert!(p.complete);
        assert_eq!(p.accounts, 1);
        let (accounts, unsupported) = session.take();
        let r = finish_into(&mut v, accounts, unsupported).unwrap();
        assert_eq!(r, MergeResult { added: 1, skipped_duplicates: 0, skipped_unsupported: 0 });

        import_bytes(&png, &mut session).unwrap();
        let (accounts, unsupported) = session.take();
        let r = finish_into(&mut v, accounts, unsupported).unwrap();
        assert_eq!(r, MergeResult { added: 0, skipped_duplicates: 1, skipped_unsupported: 0 });

        // Saved to disk: a fresh unlock sees the one account.
        let reopened = vault::unlock(&dir.path().join("vault.json"), "pw").unwrap();
        assert_eq!(reopened.accounts.len(), 1);
        assert_eq!((reopened.accounts[0].issuer.as_str(), reopened.accounts[0].name.as_str()), ("Test", "me"));
    }

    #[test]
    fn image_without_qr_errors() {
        let blank = image::GrayImage::from_pixel(100, 100, Luma([255u8]));
        let mut buf = Cursor::new(Vec::new());
        blank.write_to(&mut buf, ImageFormat::Png).unwrap();
        let mut session = ImportSession::default();
        assert_eq!(import_bytes(&buf.into_inner(), &mut session), Err("No QR code found in image".into()));
    }

    #[test]
    fn image_with_foreign_qr_is_not_supported() {
        let mut session = ImportSession::default();
        assert_eq!(import_bytes(&qr_png("https://example.com"), &mut session), Err(NOT_SUPPORTED.into()));
        assert_eq!(session.progress().accounts, 0);
    }

    #[test]
    fn decoded_mix_accepts_the_supported_ones() {
        let mut session = ImportSession::default();
        let p = add_decoded(&["hello".into(), OTPAUTH.into()], &mut session).unwrap();
        assert_eq!(p.accounts, 1);
    }

    fn frame(decoded: &[&str]) -> Result<Frame, String> {
        Ok(Frame { preview_jpeg: vec![1, 2], decoded: decoded.iter().map(|s| s.to_string()).collect() })
    }

    #[test]
    fn camera_frames_add_a_qr_once() {
        let mut session = ImportSession::default();
        let f = camera_frame(&mut session, frame(&[]));
        assert_eq!((f.preview.as_str(), f.progress.accounts, f.error), ("data:image/jpeg;base64,AQI=", 0, None));
        let f = camera_frame(&mut session, frame(&[OTPAUTH]));
        assert!(f.progress.complete);
        assert_eq!(f.progress.accounts, 1);
        // The same QR stays in view for the next frames.
        let f = camera_frame(&mut session, frame(&[OTPAUTH]));
        assert_eq!(f.progress.accounts, 1);
        assert_eq!(session.take().0.len(), 1);
    }

    #[test]
    fn camera_frame_errors() {
        let mut session = ImportSession::default();
        let f = camera_frame(&mut session, frame(&["https://example.com"]));
        assert_eq!(f.error.as_deref(), Some(NOT_SUPPORTED));
        let f = camera_frame(&mut session, Err(camera::NOT_AVAILABLE.into()));
        assert_eq!((f.preview.as_str(), f.error.as_deref()), ("", Some("Camera not available")));
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(parse_algorithm("SHA1"), Ok(Algorithm::Sha1));
        assert_eq!(parse_algorithm("SHA256"), Ok(Algorithm::Sha256));
        assert_eq!(parse_algorithm("SHA512"), Ok(Algorithm::Sha512));
        assert!(parse_algorithm("MD5").is_err());
    }

    #[test]
    fn manual_add_validates_and_saves() {
        let (dir, mut v) = temp_vault();
        assert!(add_manual(&mut v, "Acme", "me", "not base32!", "SHA1", 6, 30).is_err());
        assert!(add_manual(&mut v, "Acme", "me", "JBSWY3DPEHPK3PXP", "SHA1", 7, 30).is_err());
        assert!(v.accounts.is_empty());
        add_manual(&mut v, "Acme", "me", "jbsw y3dp ehpk 3pxp", "SHA256", 8, 60).unwrap();
        let reopened = vault::unlock(&dir.path().join("vault.json"), "pw").unwrap();
        let a = &reopened.accounts[0];
        assert_eq!((a.issuer.as_str(), a.secret.as_str(), a.algorithm, a.digits, a.period), ("Acme", "JBSWY3DPEHPK3PXP", Algorithm::Sha256, 8, 60));
    }

    fn acc(id: &str, issuer: &str, name: &str) -> Account {
        Account {
            id: id.into(),
            issuer: issuer.into(),
            name: name.into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: Algorithm::Sha1,
            digits: 8,
            period: 30,
        }
    }

    #[test]
    fn views_sorted_by_issuer_then_name_case_insensitive() {
        let accounts = vec![
            acc("1", "github", "zed"),
            acc("2", "Amazon", "b"),
            acc("3", "GitHub", "alice"),
            acc("4", "amazon", "A"),
        ];
        let ids: Vec<String> = code_views(&accounts, 59).into_iter().map(|v| v.id).collect();
        assert_eq!(ids, ["4", "2", "3", "1"]);
    }

    #[test]
    fn view_has_code_and_remaining() {
        // RFC 6238 SHA1 vector: T=59 -> 94287082.
        let views = code_views(&[acc("1", "x", "y")], 59);
        assert_eq!(views[0].code, "94287082");
        assert_eq!(views[0].remaining, 1);
        assert_eq!(views[0].period, 30);
    }
}

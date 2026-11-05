use crate::account::{Account, Algorithm};
use crate::camera::{self, CameraHandle, CameraInfo, Frame};
use crate::import::{ImportProgress, ImportSession};
use crate::merge::{self, MergeResult};
use crate::qr;
use crate::theme::{self, Palette};
use crate::totp;
use crate::unlock::{self, Fingerprint, HmacKey};
use crate::unlock_commands::{self, blocking, UnlockMethods};
use crate::vault::{self, Mode, Vault};
use base64::Engine;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct AppState {
    pub vault: Mutex<Option<Vault>>,
    pub vault_path: PathBuf,
    pub last_activity: Mutex<(Instant, SystemTime)>,
    /// One clipboard for the app lifetime: on Wayland the content can vanish when it is dropped.
    /// None when no clipboard is available (e.g. no display server).
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
    pub import: Mutex<ImportSession>,
    pub camera: Mutex<Option<CameraHandle>>,
    pub hmac_key: Arc<dyn HmacKey>,
    pub fingerprint: Arc<dyn Fingerprint>,
    /// Held by every command that may write the vault file (unlock can upgrade v1), so two of
    /// them never race on it. Taken before `vault`, never the other way round. Reads such as
    /// the 1 s `codes` poll do not take it.
    pub ops: Mutex<()>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        Self::with_devices(vault_path, Arc::from(unlock::platform_hmac_key()), Arc::from(unlock::platform_fingerprint()))
    }

    pub fn with_devices(vault_path: PathBuf, hmac_key: Arc<dyn HmacKey>, fingerprint: Arc<dyn Fingerprint>) -> Self {
        AppState {
            vault: Mutex::new(None),
            vault_path,
            last_activity: Mutex::new((Instant::now(), SystemTime::now())),
            clipboard: Mutex::new(arboard::Clipboard::new().ok()),
            import: Mutex::new(ImportSession::default()),
            camera: Mutex::new(None),
            hmac_key,
            fingerprint,
            ops: Mutex::new(()),
        }
    }

    pub(crate) fn touch(&self) {
        *self.last_activity.lock().unwrap() = (Instant::now(), SystemTime::now());
    }

    /// Instant stops while the system sleeps, so the wall clock is checked as well.
    pub fn idle_expired(&self, limit: Duration) -> bool {
        let (instant, wall) = *self.last_activity.lock().unwrap();
        idle_expired(instant.elapsed(), SystemTime::now().duration_since(wall).ok(), limit)
    }
}

/// True when either clock says the idle limit has passed. A wall clock that went backwards (None) counts as 0.
fn idle_expired(instant_elapsed: Duration, wall_elapsed: Option<Duration>, limit: Duration) -> bool {
    instant_elapsed > limit || wall_elapsed.unwrap_or_default() > limit
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

pub(crate) const LOCKED: &str = "Vault is locked";
const BUSY: &str = "Another vault change is in progress. Try again.";

/// Takes the file-writer lock without waiting: a YubiKey touch can hold it for 30 s, and sync
/// commands run on the main thread. Counts as activity, so auto-lock does not end a long
/// operation the user just started.
pub(crate) fn begin(state: &AppState) -> Result<MutexGuard<'_, ()>, String> {
    state.touch();
    state.ops.try_lock().map_err(|_| BUSY.to_string())
}

const NOT_FOUND: &str = "Account not found";

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
    let _ops = begin(&state)?;
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
    // Unlocking a v1 file rewrites it as v2.
    let _ops = begin(&state)?;
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

/// Copies text and asks clipboard managers to keep it out of their history.
fn set_text_private(clip: &mut arboard::Clipboard, text: String) -> Result<(), arboard::Error> {
    #[cfg(windows)]
    use arboard::SetExtWindows as _;
    #[cfg(target_os = "macos")]
    use arboard::SetExtApple as _;
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))))]
    use arboard::SetExtLinux as _;
    clip.set().exclude_from_history().text(text)
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
            .ok_or(NOT_FOUND)?;
        totp::code(account, unix_now())
    };
    state.touch();
    {
        let mut clip = state.clipboard.lock().unwrap();
        let clip = clip.as_mut().ok_or("Clipboard not available")?;
        set_text_private(clip, code.clone()).map_err(|e| e.to_string())?;
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
    let _ops = begin(&state)?;
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
    let _ops = begin(&state)?;
    {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        add_manual(v, &issuer, &name, &secret, &algorithm, digits, period)?;
    }
    state.touch();
    Ok(())
}

fn rename_account(accounts: &mut [Account], id: &str, issuer: &str, name: &str) -> Result<(), String> {
    let (issuer, name) = (issuer.trim(), name.trim());
    if issuer.is_empty() && name.is_empty() {
        return Err("Issuer or name is required".into());
    }
    let account = accounts.iter_mut().find(|a| a.id == id).ok_or(NOT_FOUND)?;
    account.issuer = issuer.into();
    account.name = name.into();
    Ok(())
}

/// Renames and saves. On a failed save the old names come back.
fn rename_and_save(vault: &mut Vault, id: &str, issuer: &str, name: &str) -> Result<(), String> {
    let old = vault
        .accounts
        .iter()
        .find(|a| a.id == id)
        .map(|a| (a.issuer.clone(), a.name.clone()));
    rename_account(&mut vault.accounts, id, issuer, name)?;
    vault.save().map_err(|e| {
        if let Some((issuer, name)) = old
            && let Some(a) = vault.accounts.iter_mut().find(|a| a.id == id)
        {
            a.issuer = issuer;
            a.name = name;
        }
        e.to_string()
    })
}

/// Removes and saves. On a failed save the account goes back to its place; on success it is dropped (and wiped).
fn delete_and_save(vault: &mut Vault, id: &str) -> Result<(), String> {
    let index = vault.accounts.iter().position(|a| a.id == id).ok_or(NOT_FOUND)?;
    let removed = vault.accounts.remove(index);
    match vault.save() {
        Ok(()) => Ok(()),
        Err(e) => {
            vault.accounts.insert(index, removed);
            Err(e.to_string())
        }
    }
}

/// Deletes the vault file. Only allowed while the vault is locked.
fn reset_file(unlocked: bool, path: &Path) -> Result<(), String> {
    if unlocked {
        return Err("Lock the vault first".into());
    }
    vault::delete(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn account_rename(id: String, issuer: String, name: String, state: State<AppState>) -> Result<(), String> {
    let _ops = begin(&state)?;
    {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        rename_and_save(v, &id, &issuer, &name)?;
    }
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn account_delete(id: String, state: State<AppState>) -> Result<(), String> {
    let _ops = begin(&state)?;
    {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        delete_and_save(v, &id)?;
    }
    state.touch();
    Ok(())
}

// In password_yubikey mode it asks for a touch of every registered key.
#[tauri::command]
pub async fn vault_change_password(current: String, new_password: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state, emit| unlock_commands::change_password(state, &current, &new_password, emit)).await
}

#[tauri::command]
pub async fn unlock_methods(app: AppHandle) -> Result<UnlockMethods, String> {
    blocking(app, |state, _| unlock_commands::unlock_methods(state)).await
}

#[tauri::command]
pub async fn vault_unlock_yubikey(app: AppHandle) -> Result<(), String> {
    blocking(app, unlock_commands::unlock_yubikey).await
}

#[tauri::command]
pub async fn vault_unlock_fingerprint(app: AppHandle) -> Result<(), String> {
    blocking(app, |state, _| unlock_commands::unlock_fingerprint(state)).await
}

#[tauri::command]
pub async fn vault_unlock_two_factor(password: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state, emit| unlock_commands::unlock_two_factor(state, &password, emit)).await
}

#[tauri::command]
pub async fn yubikey_add(name: String, password: Option<String>, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state, emit| unlock_commands::yubikey_add(state, &name, password.as_deref(), emit)).await
}

#[tauri::command]
pub async fn yubikey_remove(id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state, _| unlock_commands::yubikey_remove(state, &id)).await
}

#[tauri::command]
pub async fn fingerprint_enable(app: AppHandle) -> Result<(), String> {
    blocking(app, |state, _| unlock_commands::fingerprint_enable(state)).await
}

#[tauri::command]
pub async fn fingerprint_disable(app: AppHandle) -> Result<(), String> {
    blocking(app, |state, _| unlock_commands::fingerprint_disable(state)).await
}

#[tauri::command]
pub async fn set_mode(mode: Mode, password: Option<String>, name: Option<String>, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state, emit| {
        unlock_commands::set_mode(state, mode, password.as_deref(), name.as_deref(), emit)
    })
    .await
}

#[tauri::command]
pub fn vault_reset(state: State<AppState>) -> Result<(), String> {
    let _ops = begin(&state)?;
    // The guard is held so the vault cannot be unlocked between the check and the delete.
    let guard = state.vault.lock().unwrap();
    reset_file(guard.is_some(), &state.vault_path)
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
    fn idle_expires_on_either_clock() {
        let limit = Duration::from_secs(300);
        let secs = Duration::from_secs;
        assert!(!idle_expired(secs(10), Some(secs(10)), limit));
        assert!(!idle_expired(secs(300), Some(secs(300)), limit));
        assert!(idle_expired(secs(301), Some(secs(10)), limit));
        // Suspend: Instant barely moved, the wall clock jumped.
        assert!(idle_expired(secs(10), Some(secs(3600)), limit));
        // Wall clock went backwards: treated as 0.
        assert!(!idle_expired(secs(10), None, limit));
        assert!(idle_expired(secs(301), None, limit));
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

    #[test]
    fn rename_trims_and_validates() {
        let mut accounts = vec![acc("1", "Old", "old")];
        rename_account(&mut accounts, "1", "  New ", " me ").unwrap();
        assert_eq!((accounts[0].issuer.as_str(), accounts[0].name.as_str()), ("New", "me"));
        assert_eq!(rename_account(&mut accounts, "1", " ", ""), Err("Issuer or name is required".into()));
        assert_eq!(rename_account(&mut accounts, "9", "a", "b"), Err("Account not found".into()));
        rename_account(&mut accounts, "1", "", "only name").unwrap();
        assert_eq!(accounts[0].issuer, "");
    }

    #[test]
    fn rename_and_delete_persist() {
        let (dir, mut v) = temp_vault();
        v.accounts.push(acc("1", "A", "a"));
        v.accounts.push(acc("2", "B", "b"));
        rename_and_save(&mut v, "1", "Renamed", "x").unwrap();
        assert_eq!(delete_and_save(&mut v, "9"), Err("Account not found".into()));
        delete_and_save(&mut v, "2").unwrap();
        let reopened = vault::unlock(&dir.path().join("vault.json"), "pw").unwrap();
        assert_eq!(reopened.accounts.len(), 1);
        assert_eq!((reopened.accounts[0].issuer.as_str(), reopened.accounts[0].name.as_str()), ("Renamed", "x"));
    }

    #[test]
    fn failed_save_reverts_rename_and_delete() {
        let (dir, mut v) = temp_vault();
        v.accounts.push(acc("1", "A", "a"));
        v.accounts.push(acc("2", "B", "b"));
        // A directory where the vault file goes makes the rename, so every save, fail.
        let path = dir.path().join("vault.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(rename_and_save(&mut v, "1", "Changed", "c").is_err());
        assert_eq!((v.accounts[0].issuer.as_str(), v.accounts[0].name.as_str()), ("A", "a"));
        assert!(delete_and_save(&mut v, "1").is_err());
        let ids: Vec<&str> = v.accounts.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["1", "2"]);
        assert_eq!(v.accounts[0].secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn damaged_vault_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        std::fs::write(&path, "hello").unwrap();
        let err = vault::unlock(&path, "pw").err().unwrap().to_string();
        assert!(err.starts_with("Vault file is damaged"), "{err}");
    }

    #[test]
    fn reset_only_when_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        std::fs::write(&path, "hello").unwrap();
        assert_eq!(reset_file(true, &path), Err("Lock the vault first".into()));
        assert!(path.exists());
        reset_file(false, &path).unwrap();
        assert!(!vault::exists(&path));
    }
}

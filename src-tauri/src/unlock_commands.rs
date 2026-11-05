//! Commands for YubiKey and fingerprint unlock. The logic lives in plain functions taking
//! `&AppState` and a `touch-needed` callback, so tests run them with fake devices; the Tauri
//! commands only run them off the async runtime and emit the event.
//!
//! Every function that may write the file holds the file-writer lock (`commands::begin`) for its
//! whole run, but takes the vault mutex only for quick reads and the final change, never during a
//! device call or an Argon2 run. Unlocking only reads the file (except the v1 upgrade), so unlock
//! attempts run side by side: the first to finish wins, and it ends any fingerprint scan.

use crate::commands::{self, AppState, LOCKED};
use crate::unlock::{DeviceError, FingerStatus, OnStatus};
use std::sync::atomic::Ordering;
use crate::vault::{self, Mode, PasswordKek, Secret, TwoFactorKek, Vault, VaultError, VaultInfo, YubikeyInfo};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

/// Called with the key name (None when any registered key will do) before every touch.
pub type Emit<'a> = &'a dyn Fn(Option<&str>);

const PASSWORD_NEEDED: &str = "Type your password to continue";
const DEFAULT_KEY_NAME: &str = "YubiKey";

#[derive(Serialize, Debug, PartialEq)]
pub struct KeyView {
    id: String,
    name: String,
}

/// What the unlock screen and Settings need. Holds no secret, salt or credential id.
#[derive(Serialize, Debug, PartialEq)]
pub struct UnlockMethods {
    mode: Mode,
    yubikeys: Vec<KeyView>,
    fingerprint: bool,
    can_yubikey: bool,
    can_fingerprint: bool,
    /// The lock screen may look for a plugged-in key and ask for a touch by itself.
    auto_yubikey: bool,
    platform: &'static str,
}

/// A device that holds none of the allowed credentials is a key this vault does not know.
fn device_err(e: DeviceError) -> String {
    match e {
        DeviceError::NoCredential => VaultError::NotRegistered.to_string(),
        e => e.to_string(),
    }
}

fn vault_err(e: VaultError) -> String {
    e.to_string()
}

fn not_enabled(what: &str) -> String {
    format!("{what} is not enabled for this vault")
}

/// The unlock setup of the unlocked vault.
fn current_info(state: &AppState) -> Result<VaultInfo, String> {
    state.vault.lock().unwrap().as_ref().map(Vault::info).ok_or_else(|| LOCKED.into())
}

/// Applies one change to the unlocked vault (each change saves itself).
fn with_vault<T>(state: &AppState, change: impl FnOnce(&mut Vault) -> Result<T, VaultError>) -> Result<T, String> {
    let result = {
        let mut guard = state.vault.lock().unwrap();
        let v = guard.as_mut().ok_or(LOCKED)?;
        change(v).map_err(vault_err)?
    };
    state.touch();
    Ok(result)
}

/// Keeps the vault that is already unlocked, if any: a later attempt's copy is dropped.
fn set_unlocked(state: &AppState, v: Vault) {
    {
        let mut guard = state.vault.lock().unwrap();
        if guard.is_none() {
            *guard = Some(v);
        }
    }
    state.finger_cancel.store(true, Ordering::SeqCst);
    state.touch();
}

/// A device unlock that would only be dropped is not started.
fn already_unlocked(state: &AppState) -> Result<(), String> {
    if state.vault.lock().unwrap().is_some() {
        return Err(DeviceError::Cancelled.to_string());
    }
    Ok(())
}

/// An empty field means no PIN.
fn some_pin(pin: Option<&str>) -> Option<&str> {
    pin.filter(|p| !p.is_empty())
}

fn allowed(keys: &[YubikeyInfo]) -> Vec<(Vec<u8>, [u8; 32])> {
    keys.iter().map(|k| (k.credential_id.clone(), k.salt)).collect()
}

/// One touch of any registered key. Returns the credential that answered and its hmac output.
fn assert_any(state: &AppState, keys: &[YubikeyInfo], emit: Emit) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
    if keys.is_empty() {
        return Err("No YubiKey is registered for this vault".into());
    }
    emit(None);
    state.hmac_key.assert(&allowed(keys)).map_err(device_err)
}

/// Proves the password together with a registered key by opening the file; the copy is wiped.
fn verify_two_factor(state: &AppState, keys: &[YubikeyInfo], password: &str, emit: Emit) -> Result<(), String> {
    let (credential_id, hmac) = assert_any(state, keys, emit)?;
    let secret = Secret::PasswordYubikey { password, credential_id: &credential_id, hmac: &hmac };
    vault::unlock_with(&state.vault_path, secret).map_err(vault_err)?;
    Ok(())
}

/// Deletes the OS items of fingerprint slots that are gone. Failures leave only an unused item.
fn disable_fingerprints(state: &AppState, ids: &[String]) {
    for id in ids {
        let _ = state.fingerprint.disable(id);
    }
}

pub fn unlock_methods(state: &AppState) -> Result<UnlockMethods, String> {
    let unlocked = state.vault.lock().unwrap().as_ref().map(Vault::info);
    let info = match unlocked {
        Some(info) => info,
        None => vault::read_info(&state.vault_path).map_err(vault_err)?,
    };
    Ok(UnlockMethods {
        mode: info.mode,
        yubikeys: info.yubikeys.into_iter().map(|k| KeyView { id: k.id, name: k.name }).collect(),
        fingerprint: info.fingerprint.is_some(),
        can_yubikey: state.hmac_key.available(),
        can_fingerprint: state.fingerprint.available(),
        auto_yubikey: cfg!(any(target_os = "linux", target_os = "macos")),
        platform: state.fingerprint.platform(),
    })
}

pub fn unlock_yubikey(state: &AppState, emit: Emit) -> Result<(), String> {
    already_unlocked(state)?;
    let info = vault::read_info(&state.vault_path).map_err(vault_err)?;
    if info.mode != Mode::Any {
        return Err(not_enabled("YubiKey-only unlock"));
    }
    let (credential_id, hmac) = assert_any(state, &info.yubikeys, emit)?;
    let v = vault::unlock_with(&state.vault_path, Secret::Yubikey { credential_id: &credential_id, hmac: &hmac })
        .map_err(vault_err)?;
    set_unlocked(state, v);
    Ok(())
}

/// Only a v1 file is written (upgraded to v2), so only then is the file-writer lock taken.
pub fn unlock_password(state: &AppState, password: &str) -> Result<(), String> {
    let v1 = vault::read_info(&state.vault_path).is_ok_and(|i| i.version == 1);
    let _ops = if v1 { Some(commands::begin(state)?) } else { None };
    let v = vault::unlock(&state.vault_path, password).map_err(vault_err)?;
    set_unlocked(state, v);
    Ok(())
}

/// Ends with "Cancelled." when `unlock_cancel` runs or the vault is unlocked another way.
pub fn unlock_fingerprint(state: &AppState, on_status: OnStatus) -> Result<(), String> {
    let info = vault::read_info(&state.vault_path).map_err(vault_err)?;
    let id = match (info.mode, info.fingerprint) {
        (Mode::Any, Some(id)) => id,
        _ => return Err(not_enabled("Fingerprint unlock")),
    };
    state.finger_cancel.store(false, Ordering::SeqCst);
    // Checked after clearing the flag: an unlock that lands before this check is seen here,
    // one after it sets the flag again and stops the scan.
    already_unlocked(state)?;
    let secret = state.fingerprint.unlock(&id, &state.finger_cancel, on_status).map_err(device_err)?;
    let v = vault::unlock_with(&state.vault_path, Secret::Fingerprint { secret: &secret }).map_err(vault_err)?;
    set_unlocked(state, v);
    Ok(())
}

pub fn unlock_two_factor(state: &AppState, password: &str, emit: Emit) -> Result<(), String> {
    let info = vault::read_info(&state.vault_path).map_err(vault_err)?;
    if info.mode != Mode::PasswordYubikey {
        return Err(not_enabled("Password and YubiKey unlock"));
    }
    let (credential_id, hmac) = assert_any(state, &info.yubikeys, emit)?;
    let secret = Secret::PasswordYubikey { password, credential_id: &credential_id, hmac: &hmac };
    let v = vault::unlock_with(&state.vault_path, secret).map_err(vault_err)?;
    set_unlocked(state, v);
    Ok(())
}

/// The password is needed in both modes. In `any` mode it must open the file, and the new key
/// then unlocks on its own. In `password_yubikey` mode it must open the file with a registered
/// key, and the new key's slot is made from it. A key that is already registered refuses.
pub fn yubikey_add(state: &AppState, name: &str, password: Option<&str>, pin: Option<&str>, emit: Emit) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    let info = current_info(state)?;
    let pin = some_pin(pin);
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the YubiKey a name".into());
    }
    let registered: Vec<Vec<u8>> = info.yubikeys.iter().map(|k| k.credential_id.clone()).collect();
    match info.mode {
        Mode::Any => {
            let password = password.ok_or(PASSWORD_NEEDED)?;
            // Verify against the file; the copy is dropped (and wiped) right away.
            vault::unlock(&state.vault_path, password).map_err(vault_err)?;
            emit(Some(name));
            let e = state.hmac_key.enroll(&registered, pin).map_err(device_err)?;
            with_vault(state, |v| v.add_yubikey(name, &e.credential_id, e.salt, &e.hmac))?;
        }
        Mode::PasswordYubikey => {
            let password = password.ok_or(PASSWORD_NEEDED)?;
            verify_two_factor(state, &info.yubikeys, password, emit)?;
            emit(Some(name));
            let e = state.hmac_key.enroll(&registered, pin).map_err(device_err)?;
            let kek = TwoFactorKek::derive(password, &e.hmac).map_err(vault_err)?;
            with_vault(state, |v| v.add_yubikey_two_factor(name, &e.credential_id, e.salt, kek))?;
        }
        Mode::Password => return Err(not_enabled("YubiKey unlock")),
    }
    Ok(())
}

pub fn yubikey_remove(state: &AppState, id: &str) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    if !current_info(state)?.yubikeys.iter().any(|k| k.id == id) {
        return Err(VaultError::NotRegistered.to_string());
    }
    with_vault(state, |v| v.remove_slot(id))
}

/// Replaces any existing fingerprint slot. The OS item of the slot that did not end up in the
/// file (the new one on a failed save, else the old one) is deleted.
pub fn fingerprint_enable(state: &AppState, on_status: OnStatus) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    let info = current_info(state)?;
    if info.mode != Mode::Any {
        return Err(not_enabled("Fingerprint unlock"));
    }
    let id = vault::new_slot_id();
    let secret = state.fingerprint.enable(&id, on_status).map_err(device_err)?;
    let platform = state.fingerprint.platform();
    if let Err(e) = with_vault(state, |v| v.set_fingerprint(&id, platform, &secret)) {
        disable_fingerprints(state, &[id]);
        return Err(e);
    }
    disable_fingerprints(state, info.fingerprint.as_slice());
    Ok(())
}

pub fn fingerprint_disable(state: &AppState) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    let id = current_info(state)?.fingerprint.ok_or("Fingerprint unlock is not set up")?;
    with_vault(state, |v| v.remove_slot(&id))?;
    disable_fingerprints(state, &[id]);
    Ok(())
}

/// Rebuilds the slots for `mode`. Entering `password_yubikey` needs the password (checked on
/// the file) and a new key; leaving it needs the password and a touch of a registered key, and
/// that password becomes the password-only one.
pub fn set_mode(
    state: &AppState,
    mode: Mode,
    password: Option<&str>,
    name: Option<&str>,
    pin: Option<&str>,
    emit: Emit,
) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    let info = current_info(state)?;
    let pin = some_pin(pin);
    match (info.mode, mode) {
        (Mode::Password, Mode::Any) => with_vault(state, |v| v.to_any_mode(None)),
        (Mode::Any, Mode::Password) => {
            let removed = with_vault(state, |v| v.to_password_mode())?;
            disable_fingerprints(state, &removed);
            Ok(())
        }
        (Mode::Password | Mode::Any, Mode::PasswordYubikey) => {
            let password = password.ok_or(PASSWORD_NEEDED)?;
            vault::unlock(&state.vault_path, password).map_err(vault_err)?;
            let name = name.map(str::trim).filter(|n| !n.is_empty()).unwrap_or(DEFAULT_KEY_NAME);
            emit(Some(name));
            // Every existing slot is replaced, so an already registered key may be used again.
            let e = state.hmac_key.enroll(&[], pin).map_err(device_err)?;
            let kek = TwoFactorKek::derive(password, &e.hmac).map_err(vault_err)?;
            let removed = with_vault(state, |v| v.to_two_factor_mode(name, &e.credential_id, e.salt, kek))?;
            disable_fingerprints(state, &removed);
            Ok(())
        }
        (Mode::PasswordYubikey, to @ (Mode::Password | Mode::Any)) => {
            let password = password.ok_or(PASSWORD_NEEDED)?;
            verify_two_factor(state, &info.yubikeys, password, emit)?;
            let kek = PasswordKek::derive(password).map_err(vault_err)?;
            with_vault(state, |v| v.to_any_mode(Some(kek)))?;
            if to == Mode::Password {
                with_vault(state, |v| v.to_password_mode())?;
            }
            Ok(())
        }
        _ => Err("The vault already uses this mode".into()),
    }
}

/// In `password_yubikey` mode each registered key is touched in turn; each answer must open the
/// file with the current password before any slot is rewrapped under the new one.
pub fn change_password(state: &AppState, current: &str, new_password: &str, emit: Emit) -> Result<(), String> {
    let _ops = commands::begin(state)?;
    let info = current_info(state)?;
    if info.mode != Mode::PasswordYubikey {
        // Verify against the file; the copy is dropped (and wiped) right away.
        vault::unlock(&state.vault_path, current).map_err(vault_err)?;
        let kek = PasswordKek::derive(new_password).map_err(vault_err)?;
        return with_vault(state, |v| v.set_password(kek));
    }
    let mut keks = Vec::with_capacity(info.yubikeys.len());
    for key in &info.yubikeys {
        emit(Some(&key.name));
        let (credential_id, hmac) =
            state.hmac_key.assert(&[(key.credential_id.clone(), key.salt)]).map_err(device_err)?;
        if credential_id != key.credential_id {
            return Err(VaultError::NotRegistered.to_string());
        }
        let secret = Secret::PasswordYubikey { password: current, credential_id: &credential_id, hmac: &hmac };
        vault::unlock_with(&state.vault_path, secret).map_err(vault_err)?;
        keks.push((key.id.clone(), TwoFactorKek::derive(new_password, &hmac).map_err(vault_err)?));
    }
    with_vault(state, |v| v.change_password_two_factor(keks))
}

pub fn unlock_cancel(state: &AppState) {
    state.finger_cancel.store(true, Ordering::SeqCst);
}

pub fn yubikey_present(state: &AppState) -> bool {
    state.hmac_key.present()
}

/// Payload of the "touch-needed" event.
#[derive(Serialize, Clone)]
struct TouchNeeded {
    name: Option<String>,
}

/// Payload of the "finger-status" event.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub(crate) struct FingerEvent {
    state: &'static str,
    message: Option<&'static str>,
}

fn finger_event(s: FingerStatus) -> FingerEvent {
    match s {
        FingerStatus::Scanning => FingerEvent { state: "scanning", message: None },
        FingerStatus::Retry(m) => FingerEvent { state: "retry", message: Some(m) },
        FingerStatus::NoMatch => FingerEvent { state: "no_match", message: None },
    }
}

pub(crate) fn emit_finger(app: &AppHandle, s: FingerStatus) {
    let _ = app.emit("finger-status", finger_event(s));
}

/// Runs `work` on a blocking thread (device calls and Argon2 can take seconds) and emits
/// "touch-needed" for it.
pub(crate) async fn blocking<T: Send + 'static>(
    app: AppHandle,
    work: impl FnOnce(&AppState, Emit) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let emit = |name: Option<&str>| {
            let _ = app.emit("touch-needed", TouchNeeded { name: name.map(str::to_owned) });
        };
        work(&app.state::<AppState>(), &emit)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Algorithm};
    use crate::commands;
    use crate::unlock::fake::{FakeFinger, FakeKey};
    use crate::unlock::{DeviceError, Enrolled, HmacKey};
    use crate::vault::{self, Secret};
    use std::cell::Cell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock, Weak};
    use zeroize::Zeroizing;

    const NOT_REGISTERED: &str = "This YubiKey is not registered for this vault";

    fn account() -> Account {
        Account::new("Acme", "me", "JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30).unwrap()
    }

    fn labels(accounts: &[Account]) -> Vec<String> {
        accounts.iter().map(|a| format!("{}/{}", a.issuer, a.name)).collect()
    }

    struct Setup {
        _dir: tempfile::TempDir,
        path: PathBuf,
        state: AppState,
        key: Arc<FakeKey>,
        finger: Arc<FakeFinger>,
    }

    /// An unlocked vault in mode `password` (password "pw", one account) with fake devices.
    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut v = vault::create(&path, "pw").unwrap();
        v.accounts.push(account());
        v.save().unwrap();
        let key = Arc::new(FakeKey::default());
        let finger = Arc::new(FakeFinger::default());
        let state = AppState::with_devices(path.clone(), key.clone(), finger.clone());
        *state.vault.lock().unwrap() = Some(v);
        Setup { _dir: dir, path, state, key, finger }
    }

    fn no_emit(_: Option<&str>) {}

    fn quiet(_: FingerStatus) {}

    fn unlocked(state: &AppState) -> bool {
        state.vault.lock().unwrap().is_some()
    }

    fn mode(state: &AppState) -> Mode {
        unlock_methods(state).unwrap().mode
    }

    /// Unlocks the file with one specific registered key (the fake answers for the first match).
    fn unlock_with_key(path: &Path, key: &FakeKey, index: usize, password: &str) -> Result<vault::Vault, vault::VaultError> {
        let info = vault::read_info(path).unwrap();
        let k = &info.yubikeys[index];
        let (cred, hmac) = key.assert(&[(k.credential_id.clone(), k.salt)]).unwrap();
        vault::unlock_with(path, Secret::PasswordYubikey { password, credential_id: &cred, hmac: &hmac })
    }

    #[test]
    fn add_key_then_unlock_with_it() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        let names = std::cell::RefCell::new(Vec::new());
        yubikey_add(&s.state, "Blue", Some("pw"), None, &|n| names.borrow_mut().push(n.map(str::to_owned))).unwrap();
        assert_eq!(*names.borrow(), [Some("Blue".to_string())]);
        commands::lock(&s.state);
        unlock_yubikey(&s.state, &no_emit).unwrap();
        assert_eq!(labels(&s.state.vault.lock().unwrap().as_ref().unwrap().accounts), ["Acme/me"]);
        // The password still works in mode any.
        assert!(vault::unlock(&s.path, "pw").is_ok());
    }

    #[test]
    fn unknown_key_is_not_registered() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        commands::lock(&s.state);
        // A different key is plugged in.
        s.key.creds.lock().unwrap().clear();
        s.key.enroll(&[], None).unwrap();
        assert_eq!(unlock_yubikey(&s.state, &no_emit), Err(NOT_REGISTERED.into()));
        assert!(!unlocked(&s.state));
    }

    #[test]
    fn remove_key() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        let id = unlock_methods(&s.state).unwrap().yubikeys[0].id.clone();
        assert_eq!(yubikey_remove(&s.state, "nope"), Err(NOT_REGISTERED.into()));
        yubikey_remove(&s.state, &id).unwrap();
        assert!(unlock_methods(&s.state).unwrap().yubikeys.is_empty());
        commands::lock(&s.state);
        assert!(unlock_yubikey(&s.state, &no_emit).is_err());
        assert!(!unlocked(&s.state));
    }

    #[test]
    fn fingerprint_enable_then_unlock() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        assert!(unlock_methods(&s.state).unwrap().fingerprint);
        commands::lock(&s.state);
        unlock_fingerprint(&s.state, &quiet).unwrap();
        assert!(unlocked(&s.state));
    }

    #[test]
    fn fingerprint_with_cleared_store_is_not_set_up() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        s.finger.store.lock().unwrap().clear();
        assert_eq!(unlock_fingerprint(&s.state, &quiet), Err(DeviceError::NotSetUp.to_string()));
        assert!(!unlocked(&s.state));
        assert!(vault::unlock(&s.path, "pw").is_ok());
        // The dead slot can still be removed.
        *s.state.vault.lock().unwrap() = Some(vault::unlock(&s.path, "pw").unwrap());
        fingerprint_disable(&s.state).unwrap();
        assert!(!unlock_methods(&s.state).unwrap().fingerprint);
    }

    #[test]
    fn enabling_again_disables_the_old_os_item() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        let store = s.finger.store.lock().unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.contains_key(&vault::read_info(&s.path).unwrap().fingerprint.unwrap()));
    }

    #[test]
    fn failed_save_disables_the_new_os_item() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        // A directory where the vault file goes makes every save fail.
        std::fs::remove_file(&s.path).unwrap();
        std::fs::create_dir(&s.path).unwrap();
        assert!(fingerprint_enable(&s.state, &quiet).is_err());
        assert!(s.finger.store.lock().unwrap().is_empty());
    }

    #[test]
    fn leaving_any_disables_fingerprint_os_items() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        set_mode(&s.state, Mode::Password, None, None, None, &no_emit).unwrap();
        assert!(s.finger.store.lock().unwrap().is_empty());
        assert_eq!(mode(&s.state), Mode::Password);
    }

    #[test]
    fn two_factor_then_back_to_any() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        // The password is checked against the file before any touch.
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(set_mode(&s.state, Mode::PasswordYubikey, Some("bad"), Some("Blue"), None, &no_emit), Err("Wrong password".into()));
        assert!(s.key.creds.lock().unwrap().is_empty());
        assert_eq!(std::fs::read(&s.path).unwrap(), before);

        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        assert!(s.finger.store.lock().unwrap().is_empty());
        assert!(matches!(vault::unlock(&s.path, "pw"), Err(vault::VaultError::NotAllowed(_))));
        commands::lock(&s.state);
        assert_eq!(unlock_yubikey(&s.state, &no_emit), Err("YubiKey-only unlock is not enabled for this vault".into()));
        assert_eq!(unlock_two_factor(&s.state, "bad", &no_emit), Err("Wrong password".into()));
        unlock_two_factor(&s.state, "pw", &no_emit).unwrap();
        assert_eq!(labels(&s.state.vault.lock().unwrap().as_ref().unwrap().accounts), ["Acme/me"]);

        // Leaving needs the password and a touch; a wrong password writes nothing.
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(set_mode(&s.state, Mode::Any, Some("bad"), None, None, &no_emit), Err("Wrong password".into()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        assert_eq!(set_mode(&s.state, Mode::Any, None, None, None, &no_emit), Err(PASSWORD_NEEDED.into()));
        set_mode(&s.state, Mode::Any, Some("pw"), None, None, &no_emit).unwrap();
        assert_eq!(mode(&s.state), Mode::Any);
        assert_eq!(labels(&vault::unlock(&s.path, "pw").unwrap().accounts), ["Acme/me"]);
    }

    #[test]
    fn two_factor_to_password() {
        let s = setup();
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), None, None, &no_emit).unwrap();
        assert_eq!(unlock_methods(&s.state).unwrap().yubikeys[0].name, "YubiKey");
        set_mode(&s.state, Mode::Password, Some("pw"), None, None, &no_emit).unwrap();
        assert_eq!(mode(&s.state), Mode::Password);
        assert!(vault::unlock(&s.path, "pw").is_ok());
    }

    #[test]
    fn add_second_key_in_two_factor_mode() {
        let s = setup();
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(yubikey_add(&s.state, "Red", None, None, &no_emit), Err(PASSWORD_NEEDED.into()));
        assert_eq!(yubikey_add(&s.state, "Red", Some("bad"), None, &no_emit), Err("Wrong password".into()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        // The backup key is plugged in next to Blue.
        *s.key.device.lock().unwrap() = 1;
        let count = Cell::new(0);
        yubikey_add(&s.state, "Red", Some("pw"), None, &|_| count.set(count.get() + 1)).unwrap();
        // One touch to prove the password with a registered key, one to enroll.
        assert_eq!(count.get(), 2);
        assert!(unlock_with_key(&s.path, &s.key, 1, "pw").is_ok());
        assert_eq!(unlock_methods(&s.state).unwrap().yubikeys.len(), 2);
    }

    #[test]
    fn add_in_any_mode_needs_the_password() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(yubikey_add(&s.state, "Blue", None, None, &no_emit), Err(PASSWORD_NEEDED.into()));
        assert_eq!(yubikey_add(&s.state, "Blue", Some("bad"), None, &no_emit), Err("Wrong password".into()));
        assert!(s.key.creds.lock().unwrap().is_empty(), "no touch before the password is checked");
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        assert_eq!(unlock_methods(&s.state).unwrap().yubikeys.len(), 1);
    }

    #[test]
    fn adding_the_same_key_again_fails() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(yubikey_add(&s.state, "Blue again", Some("pw"), None, &no_emit), Err(DeviceError::AlreadyRegistered.to_string()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        assert_eq!(unlock_methods(&s.state).unwrap().yubikeys.len(), 1);

        // Two-factor mode: Blue proves the password, then refuses to register twice.
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(yubikey_add(&s.state, "Blue again", Some("pw"), None, &no_emit), Err(DeviceError::AlreadyRegistered.to_string()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        assert_eq!(unlock_methods(&s.state).unwrap().yubikeys.len(), 1);
    }

    /// A key that answers with a credential and hmac this vault never saw.
    struct StrangerKey;

    impl HmacKey for StrangerKey {
        fn available(&self) -> bool {
            true
        }
        fn present(&self) -> bool {
            true
        }
        fn enroll(&self, _exclude: &[Vec<u8>], _pin: Option<&str>) -> Result<Enrolled, DeviceError> {
            Err(DeviceError::Other("not used".into()))
        }
        fn assert(&self, _allowed: &[(Vec<u8>, [u8; 32])]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
            Ok((b"stranger".to_vec(), Zeroizing::new([7u8; 32])))
        }
    }

    #[test]
    fn leaving_two_factor_with_a_wrong_key_writes_nothing() {
        let s = setup();
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();

        // An unregistered key is plugged in instead of Blue.
        let blue = std::mem::take(&mut *s.key.creds.lock().unwrap());
        s.key.enroll(&[], None).unwrap();
        for to in [Mode::Any, Mode::Password] {
            assert_eq!(set_mode(&s.state, to, Some("pw"), None, None, &no_emit), Err(NOT_REGISTERED.into()));
            assert_eq!(std::fs::read(&s.path).unwrap(), before);
            assert_eq!(mode(&s.state), Mode::PasswordYubikey);
        }

        // A key that answers with a credential the vault does not know.
        let stranger = AppState::with_devices(s.path.clone(), Arc::new(StrangerKey), s.finger.clone());
        *stranger.vault.lock().unwrap() = s.state.vault.lock().unwrap().take();
        assert!(set_mode(&stranger, Mode::Any, Some("pw"), None, None, &no_emit).is_err());
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        assert_eq!(mode(&stranger), Mode::PasswordYubikey);

        // The old mode still unlocks with the right key.
        *s.key.creds.lock().unwrap() = blue;
        commands::lock(&s.state);
        unlock_two_factor(&s.state, "pw", &no_emit).unwrap();
        assert_eq!(labels(&s.state.vault.lock().unwrap().as_ref().unwrap().accounts), ["Acme/me"]);
    }

    #[test]
    fn timeout_leaves_file_unchanged() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        *s.key.next.lock().unwrap() = Some(DeviceError::Timeout);
        assert_eq!(yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit), Err(DeviceError::Timeout.to_string()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        *s.key.next.lock().unwrap() = Some(DeviceError::Timeout);
        assert!(set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), None, None, &no_emit).is_err());
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
        assert_eq!(mode(&s.state), Mode::Any);
    }

    #[test]
    fn unlock_methods_while_locked_has_no_secrets() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        let m = unlock_methods(&s.state).unwrap();
        assert_eq!(m.mode, Mode::Any);
        assert_eq!(m.yubikeys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["Blue"]);
        assert!(m.fingerprint && m.can_yubikey && m.can_fingerprint);
        assert_eq!(m.platform, "fake");
        let json = serde_json::to_string(&m).unwrap();
        for word in ["salt", "credential_id", "wrapped"] {
            assert!(!json.contains(word), "{json}");
        }
    }

    #[test]
    fn change_password_two_factor_touches_each_key() {
        let s = setup();
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        *s.key.device.lock().unwrap() = 1;
        yubikey_add(&s.state, "Red", Some("pw"), None, &no_emit).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        assert_eq!(change_password(&s.state, "bad", "new", &no_emit), Err("Wrong password".into()));
        assert_eq!(std::fs::read(&s.path).unwrap(), before);

        let names = std::cell::RefCell::new(Vec::new());
        change_password(&s.state, "pw", "new", &|n| names.borrow_mut().push(n.map(str::to_owned))).unwrap();
        assert_eq!(*names.borrow(), [Some("Blue".to_string()), Some("Red".to_string())]);
        for i in 0..2 {
            assert!(unlock_with_key(&s.path, &s.key, i, "new").is_ok());
            assert!(unlock_with_key(&s.path, &s.key, i, "pw").is_err());
        }
    }

    #[test]
    fn change_password_in_password_mode() {
        let s = setup();
        assert_eq!(change_password(&s.state, "bad", "new", &no_emit), Err("Wrong password".into()));
        change_password(&s.state, "pw", "new", &no_emit).unwrap();
        assert!(vault::unlock(&s.path, "new").is_ok());
    }

    #[test]
    fn busy_while_another_change_runs() {
        let s = setup();
        let ops = commands::begin(&s.state).unwrap();
        assert_eq!(set_mode(&s.state, Mode::Any, None, None, None, &no_emit), Err("Another vault change is in progress. Try again.".into()));
        commands::lock(&s.state);
        assert!(unlock_two_factor(&s.state, "pw", &no_emit).is_err());
        drop(ops);
        assert!(commands::begin(&s.state).is_ok());
    }

    #[test]
    fn begin_counts_as_activity() {
        let s = setup();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        s.state.last_activity.lock().unwrap().1 = old;
        let limit = std::time::Duration::from_secs(300);
        assert!(s.state.idle_expired(limit));
        let _ops = commands::begin(&s.state).unwrap();
        assert!(!s.state.idle_expired(limit));
    }

    #[test]
    fn locked_vault_refuses_changes() {
        let s = setup();
        commands::lock(&s.state);
        assert_eq!(set_mode(&s.state, Mode::Any, None, None, None, &no_emit), Err(commands::LOCKED.into()));
        assert_eq!(fingerprint_enable(&s.state, &quiet), Err(commands::LOCKED.into()));
    }

    /// A key that records whether the vault mutex was free during each device call.
    #[derive(Default)]
    struct ProbeKey {
        inner: FakeKey,
        state: OnceLock<Weak<AppState>>,
        saw_vault_held: AtomicBool,
    }

    impl ProbeKey {
        fn check(&self) {
            let state = self.state.get().unwrap().upgrade().unwrap();
            if state.vault.try_lock().is_err() {
                self.saw_vault_held.store(true, Ordering::SeqCst);
            }
        }
    }

    impl HmacKey for ProbeKey {
        fn available(&self) -> bool {
            true
        }
        fn present(&self) -> bool {
            true
        }
        fn enroll(&self, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Enrolled, DeviceError> {
            self.check();
            self.inner.enroll(exclude, pin)
        }
        fn assert(&self, allowed: &[(Vec<u8>, [u8; 32])]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
            self.check();
            self.inner.assert(allowed)
        }
    }

    #[test]
    fn vault_mutex_is_free_during_device_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let v = vault::create(&path, "pw").unwrap();
        let key = Arc::new(ProbeKey::default());
        let state = Arc::new(AppState::with_devices(path, key.clone(), Arc::new(FakeFinger::default())));
        key.state.set(Arc::downgrade(&state)).unwrap();
        *state.vault.lock().unwrap() = Some(v);
        set_mode(&state, Mode::PasswordYubikey, Some("pw"), None, None, &no_emit).unwrap();
        *key.inner.device.lock().unwrap() = 1;
        yubikey_add(&state, "Red", Some("pw"), None, &no_emit).unwrap();
        change_password(&state, "pw", "new", &no_emit).unwrap();
        commands::lock(&state);
        unlock_two_factor(&state, "new", &no_emit).unwrap();
        assert!(!key.saw_vault_held.load(Ordering::SeqCst));
    }

    const BUSY: &str = "Another vault change is in progress. Try again.";
    const CANCELLED: &str = "Cancelled.";

    /// Mode `any` with a fingerprint set up, locked, and the fake scan waiting until cancelled.
    fn locked_with_blocking_finger() -> Setup {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        s.finger.block.store(true, Ordering::SeqCst);
        *s.finger.statuses.lock().unwrap() = vec![FingerStatus::Scanning];
        s
    }

    /// Runs a fingerprint unlock on another thread and returns once its scan is running.
    fn scan_in_background<'s>(
        scope: &'s std::thread::Scope<'s, '_>,
        state: &'s AppState,
    ) -> std::thread::ScopedJoinHandle<'s, Result<(), String>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = scope.spawn(move || unlock_fingerprint(state, &|_| tx.send(()).unwrap()));
        rx.recv().unwrap();
        handle
    }

    #[test]
    fn password_unlock_while_fingerprint_scans() {
        let s = locked_with_blocking_finger();
        std::thread::scope(|scope| {
            let scan = scan_in_background(scope, &s.state);
            unlock_password(&s.state, "pw").unwrap();
            assert_eq!(scan.join().unwrap(), Err(CANCELLED.into()));
        });
        assert_eq!(labels(&s.state.vault.lock().unwrap().as_ref().unwrap().accounts), ["Acme/me"]);
    }

    #[test]
    fn unlock_cancel_ends_a_running_scan() {
        let s = locked_with_blocking_finger();
        std::thread::scope(|scope| {
            let scan = scan_in_background(scope, &s.state);
            unlock_cancel(&s.state);
            assert_eq!(scan.join().unwrap(), Err(CANCELLED.into()));
        });
        assert!(!unlocked(&s.state));
        // The next scan starts fresh.
        s.finger.block.store(false, Ordering::SeqCst);
        unlock_fingerprint(&s.state, &quiet).unwrap();
        assert!(unlocked(&s.state));
    }

    #[test]
    fn attempt_finishing_after_unlock_keeps_the_first_vault() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        // The password wins while each device call runs; the vault is marked in memory only,
        // to tell it from a fresh copy.
        let unlock_first = || {
            commands::lock(&s.state);
            unlock_password(&s.state, "pw").unwrap();
            s.state.vault.lock().unwrap().as_mut().unwrap().accounts.clear();
        };
        *s.finger.statuses.lock().unwrap() = vec![FingerStatus::Scanning];
        unlock_fingerprint(&s.state, &|_| unlock_first()).unwrap();
        assert!(s.state.vault.lock().unwrap().as_ref().unwrap().accounts.is_empty());
        commands::lock(&s.state);
        unlock_yubikey(&s.state, &|_| unlock_first()).unwrap();
        assert!(s.state.vault.lock().unwrap().as_ref().unwrap().accounts.is_empty());
        unlock_password(&s.state, "pw").unwrap();
        assert!(s.state.vault.lock().unwrap().as_ref().unwrap().accounts.is_empty());
    }

    #[test]
    fn device_unlock_on_an_unlocked_vault_is_not_started() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        *s.finger.statuses.lock().unwrap() = vec![FingerStatus::Scanning];
        let scanned = Cell::new(false);
        assert_eq!(unlock_fingerprint(&s.state, &|_| scanned.set(true)), Err(CANCELLED.into()));
        assert!(!scanned.get());
        let touched = Cell::new(false);
        assert_eq!(unlock_yubikey(&s.state, &|_| touched.set(true)), Err(CANCELLED.into()));
        assert!(!touched.get());
    }

    #[test]
    fn unlocks_do_not_take_the_ops_lock() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        let _ops = commands::begin(&s.state).unwrap();
        commands::lock(&s.state);
        unlock_password(&s.state, "pw").unwrap();
        commands::lock(&s.state);
        unlock_fingerprint(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        unlock_yubikey(&s.state, &no_emit).unwrap();
        assert!(unlocked(&s.state));
    }

    #[test]
    fn v1_password_unlock_takes_the_ops_lock_and_upgrades() {
        let s = setup();
        commands::lock(&s.state);
        vault::tests::write_v1(&s.path, "pw", &[account()]);
        let ops = commands::begin(&s.state).unwrap();
        assert_eq!(unlock_password(&s.state, "pw"), Err(BUSY.into()));
        assert_eq!(vault::read_info(&s.path).unwrap().version, 1);
        drop(ops);
        unlock_password(&s.state, "pw").unwrap();
        assert_eq!(vault::read_info(&s.path).unwrap().version, 2);
        assert_eq!(labels(&s.state.vault.lock().unwrap().as_ref().unwrap().accounts), ["Acme/me"]);
    }

    #[test]
    fn enroll_gets_the_pin() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        yubikey_add(&s.state, "Blue", Some("pw"), Some("1234"), &no_emit).unwrap();
        *s.key.device.lock().unwrap() = 1;
        yubikey_add(&s.state, "Red", Some("pw"), Some(""), &no_emit).unwrap();
        set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Green"), Some("5678"), &no_emit).unwrap();
        assert_eq!(
            *s.key.pins.lock().unwrap(),
            [Some("1234".to_string()), None, Some("5678".to_string())]
        );
    }

    #[test]
    fn pin_errors_reach_the_ui_as_sentences() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        for (e, text) in [
            (DeviceError::PinRequired, "This YubiKey has a PIN. Enter it to register the key."),
            (DeviceError::WrongPin, "Wrong YubiKey PIN."),
        ] {
            *s.key.next.lock().unwrap() = Some(e);
            assert_eq!(yubikey_add(&s.state, "Blue", Some("pw"), None, &no_emit), Err(text.into()));
        }
        assert!(unlock_methods(&s.state).unwrap().yubikeys.is_empty());
    }

    #[test]
    fn finger_status_reported_in_order() {
        let s = setup();
        set_mode(&s.state, Mode::Any, None, None, None, &no_emit).unwrap();
        fingerprint_enable(&s.state, &quiet).unwrap();
        commands::lock(&s.state);
        let sequence = vec![FingerStatus::Scanning, FingerStatus::Retry("Swipe longer."), FingerStatus::Scanning];
        *s.finger.statuses.lock().unwrap() = sequence.clone();
        let seen = std::cell::RefCell::new(Vec::new());
        unlock_fingerprint(&s.state, &|st| seen.borrow_mut().push(st)).unwrap();
        assert_eq!(*seen.borrow(), sequence);
    }

    #[test]
    fn finger_event_payloads() {
        let json = |st| serde_json::to_value(finger_event(st)).unwrap();
        assert_eq!(json(FingerStatus::Scanning), serde_json::json!({ "state": "scanning", "message": null }));
        assert_eq!(
            json(FingerStatus::Retry("Center your finger.")),
            serde_json::json!({ "state": "retry", "message": "Center your finger." })
        );
        assert_eq!(json(FingerStatus::NoMatch), serde_json::json!({ "state": "no_match", "message": null }));
    }

    #[test]
    fn yubikey_presence_and_auto_flag() {
        let s = setup();
        assert!(yubikey_present(&s.state));
        assert_eq!(unlock_methods(&s.state).unwrap().auto_yubikey, cfg!(any(target_os = "linux", target_os = "macos")));
    }
}

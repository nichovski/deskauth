use crate::account::Account;
use crate::import::ImportSession;
use crate::theme::{self, Palette};
use crate::totp;
use crate::vault::{self, Vault};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};

const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct AppState {
    pub vault: Mutex<Option<Vault>>,
    pub vault_path: PathBuf,
    pub last_activity: Mutex<Instant>,
    /// One clipboard for the app lifetime: on Wayland the content can vanish when it is dropped.
    /// None when no clipboard is available (e.g. no display server).
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
    pub import: Mutex<ImportSession>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        AppState {
            vault: Mutex::new(None),
            vault_path,
            last_activity: Mutex::new(Instant::now()),
            clipboard: Mutex::new(arboard::Clipboard::new().ok()),
            import: Mutex::new(ImportSession::default()),
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

#[tauri::command]
pub fn vault_lock(state: State<AppState>) -> Result<(), String> {
    *state.vault.lock().unwrap() = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Algorithm;

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

//! Exports every account as one `otpauth://totp/` link per line, in plain text.

use crate::account::{Account, Algorithm};
use crate::commands::{self, AppState, LOCKED};
use crate::unlock_commands::{self, Emit};
use crate::vault;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Everything but the unreserved characters of RFC 3986.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// The label is always `issuer:name`, so an empty issuer gives `:name`. That keeps a ':' in the
/// name from being read as the issuer split and a name like ".." from being dropped as a dot segment.
pub fn uri(a: &Account) -> Zeroizing<String> {
    let issuer = utf8_percent_encode(&a.issuer, COMPONENT);
    let name = utf8_percent_encode(&a.name, COMPONENT);
    let algorithm = match a.algorithm {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    };
    let mut s = Zeroizing::new(format!("otpauth://totp/{issuer}:{name}?secret={}", a.secret));
    if !a.issuer.is_empty() {
        s.push_str(&format!("&issuer={issuer}"));
    }
    s.push_str(&format!("&algorithm={algorithm}&digits={}&period={}", a.digits, a.period));
    s
}

/// Checks the password (and a key touch in two-factor mode), asks `pick` for a path, and writes
/// the file. Returns None when `pick` returns None. A wrong password stops before `pick` runs.
pub fn export(
    state: &AppState,
    password: &str,
    emit: Emit,
    pick: impl FnOnce() -> Option<PathBuf>,
) -> Result<Option<PathBuf>, String> {
    let _ops = commands::begin(state)?;
    unlock_commands::verify_identity(state, password, emit)?;
    let Some(path) = pick() else { return Ok(None) };
    let text = {
        let guard = state.vault.lock().unwrap();
        let v = guard.as_ref().ok_or(LOCKED)?;
        let mut text = Zeroizing::new(String::new());
        for a in &v.accounts {
            text.push_str(&uri(a));
            text.push('\n');
        }
        text
    };
    vault::write_atomic(&path, text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration;
    use crate::unlock::fake::{FakeFinger, FakeKey};
    use crate::unlock::HmacKey;
    use crate::vault::Mode;
    use std::cell::Cell;
    use std::sync::Arc;

    fn no_emit(_: Option<&str>, _: u8, _: u8) {}

    fn acct(issuer: &str, name: &str, algorithm: Algorithm, digits: u32, period: u64) -> Account {
        Account::new(issuer, name, "JBSWY3DPEHPK3PXP", algorithm, digits, period).unwrap()
    }

    fn plain(issuer: &str, name: &str) -> Account {
        acct(issuer, name, Algorithm::Sha1, 6, 30)
    }

    struct Setup {
        dir: tempfile::TempDir,
        state: AppState,
        key: Arc<FakeKey>,
    }

    impl Setup {
        fn target(&self) -> PathBuf {
            self.dir.path().join("out.txt")
        }
    }

    /// An unlocked vault (password "pw", two accounts) in mode password, with fake devices.
    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut v = vault::create(&path, "pw").unwrap();
        v.accounts.push(plain("Acme", "me"));
        v.accounts.push(acct("AT&T", "me+tag@x.com", Algorithm::Sha256, 8, 60));
        v.save().unwrap();
        let key = Arc::new(FakeKey::default());
        let state = AppState::with_devices(path, key.clone(), Arc::new(FakeFinger::default()));
        *state.vault.lock().unwrap() = Some(v);
        Setup { dir, state, key }
    }

    fn lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path).unwrap().lines().map(str::to_owned).collect()
    }

    #[test]
    fn uri_round_trips_through_parse_uri() {
        let cases = [
            plain("My Co", "john smith"),
            plain("a:b", "n"),
            plain("i", "x:y"),
            plain("a:b", "c:d"),
            plain("A&B", "k=v"),
            plain("100%", "%41"),
            plain("a+b", "c+d"),
            plain("C#", "n#1"),
            plain("a/b", "/a/../b"),
            plain("why?", "q?x"),
            plain("Zürich", "büro"),
            plain("", "plain"),
            plain("", "x:y"),
            plain("", ".."),
            acct("S1", "n", Algorithm::Sha1, 6, 30),
            acct("S256", "n", Algorithm::Sha256, 6, 30),
            acct("S512", "n", Algorithm::Sha512, 6, 30),
            acct("D8", "n", Algorithm::Sha1, 8, 30),
            acct("P60", "n", Algorithm::Sha1, 6, 60),
        ];
        for a in cases {
            let text = uri(&a).to_string();
            let parsed = migration::parse_uri(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(parsed.accounts.len(), 1, "{text}");
            let b = &parsed.accounts[0];
            assert_eq!(
                (&b.issuer, &b.name, &b.secret, b.algorithm, b.digits, b.period),
                (&a.issuer, &a.name, &a.secret, a.algorithm, a.digits, a.period),
                "{text}"
            );
        }
    }

    #[test]
    fn uri_format_has_all_params() {
        let a = acct("AT&T", "me+tag@x.com", Algorithm::Sha256, 8, 60);
        assert_eq!(
            uri(&a).as_str(),
            "otpauth://totp/AT%26T:me%2Btag%40x.com?secret=JBSWY3DPEHPK3PXP&issuer=AT%26T&algorithm=SHA256&digits=8&period=60"
        );
        let b = plain("", "me");
        assert_eq!(uri(&b).as_str(), "otpauth://totp/:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30");
    }

    #[cfg(unix)]
    #[test]
    fn export_writes_private_file_and_replaces_old_one() {
        use std::os::unix::fs::PermissionsExt;
        let s = setup();
        let target = s.target();
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        let saved = export(&s.state, "pw", &no_emit, || Some(target.clone())).unwrap();
        assert_eq!(saved, Some(target.clone()));
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        let got = lines(&target);
        let n = s.state.vault.lock().unwrap().as_ref().unwrap().accounts.len();
        assert_eq!(got.len(), n);
        for l in &got {
            assert_eq!(migration::parse_uri(l).unwrap().accounts.len(), 1, "{l}");
        }
    }

    #[test]
    fn wrong_password_writes_nothing() {
        let s = setup();
        let target = s.target();
        let called = Cell::new(false);
        let r = export(&s.state, "bad", &no_emit, || {
            called.set(true);
            Some(target.clone())
        });
        assert_eq!(r, Err("Wrong password".into()));
        assert!(!called.get());
        assert!(!target.exists());
    }

    #[test]
    fn cancel_writes_nothing() {
        let s = setup();
        assert_eq!(export(&s.state, "pw", &no_emit, || None), Ok(None));
        assert!(!s.target().exists());
    }

    #[test]
    fn two_factor_needs_password_and_key() {
        let s = setup();
        unlock_commands::set_mode(&s.state, Mode::PasswordYubikey, Some("pw"), Some("Blue"), None, &no_emit).unwrap();
        let target = s.target();
        let pick = || Some(target.clone());

        assert!(export(&s.state, "bad", &no_emit, pick).is_err());
        assert!(!target.exists());

        // An unregistered key is plugged in instead of Blue.
        let blue = std::mem::take(&mut *s.key.creds.lock().unwrap());
        s.key.enroll(&[], None, &|_, _| {}).unwrap();
        assert!(export(&s.state, "pw", &no_emit, pick).is_err());
        assert!(!target.exists());

        // No key at all.
        s.key.creds.lock().unwrap().clear();
        assert!(export(&s.state, "pw", &no_emit, pick).is_err());
        assert!(!target.exists());

        *s.key.creds.lock().unwrap() = blue;
        let touches = Cell::new(0);
        export(&s.state, "pw", &|_, _, _| touches.set(touches.get() + 1), pick).unwrap();
        assert_eq!(touches.get(), 1);
        assert_eq!(lines(&target).len(), 2);
    }
}

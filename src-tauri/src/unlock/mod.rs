//! Hardware unlock devices (FIDO2 hmac-secret key, fingerprint) behind traits, so the vault
//! logic is tested with fakes and never needs real hardware.

use std::fmt;
use std::sync::atomic::AtomicBool;

use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fido_hid;
#[cfg(any(test, windows))]
mod fido_windows;
#[cfg(target_os = "linux")]
mod finger_linux;
#[cfg(any(test, target_os = "macos"))]
mod finger_macos;
#[cfg(any(test, windows))]
mod finger_windows;

#[derive(Debug, PartialEq)]
pub enum DeviceError {
    NoDevice,
    NoReader,
    /// The device answered, but holds none of the allowed credentials.
    NoCredential,
    /// The device already holds one of the excluded credentials.
    AlreadyRegistered,
    /// The key has a FIDO2 PIN and none was given.
    PinRequired,
    WrongPin,
    PinBlocked,
    /// A PIN was given for a key that has none.
    NoPin,
    Timeout,
    Cancelled,
    NotSetUp,
    Unsupported(String),
    Other(String),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceError::NoDevice => write!(f, "No YubiKey found. Plug it in and try again."),
            DeviceError::NoReader => write!(f, "No fingerprint reader found."),
            DeviceError::NoCredential => {
                write!(f, "This YubiKey is not registered for this vault.")
            }
            DeviceError::AlreadyRegistered => write!(f, "This YubiKey is already registered."),
            DeviceError::PinRequired => {
                write!(f, "This YubiKey has a PIN. Enter it to register the key.")
            }
            DeviceError::WrongPin => write!(f, "Wrong YubiKey PIN."),
            DeviceError::NoPin => {
                write!(f, "This YubiKey has no PIN. Leave the PIN field empty.")
            }
            DeviceError::PinBlocked => write!(
                f,
                "This YubiKey's PIN is blocked. Unplug it and try again, or reset it with the YubiKey Manager."
            ),
            DeviceError::Timeout => write!(f, "Timed out waiting. Try again."),
            DeviceError::Cancelled => write!(f, "Cancelled."),
            DeviceError::NotSetUp => write!(
                f,
                "Fingerprint unlock is no longer set up, use your password."
            ),
            DeviceError::Unsupported(m) => write!(f, "{m}"),
            DeviceError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for DeviceError {}

/// A freshly registered hmac-secret credential and the output for its salt.
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
    pub hmac: Zeroizing<[u8; 32]>,
}

/// What a running fingerprint scan reports along the way.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FingerStatus {
    Scanning,
    /// The reader wants another try; the sentence says how.
    Retry(&'static str),
    NoMatch,
}

pub type OnStatus<'a> = &'a dyn Fn(FingerStatus);

/// A FIDO2 key with the hmac-secret extension. Calls block until touch, so run them off the UI thread.
pub trait HmacKey: Send + Sync {
    fn available(&self) -> bool;
    /// True when a key is plugged in. Only lists devices: no command, no touch.
    fn present(&self) -> bool;
    /// Creates a credential, picks a random salt and runs one assertion for its hmac
    /// (two touches on HID devices). A key that holds one of `exclude` is refused with
    /// `AlreadyRegistered`. `pin` is used for creating the credential only; every assertion is
    /// touch only, so the hmac output stays the same on unlock.
    fn enroll(&self, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Enrolled, DeviceError>;
    /// Returns the credential id that answered and its hmac output for that credential's salt.
    fn assert(
        &self,
        allowed: &[(Vec<u8>, [u8; 32])],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError>;
}

/// An OS-guarded 32-byte secret per slot, released after a fingerprint check.
pub trait Fingerprint: Send + Sync {
    fn available(&self) -> bool;
    fn platform(&self) -> &'static str;
    fn enable(&self, slot_id: &str, on_status: OnStatus) -> Result<Zeroizing<[u8; 32]>, DeviceError>;
    /// Ends with `Cancelled` soon after `cancel` is set, where the platform allows it.
    fn unlock(
        &self,
        slot_id: &str,
        cancel: &AtomicBool,
        on_status: OnStatus,
    ) -> Result<Zeroizing<[u8; 32]>, DeviceError>;
    fn disable(&self, slot_id: &str) -> Result<(), DeviceError>;
}

/// Used on platforms without a device implementation.
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
struct Stub;

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
fn unsupported() -> DeviceError {
    DeviceError::Unsupported("Not supported on this system.".into())
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
impl HmacKey for Stub {
    fn available(&self) -> bool {
        false
    }
    fn present(&self) -> bool {
        false
    }
    fn enroll(&self, _exclude: &[Vec<u8>], _pin: Option<&str>) -> Result<Enrolled, DeviceError> {
        Err(unsupported())
    }
    fn assert(
        &self,
        _allowed: &[(Vec<u8>, [u8; 32])],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
        Err(unsupported())
    }
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
impl Fingerprint for Stub {
    fn available(&self) -> bool {
        false
    }
    fn platform(&self) -> &'static str {
        "none"
    }
    fn enable(&self, _slot_id: &str, _on_status: OnStatus) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        Err(unsupported())
    }
    fn unlock(
        &self,
        _slot_id: &str,
        _cancel: &AtomicBool,
        _on_status: OnStatus,
    ) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        Err(unsupported())
    }
    fn disable(&self, _slot_id: &str) -> Result<(), DeviceError> {
        Err(unsupported())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn platform_hmac_key() -> Box<dyn HmacKey> {
    Box::new(fido_hid::HidKey)
}

#[cfg(windows)]
pub fn platform_hmac_key() -> Box<dyn HmacKey> {
    Box::new(fido_windows::WebAuthnKey)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn platform_hmac_key() -> Box<dyn HmacKey> {
    Box::new(Stub)
}

#[cfg(target_os = "linux")]
pub fn platform_fingerprint() -> Box<dyn Fingerprint> {
    Box::new(finger_linux::FprintdFinger)
}

#[cfg(target_os = "macos")]
pub fn platform_fingerprint() -> Box<dyn Fingerprint> {
    Box::new(finger_macos::TouchIdFinger)
}

#[cfg(windows)]
pub fn platform_fingerprint() -> Box<dyn Fingerprint> {
    Box::new(finger_windows::HelloFinger)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn platform_fingerprint() -> Box<dyn Fingerprint> {
    Box::new(Stub)
}

#[cfg(test)]
pub mod fake {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    use super::{DeviceError, Enrolled, FingerStatus, Fingerprint, HmacKey, OnStatus};

    fn random<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        OsRng.fill_bytes(&mut b);
        b
    }

    fn take(next: &Mutex<Option<DeviceError>>) -> Result<(), DeviceError> {
        match next.lock().unwrap().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// (credential id, credential secret, device number).
    pub type FakeCred = (Vec<u8>, [u8; 32], usize);

    /// In-memory keys: hmac = HMAC-SHA256(credential secret, salt). `creds` holds the
    /// credentials of every plugged-in key; all of them answer assertions, and the key numbered
    /// `device` is the one that enrolls. `next` makes the next call fail once. `pins` records the
    /// PIN given to each `enroll`.
    #[derive(Default)]
    pub struct FakeKey {
        pub creds: Mutex<Vec<FakeCred>>,
        pub device: Mutex<usize>,
        pub next: Mutex<Option<DeviceError>>,
        pub pins: Mutex<Vec<Option<String>>>,
    }

    fn hmac_of(secret: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
        mac.update(salt);
        Zeroizing::new(mac.finalize().into_bytes().into())
    }

    impl HmacKey for FakeKey {
        fn available(&self) -> bool {
            true
        }

        fn present(&self) -> bool {
            true
        }

        fn enroll(&self, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Enrolled, DeviceError> {
            self.pins.lock().unwrap().push(pin.map(str::to_owned));
            take(&self.next)?;
            let device = *self.device.lock().unwrap();
            let mut creds = self.creds.lock().unwrap();
            if creds
                .iter()
                .any(|(id, _, d)| *d == device && exclude.contains(id))
            {
                return Err(DeviceError::AlreadyRegistered);
            }
            let credential_id = random::<16>().to_vec();
            let secret = random::<32>();
            let salt = random::<32>();
            let hmac = hmac_of(&secret, &salt);
            creds.push((credential_id.clone(), secret, device));
            Ok(Enrolled {
                credential_id,
                salt,
                hmac,
            })
        }

        fn assert(
            &self,
            allowed: &[(Vec<u8>, [u8; 32])],
        ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
            take(&self.next)?;
            let creds = self.creds.lock().unwrap();
            for (id, salt) in allowed {
                if let Some((_, secret, _)) = creds.iter().find(|(c, _, _)| c == id) {
                    return Ok((id.clone(), hmac_of(secret, salt)));
                }
            }
            Err(DeviceError::NoCredential)
        }
    }

    /// In-memory secret store standing in for the OS keyring or Windows Hello. `statuses` are
    /// reported by every scan; with `block` set, `unlock` then waits until cancelled.
    #[derive(Default)]
    pub struct FakeFinger {
        pub store: Mutex<HashMap<String, [u8; 32]>>,
        pub next: Mutex<Option<DeviceError>>,
        pub statuses: Mutex<Vec<FingerStatus>>,
        pub block: AtomicBool,
    }

    impl FakeFinger {
        fn scan(&self, on_status: OnStatus) -> Result<(), DeviceError> {
            for s in self.statuses.lock().unwrap().iter() {
                on_status(*s);
            }
            take(&self.next)
        }
    }

    /// Long enough for any test, short enough that a missed cancel fails instead of hanging.
    const BLOCK_LIMIT: Duration = Duration::from_secs(10);

    impl Fingerprint for FakeFinger {
        fn available(&self) -> bool {
            true
        }

        fn platform(&self) -> &'static str {
            "fake"
        }

        fn enable(&self, slot_id: &str, on_status: OnStatus) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            self.scan(on_status)?;
            let secret = random::<32>();
            self.store
                .lock()
                .unwrap()
                .insert(slot_id.to_string(), secret);
            Ok(Zeroizing::new(secret))
        }

        fn unlock(
            &self,
            slot_id: &str,
            cancel: &AtomicBool,
            on_status: OnStatus,
        ) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            self.scan(on_status)?;
            if self.block.load(Ordering::SeqCst) {
                let start = Instant::now();
                while !cancel.load(Ordering::SeqCst) {
                    if start.elapsed() > BLOCK_LIMIT {
                        return Err(DeviceError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                return Err(DeviceError::Cancelled);
            }
            match self.store.lock().unwrap().get(slot_id) {
                Some(s) => Ok(Zeroizing::new(*s)),
                None => Err(DeviceError::NotSetUp),
            }
        }

        fn disable(&self, slot_id: &str) -> Result<(), DeviceError> {
            take(&self.next)?;
            self.store.lock().unwrap().remove(slot_id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeFinger, FakeKey};
    use super::*;

    fn quiet(_: FingerStatus) {}

    fn never() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn fake_same_salt_same_hmac() {
        let key = FakeKey::default();
        let e = key.enroll(&[], None).unwrap();
        let (id, out) = key.assert(&[(e.credential_id.clone(), e.salt)]).unwrap();
        assert_eq!(id, e.credential_id);
        assert_eq!(*out, *e.hmac);
    }

    #[test]
    fn fake_other_salt_differs() {
        let key = FakeKey::default();
        let e = key.enroll(&[], None).unwrap();
        let (_, out) = key.assert(&[(e.credential_id.clone(), [9u8; 32])]).unwrap();
        assert_ne!(*out, *e.hmac);
        let other = FakeKey::default().enroll(&[], None).unwrap();
        assert_ne!(*other.hmac, *e.hmac);
    }

    #[test]
    fn fake_assert_unknown_allow_list_is_no_credential() {
        let key = FakeKey::default();
        key.enroll(&[], None).unwrap();
        let r = key.assert(&[(b"unknown".to_vec(), [1u8; 32])]);
        assert_eq!(r.err(), Some(DeviceError::NoCredential));
    }

    #[test]
    fn fake_queued_error_returned_once() {
        let key = FakeKey::default();
        *key.next.lock().unwrap() = Some(DeviceError::Timeout);
        assert_eq!(key.enroll(&[], None).err(), Some(DeviceError::Timeout));
        assert!(key.enroll(&[], None).is_ok());
    }

    #[test]
    fn fake_enroll_refuses_excluded_credential_on_the_same_device() {
        let key = FakeKey::default();
        let e = key.enroll(&[], None).unwrap();
        let exclude = [e.credential_id.clone()];
        assert_eq!(
            key.enroll(&exclude, None).err(),
            Some(DeviceError::AlreadyRegistered)
        );
        assert_eq!(
            DeviceError::AlreadyRegistered.to_string(),
            "This YubiKey is already registered."
        );
        *key.device.lock().unwrap() = 1;
        assert!(key.enroll(&exclude, None).is_ok());
    }

    #[test]
    fn fake_finger_disable_then_unlock_is_not_set_up() {
        let f = FakeFinger::default();
        let secret = f.enable("s1", &quiet).unwrap();
        assert_eq!(*f.unlock("s1", &never(), &quiet).unwrap(), *secret);
        f.disable("s1").unwrap();
        assert_eq!(f.unlock("s1", &never(), &quiet).err(), Some(DeviceError::NotSetUp));
    }

    #[test]
    fn pin_errors_are_plain_sentences() {
        assert_eq!(
            DeviceError::PinRequired.to_string(),
            "This YubiKey has a PIN. Enter it to register the key."
        );
        assert_eq!(DeviceError::WrongPin.to_string(), "Wrong YubiKey PIN.");
        assert_eq!(
            DeviceError::NoPin.to_string(),
            "This YubiKey has no PIN. Leave the PIN field empty."
        );
        assert_eq!(
            DeviceError::PinBlocked.to_string(),
            "This YubiKey's PIN is blocked. Unplug it and try again, or reset it with the YubiKey Manager."
        );
    }

    /// `src/api.ts` (CANCELLED, TIMED_OUT, NO_YUBIKEY_FOUND) matches on these exact texts; the
    /// lock screen breaks if they drift.
    #[test]
    fn texts_the_ui_matches_on() {
        assert_eq!(DeviceError::Timeout.to_string(), "Timed out waiting. Try again.");
        assert_eq!(DeviceError::Cancelled.to_string(), "Cancelled.");
        assert_eq!(
            DeviceError::NoDevice.to_string(),
            "No YubiKey found. Plug it in and try again."
        );
    }

    #[test]
    fn fake_finger_blocks_until_cancelled() {
        let f = FakeFinger::default();
        f.enable("s1", &quiet).unwrap();
        f.block.store(true, std::sync::atomic::Ordering::SeqCst);
        let cancel = AtomicBool::new(true);
        assert_eq!(f.unlock("s1", &cancel, &quiet).err(), Some(DeviceError::Cancelled));
    }

    #[test]
    fn other_displays_only_the_sentence() {
        assert_eq!(
            DeviceError::Other("Fingerprint did not match.".into()).to_string(),
            "Fingerprint did not match."
        );
    }

    #[test]
    fn stubs_are_unavailable_and_unsupported() {
        // The stub directly: the platform functions may return real devices.
        assert!(!HmacKey::available(&Stub));
        assert!(!Stub.present());
        assert!(matches!(Stub.enroll(&[], None), Err(DeviceError::Unsupported(_))));
        assert!(!Fingerprint::available(&Stub));
        assert!(matches!(
            Stub.unlock("s1", &never(), &quiet),
            Err(DeviceError::Unsupported(_))
        ));
    }
}

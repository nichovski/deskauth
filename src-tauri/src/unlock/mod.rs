//! Hardware unlock devices (FIDO2 hmac-secret key, fingerprint) behind traits, so the vault
//! logic is tested with fakes and never needs real hardware.

use std::fmt;

use zeroize::Zeroizing;

#[derive(Debug, PartialEq)]
pub enum DeviceError {
    NoDevice,
    NoReader,
    /// The device answered, but holds none of the allowed credentials.
    NoCredential,
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
            DeviceError::Timeout => write!(f, "Timed out waiting. Try again."),
            DeviceError::Cancelled => write!(f, "Cancelled."),
            DeviceError::NotSetUp => write!(
                f,
                "Fingerprint unlock is no longer set up, use your password."
            ),
            DeviceError::Unsupported(m) => write!(f, "{m}"),
            DeviceError::Other(m) => write!(f, "Device error: {m}"),
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

/// A FIDO2 key with the hmac-secret extension. Calls block until touch, so run them off the UI thread.
pub trait HmacKey: Send + Sync {
    fn available(&self) -> bool;
    /// Creates a credential, picks a random salt and runs one assertion for its hmac
    /// (two touches on HID devices).
    fn enroll(&self) -> Result<Enrolled, DeviceError>;
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
    fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError>;
    fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError>;
    fn disable(&self, slot_id: &str) -> Result<(), DeviceError>;
}

/// Used on platforms without a device implementation.
struct Stub;

fn unsupported() -> DeviceError {
    DeviceError::Unsupported("Not supported on this system.".into())
}

impl HmacKey for Stub {
    fn available(&self) -> bool {
        false
    }
    fn enroll(&self) -> Result<Enrolled, DeviceError> {
        Err(unsupported())
    }
    fn assert(
        &self,
        _allowed: &[(Vec<u8>, [u8; 32])],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
        Err(unsupported())
    }
}

impl Fingerprint for Stub {
    fn available(&self) -> bool {
        false
    }
    fn platform(&self) -> &'static str {
        "none"
    }
    fn enable(&self, _slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        Err(unsupported())
    }
    fn unlock(&self, _slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        Err(unsupported())
    }
    fn disable(&self, _slot_id: &str) -> Result<(), DeviceError> {
        Err(unsupported())
    }
}

pub fn platform_hmac_key() -> Box<dyn HmacKey> {
    Box::new(Stub)
}

pub fn platform_fingerprint() -> Box<dyn Fingerprint> {
    Box::new(Stub)
}

#[cfg(test)]
pub mod fake {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    use super::{DeviceError, Enrolled, Fingerprint, HmacKey};

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

    /// In-memory key: hmac = HMAC-SHA256(device secret, salt). `next` makes the next call fail once.
    #[derive(Default)]
    pub struct FakeKey {
        pub creds: Mutex<Vec<(Vec<u8>, [u8; 32])>>,
        pub next: Mutex<Option<DeviceError>>,
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

        fn enroll(&self) -> Result<Enrolled, DeviceError> {
            take(&self.next)?;
            let credential_id = random::<16>().to_vec();
            let secret = random::<32>();
            let salt = random::<32>();
            let hmac = hmac_of(&secret, &salt);
            self.creds
                .lock()
                .unwrap()
                .push((credential_id.clone(), secret));
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
                if let Some((_, secret)) = creds.iter().find(|(c, _)| c == id) {
                    return Ok((id.clone(), hmac_of(secret, salt)));
                }
            }
            Err(DeviceError::NoCredential)
        }
    }

    /// In-memory secret store standing in for the OS keyring or Windows Hello.
    #[derive(Default)]
    pub struct FakeFinger {
        pub store: Mutex<HashMap<String, [u8; 32]>>,
        pub next: Mutex<Option<DeviceError>>,
    }

    impl Fingerprint for FakeFinger {
        fn available(&self) -> bool {
            true
        }

        fn platform(&self) -> &'static str {
            "fake"
        }

        fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            take(&self.next)?;
            let secret = random::<32>();
            self.store
                .lock()
                .unwrap()
                .insert(slot_id.to_string(), secret);
            Ok(Zeroizing::new(secret))
        }

        fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            take(&self.next)?;
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

    #[test]
    fn fake_same_salt_same_hmac() {
        let key = FakeKey::default();
        let e = key.enroll().unwrap();
        let (id, out) = key.assert(&[(e.credential_id.clone(), e.salt)]).unwrap();
        assert_eq!(id, e.credential_id);
        assert_eq!(*out, *e.hmac);
    }

    #[test]
    fn fake_other_salt_differs() {
        let key = FakeKey::default();
        let e = key.enroll().unwrap();
        let (_, out) = key.assert(&[(e.credential_id.clone(), [9u8; 32])]).unwrap();
        assert_ne!(*out, *e.hmac);
        let other = FakeKey::default().enroll().unwrap();
        assert_ne!(*other.hmac, *e.hmac);
    }

    #[test]
    fn fake_assert_unknown_allow_list_is_no_credential() {
        let key = FakeKey::default();
        key.enroll().unwrap();
        let r = key.assert(&[(b"unknown".to_vec(), [1u8; 32])]);
        assert_eq!(r.err(), Some(DeviceError::NoCredential));
    }

    #[test]
    fn fake_queued_error_returned_once() {
        let key = FakeKey::default();
        *key.next.lock().unwrap() = Some(DeviceError::Timeout);
        assert_eq!(key.enroll().err(), Some(DeviceError::Timeout));
        assert!(key.enroll().is_ok());
    }

    #[test]
    fn fake_finger_disable_then_unlock_is_not_set_up() {
        let f = FakeFinger::default();
        let secret = f.enable("s1").unwrap();
        assert_eq!(*f.unlock("s1").unwrap(), *secret);
        f.disable("s1").unwrap();
        assert_eq!(f.unlock("s1").err(), Some(DeviceError::NotSetUp));
    }

    #[test]
    fn stubs_are_unavailable_and_unsupported() {
        assert!(!platform_hmac_key().available());
        assert!(matches!(
            platform_hmac_key().enroll(),
            Err(DeviceError::Unsupported(_))
        ));
        let f = platform_fingerprint();
        assert!(!f.available());
        assert!(matches!(f.unlock("s1"), Err(DeviceError::Unsupported(_))));
    }
}

//! Windows Hello: a per-slot `KeyCredentialManager` key signs a fixed challenge; the secret
//! is SHA-256 of the signature. Nothing secret is stored.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::DeviceError;

// `KeyCredentialStatus` values.
const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_FOUND: i32 = 2;
const STATUS_USER_CANCELED: i32 = 3;
const STATUS_USER_PREFERS_PASSWORD: i32 = 4;
const STATUS_CREDENTIAL_ALREADY_EXISTS: i32 = 5;
const STATUS_SECURITY_DEVICE_LOCKED: i32 = 6;

const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;
const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;
/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`.
const HRESULT_NOT_FOUND: i32 = 0x8007_0490_u32 as i32;

fn key_name(slot_id: &str) -> String {
    format!("deskauth-{slot_id}")
}

fn challenge(slot_id: &str) -> String {
    format!("deskauth v2 fingerprint:{slot_id}")
}

/// Maps a `KeyCredentialStatus` value.
fn hello_status(status: i32) -> Result<(), DeviceError> {
    let other = |m: &str| Err(DeviceError::Other(m.into()));
    match status {
        STATUS_SUCCESS => Ok(()),
        STATUS_NOT_FOUND => Err(DeviceError::NotSetUp),
        STATUS_USER_CANCELED | STATUS_USER_PREFERS_PASSWORD => Err(DeviceError::Cancelled),
        STATUS_SECURITY_DEVICE_LOCKED => {
            other("Windows Hello is locked. Sign in to Windows with your PIN and try again.")
        }
        STATUS_CREDENTIAL_ALREADY_EXISTS => {
            other("A Windows Hello key for Deskauth already exists.")
        }
        _ => other("Windows Hello reported an error."),
    }
}

/// A failed WinRT call, as a plain sentence with the raw code.
fn hello_error(code: i32) -> DeviceError {
    DeviceError::Other(format!("Windows Hello error: 0x{:08X}.", code as u32))
}

/// `DeleteAsync` errors that mean the key is already gone.
fn already_deleted(code: i32) -> bool {
    matches!(code, NTE_NOT_FOUND | NTE_BAD_KEYSET | HRESULT_NOT_FOUND)
}

fn secret_from_signature(signature: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&Sha256::digest(signature));
    secret
}

#[cfg(windows)]
pub use imp::HelloFinger;

#[cfg(windows)]
mod imp {
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::core::{Array, HSTRING};
    use zeroize::{Zeroize, Zeroizing};

    use super::{
        already_deleted, challenge, hello_error, hello_status, key_name, secret_from_signature,
    };
    use crate::unlock::{DeviceError, Fingerprint};

    pub struct HelloFinger;

    fn win_error(e: windows::core::Error) -> DeviceError {
        hello_error(e.code().0)
    }

    fn name(slot_id: &str) -> HSTRING {
        HSTRING::from(key_name(slot_id))
    }

    /// Asks Windows Hello to sign the slot's fixed challenge. RSA PKCS#1 v1.5 signatures are
    /// deterministic, so the same key always gives the same secret.
    fn sign(credential: &KeyCredential, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        let data = CryptographicBuffer::CreateFromByteArray(challenge(slot_id).as_bytes())
            .map_err(win_error)?;
        let result = credential
            .RequestSignAsync(&data)
            .and_then(|op| op.join())
            .map_err(win_error)?;
        hello_status(result.Status().map_err(win_error)?.0)?;
        let buffer = result.Result().map_err(win_error)?;
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buffer, &mut signature).map_err(win_error)?;
        let secret = secret_from_signature(&signature);
        signature.zeroize();
        Ok(secret)
    }

    impl Fingerprint for HelloFinger {
        fn available(&self) -> bool {
            KeyCredentialManager::IsSupportedAsync()
                .and_then(|op| op.join())
                .unwrap_or(false)
        }

        fn platform(&self) -> &'static str {
            "windows"
        }

        fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            let created = KeyCredentialManager::RequestCreateAsync(
                &name(slot_id),
                KeyCredentialCreationOption::ReplaceExisting,
            )
            .and_then(|op| op.join())
            .map_err(win_error)?;
            hello_status(created.Status().map_err(win_error)?.0)?;
            sign(&created.Credential().map_err(win_error)?, slot_id)
        }

        fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            let opened = KeyCredentialManager::OpenAsync(&name(slot_id))
                .and_then(|op| op.join())
                .map_err(win_error)?;
            hello_status(opened.Status().map_err(win_error)?.0)?;
            sign(&opened.Credential().map_err(win_error)?, slot_id)
        }

        fn disable(&self, slot_id: &str) -> Result<(), DeviceError> {
            match KeyCredentialManager::DeleteAsync(&name(slot_id)).and_then(|op| op.join()) {
                Ok(()) => Ok(()),
                Err(e) if already_deleted(e.code().0) => Ok(()),
                Err(e) => Err(win_error(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_verbatim() {
        assert_eq!(key_name("s1"), "deskauth-s1");
        assert_eq!(challenge("s1"), "deskauth v2 fingerprint:s1");
    }

    #[test]
    fn statuses_map() {
        assert_eq!(hello_status(STATUS_SUCCESS), Ok(()));
        assert_eq!(
            hello_status(STATUS_USER_CANCELED),
            Err(DeviceError::Cancelled)
        );
        assert_eq!(
            hello_status(STATUS_USER_PREFERS_PASSWORD),
            Err(DeviceError::Cancelled)
        );
        assert_eq!(hello_status(STATUS_NOT_FOUND), Err(DeviceError::NotSetUp));
        for s in [
            1, // UnknownError
            STATUS_CREDENTIAL_ALREADY_EXISTS,
            STATUS_SECURITY_DEVICE_LOCKED,
            42,
        ] {
            assert!(matches!(hello_status(s), Err(DeviceError::Other(_))), "{s}");
        }
        assert_ne!(hello_status(STATUS_SECURITY_DEVICE_LOCKED), hello_status(1));
    }

    #[test]
    fn hresult_is_a_sentence() {
        assert_eq!(
            hello_error(0x8009_0027_u32 as i32),
            DeviceError::Other("Windows Hello error: 0x80090027.".into())
        );
    }

    #[test]
    fn delete_ignores_missing_key() {
        for c in [NTE_NOT_FOUND, NTE_BAD_KEYSET, HRESULT_NOT_FOUND] {
            assert!(already_deleted(c));
        }
        assert!(!already_deleted(0x8009_0027_u32 as i32));
    }

    #[test]
    fn secret_is_sha256_of_signature() {
        // SHA-256("abc").
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(*secret_from_signature(b"abc"), expected);
        assert_ne!(*secret_from_signature(b"abd"), expected);
    }
}

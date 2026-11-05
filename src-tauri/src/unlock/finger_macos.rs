//! macOS Touch ID: the 32-byte secret is a Keychain item (data protection keychain) whose
//! access control is `biometryCurrentSet`, so the Secure Enclave asks for Touch ID on read.

use zeroize::Zeroizing;

use super::DeviceError;

const ERR_USER_CANCELED: i32 = -128;
const ERR_AUTH_FAILED: i32 = -25293;
const ERR_ITEM_NOT_FOUND: i32 = -25300;
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// Unsigned builds lack the keychain entitlement the data protection keychain needs.
const ERR_MISSING_ENTITLEMENT: i32 = -34018;

fn account(slot_id: &str) -> String {
    format!("fingerprint-{slot_id}")
}

/// Maps a Keychain `OSStatus` to a `DeviceError`.
fn keychain_error(code: i32) -> DeviceError {
    let other = |m: &str| DeviceError::Other(m.into());
    match code {
        ERR_ITEM_NOT_FOUND => DeviceError::NotSetUp,
        ERR_USER_CANCELED => DeviceError::Cancelled,
        ERR_MISSING_ENTITLEMENT => {
            DeviceError::Unsupported("Touch ID unlock needs a signed build of Deskauth.".into())
        }
        ERR_AUTH_FAILED => other("Touch ID did not accept the fingerprint. Try again."),
        ERR_INTERACTION_NOT_ALLOWED => {
            other("Touch ID is not available right now. Unlock your Mac and try again.")
        }
        _ => DeviceError::Other(format!("Keychain error: {code}.")),
    }
}

fn secret_from_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    if bytes.len() != secret.len() {
        return Err(DeviceError::Other(
            "The fingerprint secret in the Keychain is damaged.".into(),
        ));
    }
    secret.copy_from_slice(bytes);
    Ok(secret)
}

#[cfg(target_os = "macos")]
pub use imp::TouchIdFinger;

#[cfg(target_os = "macos")]
mod imp {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    use zeroize::Zeroizing;

    use super::{ERR_ITEM_NOT_FOUND, account, keychain_error, secret_from_bytes};
    use crate::unlock::{DeviceError, Fingerprint};

    const SERVICE: &str = "deskauth";

    pub struct TouchIdFinger;

    fn os_error(e: security_framework::base::Error) -> DeviceError {
        keychain_error(e.code())
    }

    /// The item lives in the data protection keychain, the only one that honours biometry.
    fn options(slot_id: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, &account(slot_id));
        options.use_protected_keychain();
        options
    }

    fn delete(slot_id: &str) -> Result<(), DeviceError> {
        match delete_generic_password_options(options(slot_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(os_error(e)),
        }
    }

    fn store(slot_id: &str, secret: &[u8; 32]) -> Result<(), DeviceError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
        )
        .map_err(os_error)?;
        let mut options = options(slot_id);
        options.set_access_control(access);
        set_generic_password_options(secret, options).map_err(os_error)
    }

    /// Reading the item is what asks for Touch ID.
    fn read(slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        let bytes = Zeroizing::new(generic_password(options(slot_id)).map_err(os_error)?);
        secret_from_bytes(&bytes)
    }

    impl Fingerprint for TouchIdFinger {
        /// Stays true even on unsigned builds, so enabling shows why it cannot work.
        fn available(&self) -> bool {
            true
        }

        fn platform(&self) -> &'static str {
            "macos"
        }

        /// Replaces any old item, then reads it back once so the finger is checked and the
        /// item is known to work before the slot is written.
        fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            delete(slot_id)?;
            let mut secret = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(secret.as_mut());
            store(slot_id, &secret)?;
            match read(slot_id) {
                Ok(back) if *back == *secret => Ok(secret),
                Ok(_) => {
                    let _ = delete(slot_id);
                    Err(DeviceError::Other(
                        "The Keychain did not keep the fingerprint secret.".into(),
                    ))
                }
                Err(e) => {
                    let _ = delete(slot_id);
                    Err(e)
                }
            }
        }

        fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
            read(slot_id)
        }

        fn disable(&self, slot_id: &str) -> Result<(), DeviceError> {
            delete(slot_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_names_the_slot() {
        assert_eq!(account("abc"), "fingerprint-abc");
    }

    #[test]
    fn keychain_errors_map() {
        assert_eq!(keychain_error(ERR_ITEM_NOT_FOUND), DeviceError::NotSetUp);
        assert_eq!(keychain_error(ERR_USER_CANCELED), DeviceError::Cancelled);
        assert_eq!(
            keychain_error(ERR_MISSING_ENTITLEMENT),
            DeviceError::Unsupported("Touch ID unlock needs a signed build of Deskauth.".into())
        );
        for code in [ERR_AUTH_FAILED, ERR_INTERACTION_NOT_ALLOWED] {
            assert!(
                matches!(keychain_error(code), DeviceError::Other(_)),
                "{code}"
            );
        }
        assert_ne!(
            keychain_error(ERR_AUTH_FAILED),
            keychain_error(ERR_INTERACTION_NOT_ALLOWED)
        );
        assert_eq!(
            keychain_error(-50),
            DeviceError::Other("Keychain error: -50.".into())
        );
    }

    #[test]
    fn secret_needs_32_bytes() {
        assert_eq!(*secret_from_bytes(&[5u8; 32]).unwrap(), [5u8; 32]);
        for bad in [&[5u8; 31][..], &[5u8; 33][..], &[][..]] {
            assert!(matches!(secret_from_bytes(bad), Err(DeviceError::Other(_))));
        }
    }
}

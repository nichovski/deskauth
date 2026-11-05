//! FIDO2 hmac-secret on Windows through `webauthn.dll`: normal apps cannot open FIDO HID
//! devices there, and Windows shows its own touch (and PIN) dialog.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use super::DeviceError;

/// `WEBAUTHN_API_VERSION_4` added hmac-secret salt values to GetAssertion
/// (`pHmacSecretSaltValues`, options version 6) and the output in the assertion (version 3).
const MIN_API_VERSION: u32 = 4;

const RP_ID: &str = "deskauth";
#[cfg(windows)]
const TIMEOUT_MS: u32 = 30_000;

const NTE_EXISTS: i32 = 0x8009_000F_u32 as i32;
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;
const NTE_DEVICE_NOT_FOUND: i32 = 0x8009_0035_u32 as i32;
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
/// `HRESULT_FROM_WIN32(ERROR_TIMEOUT)`.
const HRESULT_TIMEOUT: i32 = 0x8007_05B4_u32 as i32;

fn supports_hmac_salts(api_version: u32) -> bool {
    api_version >= MIN_API_VERSION
}

/// Maps a WebAuthn `HRESULT` to a `DeviceError`.
fn hresult_error(code: i32) -> DeviceError {
    match code {
        NTE_USER_CANCELLED => DeviceError::Cancelled,
        NTE_NOT_FOUND => DeviceError::NoCredential,
        NTE_EXISTS => DeviceError::AlreadyRegistered,
        NTE_DEVICE_NOT_FOUND => DeviceError::NoDevice,
        HRESULT_TIMEOUT => DeviceError::Timeout,
        _ => DeviceError::Other(format!("Security key error: 0x{:08X}.", code as u32)),
    }
}

fn no_hmac_secret() -> DeviceError {
    DeviceError::Unsupported(
        "This security key does not support the hmac-secret feature Deskauth needs.".into(),
    )
}

/// The client data Windows hashes into the request. Nothing checks it but the authenticator
/// signature, which Deskauth does not verify, so only its shape matters.
fn client_data_json(kind: &str, challenge: &[u8; 32]) -> String {
    serde_json::json!({
        "type": kind,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": RP_ID,
        "crossOrigin": false,
    })
    .to_string()
}

/// The hmac-secret output must be exactly one 32-byte value.
fn hmac_output(first: &[u8]) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
    let mut out = Zeroizing::new([0u8; 32]);
    if first.len() != out.len() {
        return Err(no_hmac_secret());
    }
    out.copy_from_slice(first);
    Ok(out)
}

/// The credential that answered must be one we asked for.
fn check_answer(allowed: &[(Vec<u8>, [u8; 32])], credential_id: &[u8]) -> Result<(), DeviceError> {
    if allowed.iter().any(|(id, _)| id == credential_id) {
        Ok(())
    } else {
        Err(DeviceError::NoCredential)
    }
}

#[cfg(windows)]
pub use imp::WebAuthnKey;

#[cfg(windows)]
mod imp {
    use std::ptr;

    use rand::RngCore;
    use rand::rngs::OsRng;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Networking::WindowsWebServices::*;
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    use windows::core::{BOOL, PCWSTR, w};
    use zeroize::Zeroizing;

    use super::{
        TIMEOUT_MS, check_answer, client_data_json, hmac_output, hresult_error, no_hmac_secret,
        supports_hmac_salts,
    };
    use crate::unlock::{DeviceError, Enrolled, HmacKey};

    pub struct WebAuthnKey;

    fn random<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        OsRng.fill_bytes(&mut b);
        b
    }

    fn win_error(e: windows::core::Error) -> DeviceError {
        hresult_error(e.code().0)
    }

    /// Windows parents its touch dialog to this window.
    fn window() -> HWND {
        // SAFETY: no arguments; a null window is allowed and only changes where the dialog shows.
        unsafe { GetForegroundWindow() }
    }

    /// # Safety
    /// `ptr` must be null or point to `len` readable bytes that outlive the returned slice.
    unsafe fn bytes<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
        if ptr.is_null() || len == 0 {
            &[]
        } else {
            // SAFETY: guaranteed by the caller.
            unsafe { std::slice::from_raw_parts(ptr, len as usize) }
        }
    }

    /// Owns `json` so the pointer in the returned struct stays valid while it lives.
    struct ClientData {
        json: Vec<u8>,
    }

    impl ClientData {
        fn new(kind: &str) -> Self {
            Self {
                json: client_data_json(kind, &random::<32>()).into_bytes(),
            }
        }

        fn raw(&mut self) -> WEBAUTHN_CLIENT_DATA {
            WEBAUTHN_CLIENT_DATA {
                dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                cbClientDataJSON: self.json.len() as u32,
                pbClientDataJSON: self.json.as_mut_ptr(),
                pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
            }
        }
    }

    /// Frees the attestation when dropped.
    struct Attestation(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);

    impl Drop for Attestation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from WebAuthNAuthenticatorMakeCredential and is freed once.
                unsafe { WebAuthNFreeCredentialAttestation(Some(self.0.cast_const())) }
            }
        }
    }

    /// Frees the assertion when dropped.
    struct Assertion(*mut WEBAUTHN_ASSERTION);

    impl Drop for Assertion {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from WebAuthNAuthenticatorGetAssertion and is freed once.
                unsafe { WebAuthNFreeAssertion(self.0.cast_const()) }
            }
        }
    }

    /// Whether the authenticator confirmed the hmac-secret extension for the new credential.
    fn has_hmac_secret(att: &WEBAUTHN_CREDENTIAL_ATTESTATION) -> bool {
        if att.dwVersion < WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2
            || att.Extensions.pExtensions.is_null()
        {
            return false;
        }
        // SAFETY: webauthn.dll fills `cExtensions` entries; each identifier is a valid string and
        // the hmac-secret output is a BOOL.
        unsafe {
            std::slice::from_raw_parts(
                att.Extensions.pExtensions,
                att.Extensions.cExtensions as usize,
            )
            .iter()
            .any(|e| {
                matches!(e.pwszExtensionIdentifier.to_string(), Ok(id) if id == "hmac-secret")
                    && e.cbExtension as usize == size_of::<BOOL>()
                    && !e.pvExtension.is_null()
                    && (*e.pvExtension.cast::<BOOL>()).as_bool()
            })
        }
    }

    /// Creates a non-resident credential with hmac-secret on a roaming key, user presence only.
    /// A key holding one of `exclude` refuses.
    fn make_credential(exclude: &[Vec<u8>]) -> Result<Vec<u8>, DeviceError> {
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: w!("deskauth"),
            pwszName: w!("Deskauth"),
            pwszIcon: PCWSTR::null(),
        };
        let mut user_id = random::<32>();
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: w!("deskauth"),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: w!("Deskauth"),
        };
        let mut algs = [WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        }];
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: algs.len() as u32,
            pCredentialParameters: algs.as_mut_ptr(),
        };
        let mut exclude_ids: Vec<Vec<u8>> = exclude.to_vec();
        let mut excluded: Vec<WEBAUTHN_CREDENTIAL> = exclude_ids
            .iter_mut()
            .map(|id| WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
            .collect();
        let mut client = ClientData::new("webauthn.create");
        let client_data = client.raw();
        let mut enable = BOOL::from(true);
        let mut extensions = [WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: size_of::<BOOL>() as u32,
            pvExtension: ptr::from_mut(&mut enable).cast(),
        }];
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            // In options version 1 this is the exclude list.
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: excluded.len() as u32,
                pCredentials: if excluded.is_empty() {
                    ptr::null_mut()
                } else {
                    excluded.as_mut_ptr()
                },
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: extensions.len() as u32,
                pExtensions: extensions.as_mut_ptr(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: BOOL::from(false),
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ..Default::default()
        };
        // SAFETY: every pointer in the arguments points into locals that outlive the call.
        let att = Attestation(
            unsafe {
                WebAuthNAuthenticatorMakeCredential(
                    window(),
                    &rp,
                    &user,
                    &params,
                    &client_data,
                    Some(&options),
                )
            }
            .map_err(win_error)?,
        );
        if att.0.is_null() {
            return Err(DeviceError::Other(
                "Security key error: no credential returned.".into(),
            ));
        }
        // SAFETY: non-null result of a successful call, valid until `att` drops.
        let a = unsafe { &*att.0 };
        if !has_hmac_secret(a) {
            return Err(no_hmac_secret());
        }
        // SAFETY: webauthn.dll returns `cbCredentialId` bytes at `pbCredentialId`.
        let id = unsafe { bytes(a.pbCredentialId, a.cbCredentialId) }.to_vec();
        if id.is_empty() {
            return Err(DeviceError::Other(
                "Security key error: no credential returned.".into(),
            ));
        }
        Ok(id)
    }

    /// One assertion with user presence. Every allowed credential gets its own salt, so the
    /// right one is used for whichever credential answers.
    fn get_assertion(
        allowed: &[(Vec<u8>, [u8; 32])],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError> {
        let mut ids: Vec<Vec<u8>> = allowed.iter().map(|(id, _)| id.clone()).collect();
        let mut salts: Vec<[u8; 32]> = allowed.iter().map(|(_, salt)| *salt).collect();
        let mut credentials: Vec<WEBAUTHN_CREDENTIAL> = ids
            .iter_mut()
            .map(|id| WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
            .collect();
        let mut salt_values: Vec<WEBAUTHN_HMAC_SECRET_SALT> = salts
            .iter_mut()
            .map(|salt| WEBAUTHN_HMAC_SECRET_SALT {
                cbFirst: salt.len() as u32,
                pbFirst: salt.as_mut_ptr(),
                cbSecond: 0,
                pbSecond: ptr::null_mut(),
            })
            .collect();
        let mut per_credential: Vec<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> = ids
            .iter_mut()
            .zip(salt_values.iter_mut())
            .map(|(id, salt)| WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT {
                cbCredID: id.len() as u32,
                pbCredID: id.as_mut_ptr(),
                pHmacSecretSalt: salt,
            })
            .collect();
        let mut hmac_salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: ptr::null_mut(),
            cCredWithHmacSecretSaltList: per_credential.len() as u32,
            pCredWithHmacSecretSaltList: per_credential.as_mut_ptr(),
        };
        let mut client = ClientData::new("webauthn.get");
        let client_data = client.raw();
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: credentials.len() as u32,
                pCredentials: credentials.as_mut_ptr(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            pHmacSecretSaltValues: &mut hmac_salts,
            ..Default::default()
        };
        // SAFETY: every pointer in the arguments points into locals that outlive the call.
        let assertion = Assertion(
            unsafe {
                WebAuthNAuthenticatorGetAssertion(
                    window(),
                    w!("deskauth"),
                    &client_data,
                    Some(&options),
                )
            }
            .map_err(win_error)?,
        );
        if assertion.0.is_null() {
            return Err(DeviceError::NoCredential);
        }
        // SAFETY: non-null result of a successful call, valid until `assertion` drops.
        let a = unsafe { &*assertion.0 };
        // SAFETY: webauthn.dll returns `cbId` bytes at `pbId`.
        let id = unsafe { bytes(a.Credential.pbId, a.Credential.cbId) }.to_vec();
        check_answer(allowed, &id)?;
        if a.dwVersion < WEBAUTHN_ASSERTION_VERSION_3 || a.pHmacSecret.is_null() {
            return Err(no_hmac_secret());
        }
        // SAFETY: non-null, owned by the assertion.
        let secret = unsafe { &*a.pHmacSecret };
        // SAFETY: webauthn.dll returns `cbFirst` bytes at `pbFirst`.
        let out = hmac_output(unsafe { bytes(secret.pbFirst, secret.cbFirst) });
        // Wipe the library's copy before it is freed, whatever its length.
        if !secret.pbFirst.is_null() {
            // SAFETY: the same `cbFirst` writable bytes, still owned by the assertion.
            unsafe { ptr::write_bytes(secret.pbFirst, 0, secret.cbFirst as usize) };
        }
        Ok((id, out?))
    }

    impl HmacKey for WebAuthnKey {
        /// False when webauthn.dll is too old to pass hmac-secret salts.
        fn available(&self) -> bool {
            // SAFETY: no arguments.
            supports_hmac_salts(unsafe { WebAuthNGetApiVersionNumber() })
        }

        /// Never true: polling for a key must not make Windows show its dialog.
        fn present(&self) -> bool {
            false
        }

        /// Windows asks for the PIN itself when the key has one.
        fn enroll(&self, exclude: &[Vec<u8>], _pin: Option<&str>) -> Result<Enrolled, DeviceError> {
            let credential_id = make_credential(exclude)?;
            let salt = random::<32>();
            let (_, hmac) = get_assertion(&[(credential_id.clone(), salt)])?;
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
            if allowed.is_empty() {
                return Err(DeviceError::NoCredential);
            }
            get_assertion(allowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_api_version_4() {
        assert!(!supports_hmac_salts(1));
        assert!(!supports_hmac_salts(3));
        assert!(supports_hmac_salts(4));
        assert!(supports_hmac_salts(7));
    }

    #[test]
    fn hresults_map() {
        assert_eq!(hresult_error(NTE_USER_CANCELLED), DeviceError::Cancelled);
        assert_eq!(hresult_error(NTE_NOT_FOUND), DeviceError::NoCredential);
        assert_eq!(hresult_error(HRESULT_TIMEOUT), DeviceError::Timeout);
        assert_eq!(hresult_error(NTE_DEVICE_NOT_FOUND), DeviceError::NoDevice);
        assert_eq!(hresult_error(NTE_EXISTS), DeviceError::AlreadyRegistered);
        assert_eq!(
            hresult_error(0x8009_0027_u32 as i32),
            DeviceError::Other("Security key error: 0x80090027.".into())
        );
    }

    #[test]
    fn client_data_has_type_and_challenge() {
        let json = client_data_json("webauthn.get", &[0xffu8; 32]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "webauthn.get");
        assert_eq!(v["challenge"], URL_SAFE_NO_PAD.encode([0xffu8; 32]));
        assert_eq!(v["origin"], "deskauth");
    }

    #[test]
    fn hmac_output_needs_32_bytes() {
        assert_eq!(*hmac_output(&[4u8; 32]).unwrap(), [4u8; 32]);
        for bad in [&[4u8; 31][..], &[4u8; 64][..], &[][..]] {
            assert!(matches!(hmac_output(bad), Err(DeviceError::Unsupported(_))));
        }
    }

    #[test]
    fn answer_must_be_allowed() {
        let allowed = vec![(b"a".to_vec(), [1u8; 32]), (b"b".to_vec(), [2u8; 32])];
        assert_eq!(check_answer(&allowed, b"b"), Ok(()));
        assert_eq!(
            check_answer(&allowed, b"zz"),
            Err(DeviceError::NoCredential)
        );
        assert_eq!(check_answer(&allowed, b""), Err(DeviceError::NoCredential));
    }
}

//! FIDO2 hmac-secret over USB HID (Linux, macOS) through `ctap-hid-fido2`.

use ctap_hid_fido2::fidokey::get_assertion::{Extension as GetExt, GetAssertionArgsBuilder};
use ctap_hid_fido2::fidokey::make_credential::{Extension as MakeExt, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, HidParam, LibCfg, get_fidokey_devices};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use super::{DeviceError, Enrolled, HmacKey};

const RP_ID: &str = "deskauth";

pub struct HidKey;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// The library must print nothing: no CTAP traces, no "touch the sensor" line.
fn lib_cfg() -> LibCfg {
    let mut cfg = LibCfg::init();
    cfg.enable_log = false;
    cfg.enable_keep_alive_msg = false;
    cfg.keep_alive_msg.clear();
    cfg
}

/// Maps a `ctap-hid-fido2` error message (CTAP status names are part of the text) to a `DeviceError`.
fn map_error(msg: &str) -> DeviceError {
    if msg.contains("CTAP2_ERR_NO_CREDENTIALS") {
        DeviceError::NoCredential
    } else if msg.contains("CTAP2_ERR_CREDENTIAL_EXCLUDED") {
        DeviceError::AlreadyRegistered
    } else if msg.contains("CTAP2_ERR_USER_ACTION_TIMEOUT")
        || msg.contains("CTAP2_ERR_ACTION_TIMEOUT")
    {
        DeviceError::Timeout
    } else if msg.contains("CTAP2_ERR_KEEPALIVE_CANCEL") {
        DeviceError::Cancelled
    } else if msg.contains("FIDO device not found") {
        DeviceError::NoDevice
    } else if msg.contains("CTAP2_ERR_PIN_INVALID") {
        DeviceError::WrongPin
    } else if msg.contains("CTAP2_ERR_PIN_BLOCKED") || msg.contains("CTAP2_ERR_PIN_AUTH_BLOCKED") {
        DeviceError::PinBlocked
    } else if [
        "CTAP2_ERR_PIN_REQUIRED",
        "CTAP2_ERR_PUAT_REQUIRED",
        "CTAP2_ERR_PIN_AUTH_INVALID",
        "CTAP2_ERR_OPERATION_DENIED",
    ]
    .iter()
    .any(|code| msg.contains(code))
    {
        DeviceError::PinRequired
    } else if msg.contains("CTAP2_ERR_LIMIT_EXCEEDED") {
        DeviceError::Unsupported(
            "Too many YubiKeys are registered for this key to check at once.".into(),
        )
    } else {
        let short = msg
            .split_whitespace()
            .find(|w| w.starts_with("CTAP"))
            .unwrap_or(msg.trim());
        key_error(short)
    }
}

/// A sentence around a raw library code or message the user cannot act on directly.
fn key_error(code: &str) -> DeviceError {
    DeviceError::Other(format!(
        "Security key error: {}.",
        code.trim_end_matches('.')
    ))
}

/// CTAP2 lets the authenticator omit the credential id when the allow list has exactly one
/// entry; then that entry is the one it used (libfido2 does the same).
fn returned_id(returned: Vec<u8>, sent: &[(Vec<u8>, [u8; 32])]) -> Vec<u8> {
    match sent {
        [(only, _)] if returned.is_empty() => only.clone(),
        _ => returned,
    }
}

fn salt_for(allowed: &[(Vec<u8>, [u8; 32])], credential_id: &[u8]) -> Option<[u8; 32]> {
    allowed
        .iter()
        .find(|(id, _)| id == credential_id)
        .map(|(_, salt)| *salt)
}

/// Probes devices in order and returns the first that holds an allowed credential, with that
/// credential's id and salt. No devices → `NoDevice`; devices that answered but hold none →
/// `NoCredential`; if every device failed otherwise, the first of those errors.
fn first_holder<D, T>(
    devices: impl IntoIterator<Item = D>,
    allowed: &[(Vec<u8>, [u8; 32])],
    mut probe: impl FnMut(D) -> Result<(T, Vec<u8>), DeviceError>,
) -> Result<(T, Vec<u8>, [u8; 32]), DeviceError> {
    let mut answered = false;
    let mut first_err = None;
    for device in devices {
        match probe(device) {
            Ok((dev, id)) => match salt_for(allowed, &id) {
                Some(salt) => return Ok((dev, id, salt)),
                None => answered = true,
            },
            Err(DeviceError::NoCredential) => answered = true,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if answered {
        return Err(DeviceError::NoCredential);
    }
    Err(first_err.unwrap_or(DeviceError::NoDevice))
}

/// Copies the hmac-secret output out of the assertion's extensions and wipes the library's copy.
fn take_hmac(extensions: &mut [GetExt]) -> Option<Zeroizing<[u8; 32]>> {
    extensions.iter_mut().find_map(|e| match e {
        GetExt::HmacSecret(Some(out)) => {
            let hmac = Zeroizing::new(*out);
            out.zeroize();
            Some(hmac)
        }
        _ => None,
    })
}

fn no_hmac_secret() -> DeviceError {
    DeviceError::Unsupported(
        "This security key does not support the hmac-secret feature Deskauth needs.".into(),
    )
}

fn has_hmac_secret(extensions: &[MakeExt]) -> bool {
    extensions
        .iter()
        .any(|e| matches!(e, MakeExt::HmacSecret(Some(true))))
}

fn open(param: HidParam) -> Result<FidoKeyHid, DeviceError> {
    FidoKeyHidFactory::create_by_params(&[param], &lib_cfg()).map_err(|e| map_error(&e.to_string()))
}

/// Asks the device, without a touch, which of the allowed credentials it holds.
fn probe(dev: &FidoKeyHid, allowed: &[(Vec<u8>, [u8; 32])]) -> Result<Vec<u8>, DeviceError> {
    let challenge = random::<32>();
    let mut builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .without_pin_and_uv()
        .without_up();
    for (id, _) in allowed {
        builder = builder.add_credential_id(id);
    }
    let assertions = dev
        .get_assertion_with_args(&builder.build())
        .map_err(|e| map_error(&e.to_string()))?;
    assertions
        .into_iter()
        .next()
        .map(|a| returned_id(a.credential_id, allowed))
        .ok_or(DeviceError::NoCredential)
}

/// One assertion with user presence (touch) returning the hmac-secret output for `salt`.
fn hmac(
    dev: &FidoKeyHid,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
    let challenge = random::<32>();
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .without_pin_and_uv()
        .credential_id(credential_id)
        .extensions(&[GetExt::HmacSecret(Some(*salt))])
        .build();
    let mut assertions = dev
        .get_assertion_with_args(&args)
        .map_err(|e| map_error(&e.to_string()))?;
    let mut out = None;
    for a in &mut assertions {
        if let Some(h) = take_hmac(&mut a.extensions) {
            out.get_or_insert(h);
        }
    }
    out.ok_or_else(no_hmac_secret)
}

impl HmacKey for HidKey {
    /// HID access is always there; a missing key is reported when it is used.
    fn available(&self) -> bool {
        true
    }

    fn present(&self) -> bool {
        !get_fidokey_devices().is_empty()
    }

    /// Uses the first FIDO device found when several are plugged in. `exclude` is sent as the
    /// excludeList, so a key that is already registered refuses. With `pin`, makeCredential
    /// carries a pinUvAuthParam (keys whose firmware wants the PIN to register); the assertion
    /// after it stays touch only, like every unlock, so both get the same hmac output.
    fn enroll(&self, exclude: &[Vec<u8>], pin: Option<&str>) -> Result<Enrolled, DeviceError> {
        let param = get_fidokey_devices()
            .into_iter()
            .next()
            .ok_or(DeviceError::NoDevice)?
            .param;
        let dev = open(param)?;
        let challenge = random::<32>();
        let user_id = random::<32>();
        let user =
            PublicKeyCredentialUserEntity::new(Some(&user_id), Some("deskauth"), Some("Deskauth"));
        let builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge);
        let builder = match pin {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };
        let mut builder = builder
            .user_entity(&user)
            .extensions(&[MakeExt::HmacSecret(Some(true))]);
        for id in exclude {
            builder = builder.exclude_authenticator(id);
        }
        let args = builder.build();
        let att = dev
            .make_credential_with_args(&args)
            .map_err(|e| map_error(&e.to_string()))?;
        if !has_hmac_secret(&att.extensions) {
            return Err(no_hmac_secret());
        }
        let credential_id = att.credential_descriptor.id;
        let salt = random::<32>();
        let hmac = hmac(&dev, &credential_id, &salt)?;
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
        let params = get_fidokey_devices().into_iter().map(|d| d.param);
        let (dev, credential_id, salt) = first_holder(params, allowed, |param| {
            let dev = open(param)?;
            let id = probe(&dev, allowed)?;
            Ok((dev, id))
        })?;
        let out = hmac(&dev, &credential_id, &salt)?;
        Ok((credential_id, out))
    }
}

#[cfg(test)]
mod tests {
    use ctap_hid_fido2::fidokey::get_assertion::Extension as GetExt;
    use ctap_hid_fido2::fidokey::make_credential::Extension as MakeExt;

    use super::*;

    fn allowed() -> Vec<(Vec<u8>, [u8; 32])> {
        vec![(b"a".to_vec(), [1u8; 32]), (b"b".to_vec(), [2u8; 32])]
    }

    #[test]
    fn maps_ctap_errors() {
        let e = |s: &str| map_error(s);
        assert_eq!(
            e(
                "response_status err = 0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."
            ),
            DeviceError::NoCredential
        );
        assert_eq!(
            e(
                "response_status err = 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT   Timeout waiting for user interaction."
            ),
            DeviceError::Timeout
        );
        assert_eq!(
            e(
                "response_status err = 0x3A CTAP2_ERR_ACTION_TIMEOUT The current operation has timed out."
            ),
            DeviceError::Timeout
        );
        assert_eq!(
            e(
                "response_status err = 0x2D CTAP2_ERR_KEEPALIVE_CANCEL  Pending keep alive was cancelled."
            ),
            DeviceError::Cancelled
        );
        assert_eq!(
            e(
                "response_status err = 0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED   Valid credential found in the exclude list."
            ),
            DeviceError::AlreadyRegistered
        );
        assert_eq!(e("FIDO device not found."), DeviceError::NoDevice);
    }

    #[test]
    fn pin_errors_map() {
        for msg in [
            "response_status err = 0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation.",
            "response_status err = 0x36 CTAP2_ERR_PUAT_REQUIRED",
            "response_status err = 0x33 CTAP2_ERR_PIN_AUTH_INVALID PIN authentication, pinAuth, verification failed.",
            "response_status err = 0x27 CTAP2_ERR_OPERATION_DENIED  Not authorized for requested operation.",
        ] {
            assert_eq!(map_error(msg), DeviceError::PinRequired, "{msg}");
        }
        assert_eq!(
            map_error("response_status err = 0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
            DeviceError::WrongPin
        );
        for msg in [
            "response_status err = 0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked.",
            "response_status err = 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked.Requires power recycle to reset.",
        ] {
            assert_eq!(map_error(msg), DeviceError::PinBlocked, "{msg}");
        }
    }

    #[test]
    fn limit_and_hmac_errors_are_plain_sentences() {
        assert_eq!(
            map_error(
                "response_status err = 0x15 CTAP2_ERR_LIMIT_EXCEEDED Limit for number of items exceeded."
            ),
            DeviceError::Unsupported(
                "Too many YubiKeys are registered for this key to check at once.".into()
            )
        );
        assert!(
            matches!(no_hmac_secret(), DeviceError::Unsupported(m) if m.ends_with("Deskauth needs."))
        );
    }

    #[test]
    fn returned_id_fills_omitted_single_credential() {
        let one = vec![(b"a".to_vec(), [1u8; 32])];
        assert_eq!(returned_id(vec![], &one), b"a".to_vec());
        assert_eq!(returned_id(vec![], &allowed()), Vec::<u8>::new());
        assert_eq!(salt_for(&allowed(), &returned_id(vec![], &allowed())), None);
        assert_eq!(returned_id(b"b".to_vec(), &one), b"b".to_vec());
        assert_eq!(returned_id(b"b".to_vec(), &allowed()), b"b".to_vec());
    }

    #[test]
    fn other_errors_keep_short_text() {
        assert_eq!(
            map_error(
                "response_status err = 0x01 CTAP1_ERR_INVALID_COMMAND The command is not a valid CTAP command."
            ),
            DeviceError::Other("Security key error: CTAP1_ERR_INVALID_COMMAND.".into())
        );
        assert_eq!(
            map_error("Failed to open device."),
            DeviceError::Other("Security key error: Failed to open device.".into())
        );
    }

    #[test]
    fn salt_for_finds_matching_credential() {
        assert_eq!(salt_for(&allowed(), b"b"), Some([2u8; 32]));
        assert_eq!(salt_for(&allowed(), b"zz"), None);
    }

    #[test]
    fn first_holder_no_devices_is_no_device() {
        let r = first_holder(
            Vec::<u8>::new(),
            &allowed(),
            |_| -> Result<((), Vec<u8>), DeviceError> { unreachable!() },
        );
        assert_eq!(r.err(), Some(DeviceError::NoDevice));
    }

    #[test]
    fn first_holder_skips_devices_without_the_credential() {
        let mut probed = vec![];
        let r = first_holder(vec![1, 2, 3], &allowed(), |d| {
            probed.push(d);
            match d {
                1 => Err(DeviceError::NoCredential),
                2 => Ok((d, b"b".to_vec())),
                _ => Ok((d, b"a".to_vec())),
            }
        })
        .unwrap();
        assert_eq!(r.0, 2);
        assert_eq!(r.1, b"b".to_vec());
        assert_eq!(r.2, [2u8; 32]);
        assert_eq!(probed, vec![1, 2], "stops at the first holder");
    }

    #[test]
    fn first_holder_ignores_unknown_returned_id_and_device_errors() {
        let r = first_holder(vec![1, 2, 3], &allowed(), |d| match d {
            1 => Err(DeviceError::Other("CTAP1_ERR_INVALID_COMMAND".into())),
            2 => Ok((d, b"stranger".to_vec())),
            _ => Ok((d, b"a".to_vec())),
        })
        .unwrap();
        assert_eq!((r.0, r.2), (3, [1u8; 32]));
    }

    #[test]
    fn first_holder_none_holds_is_no_credential() {
        let r = first_holder(
            vec![1, 2],
            &allowed(),
            |d| -> Result<((), Vec<u8>), DeviceError> {
                match d {
                    1 => Err(DeviceError::Other("x".into())),
                    _ => Err(DeviceError::NoCredential),
                }
            },
        );
        assert_eq!(r.err(), Some(DeviceError::NoCredential));
        let r = first_holder(vec![1], &allowed(), |d| Ok((d, b"stranger".to_vec())));
        assert_eq!(r.err(), Some(DeviceError::NoCredential));
    }

    #[test]
    fn first_holder_all_failing_returns_first_error() {
        let r = first_holder(
            vec![1, 2],
            &allowed(),
            |d| -> Result<(i32, Vec<u8>), DeviceError> {
                Err(DeviceError::Other(format!("dev {d}")))
            },
        );
        assert_eq!(r.err(), Some(DeviceError::Other("dev 1".into())));
    }

    #[test]
    fn take_hmac_copies_and_wipes() {
        let mut ext = vec![
            GetExt::CredBlob((None, Some(vec![1]))),
            GetExt::HmacSecret(Some([7u8; 32])),
        ];
        let out = take_hmac(&mut ext).unwrap();
        assert_eq!(*out, [7u8; 32]);
        assert!(matches!(ext[1], GetExt::HmacSecret(Some(o)) if o == [0u8; 32]));
        assert!(take_hmac(&mut [GetExt::HmacSecret(None)]).is_none());
    }

    #[test]
    fn has_hmac_secret_needs_true() {
        assert!(has_hmac_secret(&[MakeExt::HmacSecret(Some(true))]));
        assert!(!has_hmac_secret(&[MakeExt::HmacSecret(Some(false))]));
        assert!(!has_hmac_secret(&[]));
    }

    #[test]
    fn lib_cfg_prints_nothing() {
        let c = lib_cfg();
        assert!(!c.enable_log);
        assert!(!c.enable_keep_alive_msg);
        assert!(c.keep_alive_msg.is_empty());
    }
}

//! Linux fingerprint: `fprintd` over the system D-Bus checks the finger, then the 32-byte
//! secret is read from the Secret Service keyring (gnome-keyring, KWallet).

use std::time::{Duration, Instant};

use async_io::Timer;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_lite::{StreamExt, future};
use rand::RngCore;
use rand::rngs::OsRng;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};
use zeroize::Zeroizing;

use super::{DeviceError, Fingerprint};

const FPRINT: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";
const KEYRING_SERVICE: &str = "deskauth";
const TIMEOUT: Duration = Duration::from_secs(30);
/// Per D-Bus call, so a wedged fprintd cannot hang Claim, VerifyStart, VerifyStop or Release.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct FprintdFinger;

/// What one `VerifyStatus` signal means for the wait loop.
#[derive(Debug, PartialEq)]
enum Status {
    Match,
    Retry,
    Fail(DeviceError),
}

/// Maps a `VerifyStatus(result, done)` signal. Retry results keep the scan running unless
/// fprintd says the scan is over.
fn status(result: &str, done: bool) -> Status {
    let other = |m: &str| Status::Fail(DeviceError::Other(m.into()));
    match result {
        "verify-match" => Status::Match,
        "verify-no-match" => other("Fingerprint did not match."),
        "verify-retry-scan"
        | "verify-swipe-too-short"
        | "verify-finger-not-centered"
        | "verify-remove-and-retry" => {
            if done {
                other("The fingerprint could not be read. Try again.")
            } else {
                Status::Retry
            }
        }
        "verify-disconnected" => other("The fingerprint reader was disconnected."),
        _ => other("The fingerprint reader reported an error."),
    }
}

/// Maps a D-Bus error name from fprintd (or the bus itself) to a `DeviceError`.
fn fprint_error(name: &str) -> DeviceError {
    let other = |m: &str| DeviceError::Other(m.into());
    match name {
        "net.reactivated.Fprint.Error.NoSuchDevice"
        | "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner" => DeviceError::NoReader,
        "org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.Timeout" => {
            DeviceError::Timeout
        }
        "net.reactivated.Fprint.Error.AlreadyInUse" => {
            other("The fingerprint reader is in use by another program.")
        }
        "net.reactivated.Fprint.Error.PermissionDenied" => {
            other("Deskauth is not allowed to use the fingerprint reader.")
        }
        "net.reactivated.Fprint.Error.NoEnrolledPrints" => {
            other("No fingerprint is enrolled for your user. Add one in the system settings.")
        }
        _ => other("The fingerprint reader reported an error."),
    }
}

fn bus_error(e: zbus::Error) -> DeviceError {
    match e {
        zbus::Error::MethodError(name, _, _) => fprint_error(name.as_str()),
        zbus::Error::InputOutput(io) if io.kind() == std::io::ErrorKind::TimedOut => {
            DeviceError::Timeout
        }
        _ => DeviceError::Other("Could not reach the fingerprint service.".into()),
    }
}

fn keyring_error(e: keyring::Error) -> DeviceError {
    match e {
        keyring::Error::NoEntry => DeviceError::NotSetUp,
        keyring::Error::NoStorageAccess(_) => {
            DeviceError::Other("The system keyring is locked or unavailable.".into())
        }
        _ => DeviceError::Other("Could not use the system keyring.".into()),
    }
}

fn encode_secret(secret: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(secret))
}

fn decode_secret(text: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
    let damaged = || DeviceError::Other("The fingerprint secret in the keyring is damaged.".into());
    let bytes = Zeroizing::new(STANDARD.decode(text).map_err(|_| damaged())?);
    let mut secret = Zeroizing::new([0u8; 32]);
    if bytes.len() != secret.len() {
        return Err(damaged());
    }
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// Checks the stored secret is there and readable before the scan, so a removed item fails
/// at once, then reads it again only after `scan` succeeds.
fn read_after_scan(
    read: impl Fn() -> Result<Zeroizing<String>, keyring::Error>,
    scan: impl FnOnce() -> Result<(), DeviceError>,
) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
    decode_secret(&read().map_err(keyring_error)?)?;
    scan()?;
    decode_secret(&read().map_err(keyring_error)?)
}

async fn system_bus() -> Result<Connection, DeviceError> {
    zbus::connection::Builder::system()
        .map_err(bus_error)?
        .method_timeout(CALL_TIMEOUT)
        .build()
        .await
        .map_err(bus_error)
}

fn entry(slot_id: &str) -> Result<keyring::Entry, DeviceError> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("fingerprint-{slot_id}")).map_err(keyring_error)
}

async fn default_device(conn: &Connection) -> Result<Proxy<'static>, DeviceError> {
    let manager = Proxy::new(conn, FPRINT, MANAGER_PATH, MANAGER_IFACE)
        .await
        .map_err(bus_error)?;
    let path: OwnedObjectPath = manager
        .call("GetDefaultDevice", &())
        .await
        .map_err(bus_error)?;
    Proxy::new(conn, FPRINT, path, DEVICE_IFACE)
        .await
        .map_err(bus_error)
}

async fn has_enrolled_finger() -> Result<bool, DeviceError> {
    let conn = system_bus().await?;
    let device = default_device(&conn).await?;
    let fingers: Vec<String> = device
        .call("ListEnrolledFingers", &("",))
        .await
        .map_err(bus_error)?;
    Ok(!fingers.is_empty())
}

/// Claims the default reader for the current user, runs one verify and always releases it.
async fn verify() -> Result<(), DeviceError> {
    let conn = system_bus().await?;
    let device = default_device(&conn).await?;
    device
        .call::<_, _, ()>("Claim", &("",))
        .await
        .map_err(bus_error)?;
    let result = verify_claimed(&device).await;
    // Best effort: fprintd also releases the device when this connection closes.
    let _ = device.call::<_, _, ()>("Release", &()).await;
    result
}

async fn verify_claimed(device: &Proxy<'_>) -> Result<(), DeviceError> {
    // Subscribe before starting so no result is missed.
    let mut statuses = device
        .receive_signal("VerifyStatus")
        .await
        .map_err(bus_error)?;
    device
        .call::<_, _, ()>("VerifyStart", &("any",))
        .await
        .map_err(bus_error)?;
    let result = wait_for_match(&mut statuses).await;
    // fprintd needs VerifyStop after every VerifyStart, even when the scan is done.
    let _ = device.call::<_, _, ()>("VerifyStop", &()).await;
    result
}

async fn wait_for_match(statuses: &mut zbus::proxy::SignalStream<'_>) -> Result<(), DeviceError> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let next = future::or(async { Some(statuses.next().await) }, async {
            Timer::at(deadline).await;
            None
        })
        .await;
        let msg = match next {
            None => return Err(DeviceError::Timeout),
            Some(None) => {
                return Err(DeviceError::Other(
                    "Lost the connection to the fingerprint service.".into(),
                ));
            }
            Some(Some(msg)) => msg,
        };
        let (result, done): (String, bool) = msg.body().deserialize().map_err(bus_error)?;
        match status(&result, done) {
            Status::Match => return Ok(()),
            Status::Retry => continue,
            Status::Fail(e) => return Err(e),
        }
    }
}

fn random_secret() -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    secret
}

impl Fingerprint for FprintdFinger {
    fn available(&self) -> bool {
        async_io::block_on(has_enrolled_finger()).unwrap_or(false)
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        async_io::block_on(verify())?;
        let secret = random_secret();
        entry(slot_id)?
            .set_password(&encode_secret(&secret))
            .map_err(keyring_error)?;
        Ok(secret)
    }

    fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        let entry = entry(slot_id)?;
        read_after_scan(
            || entry.get_password().map(Zeroizing::new),
            || async_io::block_on(verify()),
        )
    }

    fn disable(&self, slot_id: &str) -> Result<(), DeviceError> {
        match entry(slot_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keyring_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_is_match() {
        assert_eq!(status("verify-match", true), Status::Match);
    }

    #[test]
    fn no_match_says_so() {
        assert_eq!(
            status("verify-no-match", true),
            Status::Fail(DeviceError::Other("Fingerprint did not match.".into()))
        );
    }

    #[test]
    fn retry_results_keep_waiting() {
        for r in [
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
        ] {
            assert_eq!(status(r, false), Status::Retry, "{r}");
        }
    }

    #[test]
    fn retry_that_ends_the_scan_fails() {
        assert!(matches!(
            status("verify-retry-scan", true),
            Status::Fail(DeviceError::Other(_))
        ));
    }

    #[test]
    fn disconnected_and_unknown_fail() {
        for r in [
            "verify-disconnected",
            "verify-unknown-error",
            "something-new",
        ] {
            assert!(
                matches!(status(r, true), Status::Fail(DeviceError::Other(_))),
                "{r}"
            );
        }
        assert_ne!(
            status("verify-disconnected", true),
            status("verify-unknown-error", true)
        );
    }

    #[test]
    fn fprintd_errors_map() {
        assert_eq!(
            fprint_error("net.reactivated.Fprint.Error.NoSuchDevice"),
            DeviceError::NoReader
        );
        assert_eq!(
            fprint_error("org.freedesktop.DBus.Error.ServiceUnknown"),
            DeviceError::NoReader
        );
        for name in [
            "net.reactivated.Fprint.Error.AlreadyInUse",
            "net.reactivated.Fprint.Error.PermissionDenied",
            "net.reactivated.Fprint.Error.NoEnrolledPrints",
            "net.reactivated.Fprint.Error.Internal",
        ] {
            assert!(
                matches!(fprint_error(name), DeviceError::Other(_)),
                "{name}"
            );
        }
    }

    #[test]
    fn call_timeout_is_timeout() {
        let io = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(
            bus_error(zbus::Error::InputOutput(std::sync::Arc::new(io))),
            DeviceError::Timeout
        );
        assert_eq!(
            fprint_error("org.freedesktop.DBus.Error.NoReply"),
            DeviceError::Timeout
        );
        let other = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        assert!(matches!(
            bus_error(zbus::Error::InputOutput(std::sync::Arc::new(other))),
            DeviceError::Other(_)
        ));
    }

    #[test]
    fn missing_item_fails_before_scan() {
        let mut scanned = false;
        let r = read_after_scan(
            || Err(keyring::Error::NoEntry),
            || {
                scanned = true;
                Ok(())
            },
        );
        assert_eq!(r.err(), Some(DeviceError::NotSetUp));
        assert!(!scanned);
    }

    #[test]
    fn damaged_item_fails_before_scan() {
        let mut scanned = false;
        let r = read_after_scan(
            || Ok(Zeroizing::new("bad".into())),
            || {
                scanned = true;
                Ok(())
            },
        );
        assert!(matches!(r, Err(DeviceError::Other(_))));
        assert!(!scanned);
    }

    #[test]
    fn failed_scan_returns_scan_error() {
        let text = encode_secret(&[3u8; 32]);
        let r = read_after_scan(|| Ok(text.clone()), || Err(DeviceError::Timeout));
        assert_eq!(r.err(), Some(DeviceError::Timeout));
    }

    #[test]
    fn good_scan_reads_secret_again() {
        let text = encode_secret(&[3u8; 32]);
        let reads = std::cell::Cell::new(0);
        let r = read_after_scan(
            || {
                reads.set(reads.get() + 1);
                Ok(text.clone())
            },
            || Ok(()),
        );
        assert_eq!(*r.unwrap(), [3u8; 32]);
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn secret_round_trip() {
        let secret = [7u8; 32];
        let text = encode_secret(&secret);
        assert_eq!(*decode_secret(&text).unwrap(), secret);
    }

    #[test]
    fn bad_secret_rejected() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let short = STANDARD.encode([1u8; 31]);
        let long = STANDARD.encode([1u8; 33]);
        for text in [short.as_str(), long.as_str(), "not base64!", ""] {
            assert!(
                matches!(decode_secret(text), Err(DeviceError::Other(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn keyring_errors_map() {
        assert_eq!(
            keyring_error(keyring::Error::NoEntry),
            DeviceError::NotSetUp
        );
        let io = || Box::new(std::io::Error::other("x"));
        assert!(matches!(
            keyring_error(keyring::Error::NoStorageAccess(io())),
            DeviceError::Other(_)
        ));
        assert!(matches!(
            keyring_error(keyring::Error::PlatformFailure(io())),
            DeviceError::Other(_)
        ));
        assert!(matches!(
            keyring_error(keyring::Error::BadEncoding(vec![0xff])),
            DeviceError::Other(_)
        ));
    }
}

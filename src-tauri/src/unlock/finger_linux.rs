//! Linux fingerprint: `fprintd` over the system D-Bus checks the finger, then the 32-byte
//! secret is read from the Secret Service keyring (gnome-keyring, KWallet).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_io::Timer;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_lite::{Stream, StreamExt, future};
use rand::RngCore;
use rand::rngs::OsRng;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};
use zeroize::Zeroizing;

use super::{DeviceError, FingerStatus, Fingerprint, OnStatus};

const FPRINT: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";
const KEYRING_SERVICE: &str = "deskauth";
const TIMEOUT: Duration = Duration::from_secs(30);
/// Per D-Bus call, so a wedged fprintd cannot hang Claim, VerifyStart, VerifyStop or Release.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// How soon a running scan notices it was cancelled.
const CANCEL_CHECK: Duration = Duration::from_millis(200);

pub struct FprintdFinger;

/// What one `VerifyStatus` signal means for the wait loop.
#[derive(Debug, PartialEq)]
enum Status {
    Match,
    /// Keep waiting; the sentence tells the user what to do.
    Retry(&'static str),
    NoMatch,
    Fail(DeviceError),
}

/// Maps a `VerifyStatus(result, done)` signal. Retry results keep the scan running unless
/// fprintd says the scan is over.
fn status(result: &str, done: bool) -> Status {
    let other = |m: &str| Status::Fail(DeviceError::Other(m.into()));
    let retry = |hint| {
        if done {
            other("The fingerprint could not be read. Try again.")
        } else {
            Status::Retry(hint)
        }
    };
    match result {
        "verify-match" => Status::Match,
        "verify-no-match" => Status::NoMatch,
        "verify-retry-scan" => retry("Scan again."),
        "verify-swipe-too-short" => retry("Swipe longer."),
        "verify-finger-not-centered" => retry("Center your finger."),
        "verify-remove-and-retry" => retry("Lift your finger and try again."),
        "verify-disconnected" => other("The fingerprint reader was disconnected."),
        _ => other("The fingerprint reader reported an error."),
    }
}

fn no_match() -> DeviceError {
    DeviceError::Other("Fingerprint did not match.".into())
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
async fn verify(cancel: &AtomicBool, on_status: OnStatus<'_>) -> Result<(), DeviceError> {
    let conn = system_bus().await?;
    let device = default_device(&conn).await?;
    device
        .call::<_, _, ()>("Claim", &("",))
        .await
        .map_err(bus_error)?;
    let result = verify_claimed(&device, cancel, on_status).await;
    // Best effort: fprintd also releases the device when this connection closes.
    let _ = device.call::<_, _, ()>("Release", &()).await;
    result
}

async fn verify_claimed(
    device: &Proxy<'_>,
    cancel: &AtomicBool,
    on_status: OnStatus<'_>,
) -> Result<(), DeviceError> {
    // Subscribe before starting so no result is missed.
    let statuses = device
        .receive_signal("VerifyStatus")
        .await
        .map_err(bus_error)?
        .map(|msg| msg.body().deserialize::<(String, bool)>().map_err(bus_error));
    device
        .call::<_, _, ()>("VerifyStart", &("any",))
        .await
        .map_err(bus_error)?;
    on_status(FingerStatus::Scanning);
    let result = wait_for_match(statuses, cancel, on_status).await;
    // fprintd needs VerifyStop after every VerifyStart, even when the scan is done.
    let _ = device.call::<_, _, ()>("VerifyStop", &()).await;
    result
}

/// Waits for the end of a scan, given the `(result, done)` of each `VerifyStatus` signal.
/// Wakes at least every `CANCEL_CHECK` to look at `cancel`; dropping `next()` loses no signal.
async fn wait_for_match(
    mut statuses: impl Stream<Item = Result<(String, bool), DeviceError>> + Unpin,
    cancel: &AtomicBool,
    on_status: OnStatus<'_>,
) -> Result<(), DeviceError> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(DeviceError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(DeviceError::Timeout);
        }
        let next = future::or(async { Some(statuses.next().await) }, async {
            Timer::after(CANCEL_CHECK).await;
            None
        })
        .await;
        let (result, done) = match next {
            None => continue,
            Some(None) => {
                return Err(DeviceError::Other(
                    "Lost the connection to the fingerprint service.".into(),
                ));
            }
            Some(Some(item)) => item?,
        };
        match status(&result, done) {
            Status::Match => return Ok(()),
            Status::Retry(hint) => on_status(FingerStatus::Retry(hint)),
            Status::NoMatch => {
                on_status(FingerStatus::NoMatch);
                return Err(no_match());
            }
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

    fn enable(&self, slot_id: &str, on_status: OnStatus) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        let never = AtomicBool::new(false);
        async_io::block_on(verify(&never, on_status))?;
        let secret = random_secret();
        entry(slot_id)?
            .set_password(&encode_secret(&secret))
            .map_err(keyring_error)?;
        Ok(secret)
    }

    /// On cancel the scan is stopped (VerifyStop, Release) and `Cancelled` returned.
    fn unlock(
        &self,
        slot_id: &str,
        cancel: &AtomicBool,
        on_status: OnStatus,
    ) -> Result<Zeroizing<[u8; 32]>, DeviceError> {
        let entry = entry(slot_id)?;
        read_after_scan(
            || entry.get_password().map(Zeroizing::new),
            || async_io::block_on(verify(cancel, on_status)),
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
        assert_eq!(status("verify-no-match", true), Status::NoMatch);
        assert_eq!(
            no_match(),
            DeviceError::Other("Fingerprint did not match.".into())
        );
    }

    #[test]
    fn retry_results_keep_waiting_with_a_hint() {
        for (r, hint) in [
            ("verify-retry-scan", "Scan again."),
            ("verify-swipe-too-short", "Swipe longer."),
            ("verify-finger-not-centered", "Center your finger."),
            ("verify-remove-and-retry", "Lift your finger and try again."),
        ] {
            assert_eq!(status(r, false), Status::Retry(hint), "{r}");
        }
    }

    fn signals(
        items: Vec<(&str, bool)>,
    ) -> impl futures_lite::Stream<Item = Result<(String, bool), DeviceError>> + Unpin {
        futures_lite::stream::iter(
            items
                .into_iter()
                .map(|(r, d)| Ok((r.to_string(), d)))
                .collect::<Vec<_>>(),
        )
    }

    fn wait(
        statuses: impl futures_lite::Stream<Item = Result<(String, bool), DeviceError>> + Unpin,
        cancel: &AtomicBool,
    ) -> (Result<(), DeviceError>, Vec<FingerStatus>) {
        let seen = std::cell::RefCell::new(Vec::new());
        let r = async_io::block_on(wait_for_match(statuses, cancel, &|s| {
            seen.borrow_mut().push(s)
        }));
        (r, seen.into_inner())
    }

    #[test]
    fn wait_reports_retries_then_matches() {
        let (r, seen) = wait(
            signals(vec![
                ("verify-swipe-too-short", false),
                ("verify-match", true),
            ]),
            &AtomicBool::new(false),
        );
        assert_eq!(r, Ok(()));
        assert_eq!(seen, [FingerStatus::Retry("Swipe longer.")]);
    }

    #[test]
    fn wait_reports_no_match() {
        let (r, seen) = wait(
            signals(vec![("verify-no-match", true)]),
            &AtomicBool::new(false),
        );
        assert_eq!(r, Err(no_match()));
        assert_eq!(seen, [FingerStatus::NoMatch]);
    }

    #[test]
    fn wait_ends_soon_after_cancel() {
        let cancel = AtomicBool::new(false);
        let start = Instant::now();
        let (r, _) = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cancel.store(true, Ordering::SeqCst);
            });
            wait(futures_lite::stream::pending(), &cancel)
        });
        assert_eq!(r, Err(DeviceError::Cancelled));
        assert!(start.elapsed() < Duration::from_secs(2));
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

# YubiKey and fingerprint unlock - design

**Date:** 2026-11-05 · **Status:** approved in chat, awaiting spec review

## Goal

Let the user unlock Deskauth with a YubiKey or a fingerprint, not only the master password, and let them pick how strict that is. Works on Linux, macOS and Windows. Linux is tested on real hardware (YubiKey 5, Goodix reader with `fprintd`); macOS and Windows are compiled in CI but not run.

## Modes

The user picks one mode in Settings > Unlock methods:

| Mode | Unlocks with | Slots in the file |
|---|---|---|
| `password` | the password | 1 password slot |
| `any` | the password, or any registered YubiKey, or the fingerprint | 1 password slot + 0..n YubiKey slots + 0..1 fingerprint slot |
| `password_yubikey` | the password **and** a registered YubiKey | 1..n two-factor slots (one per YubiKey) |

Rules:

- In `password` and `any` mode the password slot always exists and cannot be removed. The password is the recovery path.
- In `password_yubikey` mode there is no password-only, YubiKey-only or fingerprint slot, so nothing bypasses the second factor. The fingerprint is not available in this mode. With only one YubiKey registered, Settings shows a warning that losing it loses the vault.
- Every change to the mode or the methods needs an unlocked vault and proof the user holds what the new slots need (typing the password, touching each YubiKey, scanning the finger).
- The app refuses a change that would leave no way to unlock.

## Vault format v2

A random 32-byte **vault key** encrypts the accounts (XChaCha20-Poly1305, as today). Each slot holds the vault key wrapped by a key-encryption key (KEK) that only that unlock method can produce.

```json
{
  "version": 2,
  "mode": "any",
  "slots": [
    { "id": "…", "kind": "password", "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "b64" }, "nonce": "b64", "wrapped": "b64" },
    { "id": "…", "kind": "yubikey", "name": "Blue key", "credential_id": "b64", "salt": "b64(32)", "nonce": "b64", "wrapped": "b64" },
    { "id": "…", "kind": "fingerprint", "platform": "linux", "nonce": "b64", "wrapped": "b64" },
    { "id": "…", "kind": "password_yubikey", "name": "Blue key", "kdf": { … }, "credential_id": "b64", "salt": "b64(32)", "nonce": "b64", "wrapped": "b64" }
  ],
  "nonce": "b64",
  "ciphertext": "b64"
}
```

- The header (`version`, `mode`, `slots`, `nonce`) is the AAD of the account ciphertext, so slots and mode cannot be edited without the vault key.
- Each slot wraps the vault key with XChaCha20-Poly1305 under its KEK, a fresh 24-byte nonce, and AAD `"deskauth-slot-v2:" + kind + ":" + id`.
- Slot ids are random 16-byte values, base64.
- The Argon2id parameters stay fixed (64 MiB, t=3, p=1). Other values are rejected before the KDF runs, as in v1.

KEK per slot kind:

| Kind | KEK |
|---|---|
| `password` | Argon2id(password, kdf.salt) |
| `yubikey` | HKDF-SHA256(ikm = hmac-secret output, info = `"deskauth v2 yubikey"`) |
| `password_yubikey` | HKDF-SHA256(ikm = Argon2id(password, kdf.salt) ‖ hmac-secret output, info = `"deskauth v2 password+yubikey"`) |
| `fingerprint` | a random 32-byte secret kept by the OS (see below) |

### Upgrade from v1

Unlocking a v1 file with the password creates a vault key, re-encrypts the accounts, writes one password slot (new salt, same Argon2id settings), sets mode `password`, and saves atomically as v2. Only v1 and v2 are accepted.

## YubiKey (FIDO2 hmac-secret)

- **Enroll:** `makeCredential` with relying party id `deskauth`, the `hmac-secret` extension, non-resident credential, user presence only (no PIN, no user verification). Store the credential id and a random 32-byte salt in the slot. Then run one `getAssertion` with that salt to get the 32-byte hmac-secret output and build the slot. Each enrollment asks for a touch.
- **Unlock:** one `getAssertion` with every registered credential id in the allow list and each slot's salt. The returned credential id picks the slot. Touch timeout 30 s; the UI has Cancel.
- **Linux and macOS:** `ctap-hid-fido2` over USB HID.
- **Windows:** `webauthn.dll` through the `windows` crate (`WebAuthNAuthenticatorMakeCredential` / `GetAssertion` with hmac-secret salt values). Normal apps cannot open FIDO HID devices on Windows. If `WebAuthNGetApiVersionNumber()` is too old for hmac-secret, YubiKey options are hidden. Windows shows its own touch and PIN dialog.
- The KEK is the same only on the computer and library that enrolled it, which is fine because each computer has its own vault.

## Fingerprint

| Platform | Where the 32-byte secret lives | What enforces the fingerprint |
|---|---|---|
| Linux | system keyring (Secret Service, e.g. gnome-keyring), item `deskauth / <slot id>` | the app: `fprintd` D-Bus verify must report `verify-match` before the app reads the item |
| macOS | Keychain item with access control `biometryCurrentSet` | the Secure Enclave (Touch ID) |
| Windows | not stored: KEK = SHA-256(Windows Hello signature of the fixed challenge `"deskauth v2 fingerprint:" + slot id`) | Windows Hello (`KeyCredentialManager`, key name `deskauth-<slot id>`) |

- **Linux honesty note** (shown in Settings next to the switch): any program running as you can read the keyring item while you are logged in, so on Linux the fingerprint is convenience, not extra security.
- `fprintd` flow: `Manager.GetDefaultDevice` → `Device.Claim("")` → `VerifyStart("any")` → wait for `VerifyStatus` → `VerifyStop` → `Release`. `verify-no-match` and `verify-retry-*` show a message and let the user try again; a 30 s timeout cancels.
- Enabling the fingerprint verifies once, then creates the secret and the slot. Disabling deletes the slot and the OS item.
- If the OS item is gone (keyring reset, finger re-enrolled on macOS), fingerprint unlock fails with "Fingerprint unlock is no longer set up, use your password" and the slot stays until the user removes it in Settings.

## Code layout

- `vault.rs`: v2 format, slots, wrap/unwrap, v1 upgrade. No device code. Unlock functions take the KEK inputs (password, hmac output, fingerprint secret), not devices.
- `unlock/mod.rs`: traits the commands use, so tests can swap in fakes:
  - `trait HmacKey { fn enroll(&self) -> Result<Enrolled>; fn assert(&self, creds: &[(CredId, Salt)]) -> Result<(CredId, [u8; 32])>; fn available(&self) -> bool; }`
  - `trait Fingerprint { fn enable(&self, slot_id) -> Result<[u8; 32]>; fn unlock(&self, slot_id) -> Result<[u8; 32]>; fn disable(&self, slot_id) -> Result<()>; fn available(&self) -> bool; }`
- `unlock/fido_hid.rs` (Linux, macOS), `unlock/fido_windows.rs`, `unlock/finger_linux.rs`, `unlock/finger_macos.rs`, `unlock/finger_windows.rs`: one file per platform behind `#[cfg(target_os)]`.
- `commands.rs`: new commands below. Device calls run off the async runtime with `spawn_blocking`, never while holding the vault mutex.

## New commands and UI

Commands:

- `unlock_methods() -> { mode, yubikeys: [{id, name}], fingerprint: bool, can_yubikey: bool, can_fingerprint: bool }` (no secrets; works while locked)
- `vault_unlock_yubikey()`, `vault_unlock_fingerprint()`, `vault_unlock_two_factor(password)`
- `yubikey_add(name, password?)`: `password` is needed in `password_yubikey` mode
- `yubikey_remove(id)`, `fingerprint_enable()`, `fingerprint_disable()`
- `set_mode(mode, password)`: rebuilds the slots for the new mode and asks for each needed touch in turn
- `vault_change_password(current, new)`: in `password_yubikey` mode it asks for a touch per registered YubiKey
- Event `touch-needed { name }` so the UI can say "Touch Blue key"

UI:

- **Unlock screen:** the password field as today, plus "Use YubiKey" and "Use fingerprint" buttons when that mode and method exist and the device is there. In `password_yubikey` mode: type the password, then "Touch your YubiKey". Auto-lock returns here.
- **Settings > Unlock methods:** mode choice (3 options with one-line explanations), YubiKey list with name and Remove, "Add YubiKey" (asks a name, then a touch), fingerprint switch with the Linux note, warnings for a single YubiKey in two-factor mode.
- All user-facing errors are plain sentences, e.g. "No YubiKey found. Plug it in and try again."

## Errors and edge cases

- No device, wrong device (credential not in the vault), timeout, cancelled touch, unplugged mid-touch: clear message, vault stays locked, nothing written.
- Saving after any slot change is atomic (temp file + rename), as today. If enrolling succeeds on the device but saving fails, the vault is unchanged; on Linux and macOS the orphan OS item is deleted.
- Removing a YubiKey does not touch the key itself (non-resident credentials leave nothing on it).
- Unknown slot kinds or modes in the file are rejected as damaged.

## Testing

- Unit tests in `vault.rs` with plain byte inputs: each slot kind round-trips; wrong password / wrong hmac output / wrong fingerprint secret fail with the right error; header or slot edits fail AAD; v1 file upgrades and still opens with the password; `password_yubikey` cannot be opened by password alone or hmac alone; last-way-to-unlock rule.
- Command-level tests with fake `HmacKey` and `Fingerprint`: mode switches build the right slots, removals keep the rules, timeout and no-device paths leave the file unchanged.
- Linux by hand with the real YubiKey and finger: enroll, unlock, wrong key, timeout, two-factor mode, switch back, upgrade of the real v1 vault (after a backup copy made by the user).
- CI: add `cargo check` (and `cargo clippy`) jobs on `macos-latest` and `windows-latest`. The README marks macOS and Windows YubiKey/fingerprint unlock as untested until someone runs them.

## New dependencies

`ctap-hid-fido2` (Linux, macOS), `keyring` (Linux, Secret Service backend), `zbus` (Linux, already in the tree as 5.x via Tauri), `security-framework` (macOS), `windows` (Windows, already in the tree as 0.62 via Tauri), `hkdf` + `sha2`.

## Out of scope

- FIDO2 PIN / user verification (touch only for now).
- Unlocking with a phone, smart cards (PIV), or YubiKey OTP challenge-response.
- Syncing vaults between computers.

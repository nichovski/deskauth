# Desktop Authenticator - Design

Date: 2026-11-03
Status: draft, waiting for review

## Goal

A desktop TOTP app for Linux, Windows and macOS, so codes can be read without taking out the phone.
It imports accounts from Google Authenticator, is locked by a master password, and follows the Omarchy theme on Linux.

Working name: **Deskauth** (binary `deskauth`). The name must not include "Google" (trademark).

## Requirements

What the user asked for:

- Runs on Linux (Omarchy), Windows and macOS.
- Master password chosen on first run, needed to unlock.
- Accounts imported from Google Authenticator.
- "Re-import" any time: a new Google export is merged, existing accounts are skipped.
- Each computer imports on its own. Nothing is synced between computers or over the network.
- Public GitHub repo. Builds are for the author's own use. No code signing, no auto-update. Others build and sign it themselves.
- Follows the Omarchy theme.

Assumptions (correct these if wrong):

- One vault per computer, one user.
- TOTP only (SHA1/SHA256/SHA512, 6 or 8 digits, any period). No HOTP.
- Losing the master password means deleting the vault and importing again from the phone. No recovery.

Success criteria:

- Fresh install: set a password, import a Google export, see codes that match the phone.
- Re-importing the same export adds 0 accounts. Adding one account on the phone and re-importing adds exactly 1.
- Restart the app: it asks for the password, a wrong password fails, the right one shows the codes.
- On Omarchy, switching theme recolors the open app within about 1 second.
- Builds for all 3 OSes come from CI on a tag.

## Out of scope

Cloud or device-to-device sync, HOTP, multiple vaults, browser extension, password recovery, code signing, auto-update, export to other apps.

## Facts this design depends on

- Google Authenticator has no API. Its cloud backup is not readable by third parties. The only way out is
  "Transfer accounts > Export accounts", which shows one or more QR codes with an
  `otpauth-migration://offline?data=<base64 protobuf>` URL. Large account lists are split into several QR codes (batch fields in the payload).
- Android Google Authenticator blocks screenshots of the export screen. So the main import path is **scanning the phone screen with the computer's camera**. Image file import is a second path (iOS, or a photo taken with another device).
- Omarchy keeps the current theme at `~/.local/state/omarchy/current/theme/colors.toml`. `current` is a symlink that changes on theme switch. Keys used: `background`, `lighter_background`, `foreground`, `dark_foreground`, `bright_foreground`, `accent`, `selection`, `muted`, `red`, `yellow`, `green`, `mode`.

## Architecture

Tauri 2 app. Rust holds all secrets and logic. The web UI only shows what Rust sends it.

```
src-tauri/src/
  main.rs        Tauri setup, command wiring
  vault.rs       encrypted file: create, unlock, save, lock
  totp.rs        code generation (RFC 6238)
  migration.rs   decode otpauth-migration:// and otpauth:// URLs
  merge.rs       merge imported accounts into the vault
  qr.rs          decode QR from an image or a camera frame
  camera.rs      open camera, stream frames, stop
  theme.rs       read + watch Omarchy colors.toml, emit palette
  commands.rs    thin Tauri commands calling the modules above
src/             TypeScript + Vite, no UI framework
  main.ts, views (setup, unlock, list, import, add), theme.css
```

Each Rust module has one job and no Tauri types, except `commands.rs` and `main.rs`. That keeps them unit-testable.

### Crates

`argon2`, `chacha20poly1305`, `zeroize`, `rand`, `serde`/`serde_json`, `base32`, `hmac` + `sha1` + `sha2`,
`prost` (message structs written by hand with derive, so no `protoc` is needed), `url`, `base64`,
`rqrr` + `image` (QR), `nokhwa` (camera), `notify` (file watch), `toml`, `arboard` with the `wayland-data-control` feature (clipboard, needed on Hyprland).
Tauri plugins: dialog (file picker), single-instance.

## Components

### 1. Vault (`vault.rs`)

- File: `<app data dir>/vault.json` (Tauri `app_data_dir`, e.g. `~/.local/share/deskauth/` on Linux).
- Format:
  ```json
  { "version": 1,
    "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "<b64 16B>" },
    "nonce": "<b64 24B>",
    "ciphertext": "<b64>" }
  ```
- Key = Argon2id(password, salt) -> 32 bytes. Ciphertext = XChaCha20-Poly1305 of the JSON account list. The header JSON is passed as associated data, so changing the KDF parameters breaks decryption.
- Each save uses a new random nonce. Writes go to a temp file, then rename (atomic). The file gets mode 0600 on Unix.
- Unlocked state: key and accounts in memory, wrapped in `Zeroizing`. Lock drops both.
- Auto-lock after 5 minutes without user input (UI sends activity pings; Rust holds the timer). Also a manual lock button.
- Wrong password = decryption fails -> "Wrong password". No lockout or attempt counter (local file, offline attack is possible anyway; Argon2 cost is the defense).
- Change master password: unlock, ask for the new one twice, re-encrypt with a new salt.

Account record:

```json
{ "id": "<uuid>", "issuer": "GitHub", "name": "user@example.com",
  "secret": "<base32>", "algorithm": "SHA1", "digits": 6, "period": 30 }
```

### 2. TOTP (`totp.rs`)

`code(account, unix_time) -> String` and `remaining_seconds(period, unix_time)`. HMAC per RFC 4226/6238, zero-padded to `digits`.

### 3. Import (`migration.rs`, `merge.rs`, `qr.rs`, `camera.rs`)

- `migration.rs` parses:
  - `otpauth-migration://offline?data=...` -> list of accounts. Maps the enum values for algorithm/digits. Skips HOTP entries and reports how many were skipped. Reads `batch_size`/`batch_index`.
  - `otpauth://totp/Issuer:name?secret=...&issuer=...&algorithm=...&digits=...&period=...` -> one account.
- `merge.rs`: an account is a duplicate if the decoded secret bytes match an existing one (issuer/name can differ between exports, the secret can't). Returns `{added, skipped_duplicates, skipped_hotp}`.
- Multi-QR exports: the import screen keeps scanning and shows "batch 2 of 3 scanned" until all batches are in, then merges once. The user can also finish early.
- `qr.rs`: grayscale image -> `rqrr` -> list of strings.
- `camera.rs`: `nokhwa` opens the default camera (a picker if there are several). Frames are decoded in Rust about 5 times a second. A downscaled JPEG preview goes to the UI so the user can aim. The camera stops as soon as the import finishes or the screen closes.
- Image path: file picker or drag-and-drop -> `qr.rs`.

### 4. Add one account

Same camera/image screen, accepting `otpauth://` QR codes. Plus a manual form: issuer, name, secret (base32), advanced (algorithm, digits, period) collapsed.

### 5. Main screen

- List: issuer, name, current code (grouped `123 456`), countdown ring per period.
- Search box focused on open. Typing filters. Enter copies the top match. Click a row copies it.
- Clipboard is cleared after 30 seconds, only if it still holds the copied code.
- Row menu: rename (issuer/name), delete (with confirm).
- Codes are computed in Rust and sent to the UI once a second. Secrets never reach the UI.
- Single instance: launching again focuses the open window. On Omarchy this lets a Hyprland keybind open it instantly (bind setup is up to the user, documented in the README).

### 6. Theme (`theme.rs`)

- Linux: if `~/.local/state/omarchy/current/theme/colors.toml` exists, read it and emit a palette to the UI as CSS variables. Watch the `current` directory (not the file, since the symlink target changes) and re-emit on change, debounced to about 200 ms.
- Missing keys fall back to the Tokyo Night value of the same key.
- Not Omarchy, Windows, macOS: built-in Tokyo Night palette.
- UI uses only CSS variables (`--bg`, `--bg-alt`, `--fg`, `--fg-dim`, `--fg-bright`, `--accent`, `--selection`, `--muted`, `--danger`, `--warn`, `--ok`). Font: the system monospace font for codes, system UI font for the rest.

### 7. Error handling

- All Tauri commands return `Result<T, String>` with short, user-facing messages ("Wrong password", "No QR code found in image", "Camera not available").
- Corrupt or unreadable vault file: show the error and offer "Delete vault and start over" (with confirm). Never overwrite silently.
- Camera missing or no permission: say so and point to image import.

## Testing

Rust unit tests (`cargo test`):

- `totp.rs`: RFC 6238 test vectors for SHA1, SHA256, SHA512.
- `migration.rs`: a known Google export URL (built from test secrets) decodes to the expected accounts. HOTP entries are skipped. `otpauth://` parsing including defaults.
- `merge.rs`: same import twice adds 0. One new account adds 1. A renamed account with the same secret counts as a duplicate.
- `vault.rs`: create -> save -> unlock round trip. Wrong password fails. A changed header byte fails. Change password works.
- `qr.rs`: a generated QR PNG fixture decodes to the expected string.
- `theme.rs`: parsing a fixture `colors.toml`, missing keys fall back.

Manual check in the real app on Omarchy: first run, camera import from a real phone export, codes match the phone, re-import, auto-lock, theme switch.

## Repo and CI

- Public GitHub repo, MIT license.
- GitHub Actions: `cargo test` + `cargo clippy` + frontend typecheck on every push.
- On a `v*` tag: `tauri-action` builds unsigned packages (Linux AppImage + .deb, Windows .msi, macOS .dmg) and attaches them to a GitHub release.
- README: what it does, the security trade-off (codes on the same computer as passwords), how to import from Google Authenticator, how to build, how to sign your own build on macOS/Windows, the optional Hyprland keybind. Also states that macOS will warn about the unsigned app.
- Arch: a `PKGBUILD` in the repo for local install on Omarchy.

## Open questions

None blocking. Name "Deskauth" can change before the repo is created.

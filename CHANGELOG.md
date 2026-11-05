# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- Unlock with a YubiKey (FIDO2 touch) or fingerprint, in three modes: password only, any one method, or password and YubiKey together. Vault file v2 with key slots; v1 files upgrade on the next password unlock.
- App icon (countdown ring and keyhole) replacing the Tauri template icons, a scalable icon in the Arch package, and README screenshots in eight Omarchy themes with a platform table.
- Deskauth: a desktop TOTP authenticator for Linux, Windows and macOS, so codes no longer need the phone.
- Import from Google Authenticator's export QR, by camera or image file, including exports split over several QR codes. Re-import merges and skips accounts you already have.
- Add a single account by `otpauth://` QR or by typing the secret.
- Master password set on first run. The vault is encrypted with Argon2id and XChaCha20-Poly1305 and is never sent to the UI.
- Code list with search, Enter or click to copy, countdown rings. Copied codes are kept out of clipboard history and cleared after 30 seconds.
- Auto-lock after 5 minutes of no use, including time the computer was asleep.
- Rename and delete accounts, change the master password, and reset a damaged vault.
- Follows the current Omarchy theme on Linux and updates live on theme switch. Tokyo Night elsewhere.
- CI on every push, unsigned release builds on `v*` tags, an Arch `PKGBUILD`, and a README with build and signing steps.

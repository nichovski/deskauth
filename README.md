<p align="center"><img src="src-tauri/icons/icon.svg" width="112" alt="Deskauth icon"></p>

# Deskauth

A desktop TOTP authenticator. It imports your accounts from Google Authenticator and shows the 6 or 8 digit codes on your computer, so you don't need your phone for 2FA. Built with Tauri 2 (Rust backend, TypeScript UI). MIT license.

**Runs on Linux, Windows and macOS.** On Omarchy it follows your theme and changes live when you switch themes.

Not affiliated with Google.

<p align="center"><img src="docs/screenshots/list-tokyo-night.png" width="320" alt="Deskauth code list"> <img src="docs/screenshots/unlock-tokyo-night.png" width="320" alt="Deskauth unlock screen"></p>

## Omarchy themes

The colors come from the current Omarchy theme (`~/.local/state/omarchy/current/theme/colors.toml`). On other systems it uses Tokyo Night.

![Deskauth in eight Omarchy themes](docs/screenshots/themes.png)

Screenshots use demo accounts.

## Platforms

| System | How to get it |
|---|---|
| Linux (Arch / Omarchy) | `makepkg` from `packaging/arch`, see [Install on Arch](#install-on-arch) |
| Linux (other) | AppImage, .deb or .rpm from a release, or [build from source](#build-from-source) |
| Windows | .msi or .exe installer from a release, or build from source |
| macOS | .dmg from a release, or build from source |

Release builds are unsigned, see [Releases](#releases).

## Security trade-off

Read this before you use it.

- The codes live on the same computer as your passwords. If someone gets into this computer, they get both factors.
- The vault is an encrypted file (Argon2id key derivation, XChaCha20-Poly1305). What opens it depends on the unlock mode: the password alone, the password or a YubiKey or your fingerprint, or the password and a YubiKey together. See [Unlock with a YubiKey or fingerprint](#unlock-with-a-yubikey-or-fingerprint).
- There is no recovery. If none of your ways in works any more (for example you forget the password and have no YubiKey or fingerprint set up, or in "Password and YubiKey together" you lose the password or every key), the vault cannot be opened. Delete the vault file (`vault.json`, see below) and import your accounts again.
- The app locks itself after 5 minutes of no use. A copied code is cleared from the clipboard after 30 seconds.

## Unlock with a YubiKey or fingerprint

Settings > Unlock methods has three modes:

- **Password only.** Only the master password opens the vault.
- **Password, YubiKey or fingerprint.** Any one of them opens the vault. The password always works, so it is your way back in.
- **Password and YubiKey together.** You need the password and a touch of a registered YubiKey. Nothing else opens the vault. Register a backup key: if you lose your only key, you lose the vault.

The YubiKey uses FIDO2 `hmac-secret` with a touch only. Adding a YubiKey asks for your current password, and a key that is already registered is refused. If the key has a FIDO2 PIN, type it in the "YubiKey PIN" field when you register the key. Unlocking never asks for the PIN, only for a touch.

In "Password, YubiKey or fingerprint" the lock screen listens by itself: it starts a fingerprint scan as soon as it shows, and asks for a touch when a registered YubiKey is plugged in. You can type the password at the same time. On Windows the YubiKey still needs a click on "Use YubiKey", so its dialog does not pop up by itself.

- Linux needs the usual udev rules for FIDO keys. On Arch the `libfido2` package provides them.
- Windows needs Windows 11 22H2 or later (WebAuthn API v4) for the YubiKey. Windows shows its own touch dialog. The fingerprint uses Windows Hello.
- macOS uses Touch ID for the fingerprint. It needs a signed build with the `keychain-access-groups` entitlement. Unsigned builds show "Touch ID unlock needs a signed build of Deskauth."
- macOS and Windows unlock methods are untested on real hardware so far.

On Linux the fingerprint is convenience, not extra security: the secret it guards sits in your keyring, and any program running as you can read it while you are logged in.

Removing a lost YubiKey does not protect old copies of `vault.json`. An old copy plus that key still opens the accounts that existed then. Switching into or out of "Password and YubiKey together" makes a fresh vault key.

The first unlock with this version upgrades `vault.json` to the new format (v2). Older Deskauth versions cannot open a v2 vault, so keep a backup of `vault.json` before that first unlock.

## Import from Google Authenticator

Google has no API, so the import uses the export screen of the phone app.

1. On the phone: Google Authenticator > menu > Transfer accounts > Export accounts. Pick the accounts.
2. In Deskauth: click Import / Re-import and scan the QR code on the phone screen with the computer camera.
3. Large lists are split into several QR codes. Scan each one.

Android blocks screenshots of the export screen, so use the camera there. iOS allows screenshots, so on iOS you can also import from an image file.

Importing again is safe. It merges into the vault and skips accounts that are already there (matched by secret).

## Build from source

Needs Node.js 22, Rust (stable) and the Tauri Linux libraries. On Debian/Ubuntu:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev libv4l-dev
```

Then:

```bash
npm ci
npm run tauri build
```

Packages are written to `src-tauri/target/release/bundle/`.

On Windows you need the Visual Studio C++ build tools and WebView2 (built into Windows 10 and 11). On macOS you need the Xcode command line tools. See https://v2.tauri.app/start/prerequisites/

## Install on Arch

```bash
cd packaging/arch && makepkg -si
```

This builds from the local checkout and installs `deskauth` to `/usr/bin`.

If your Rust or Node come from rustup or mise (not pacman), run `makepkg -fid` instead. The `-d` flag skips the dependency check, which would otherwise fail on the missing `rust` and `npm` packages.

## Releases

Pushing a `v*` tag builds unsigned packages (bundle targets are "all", so Linux gets AppImage, .deb and .rpm, Windows gets .msi and the NSIS .exe installer, macOS gets .dmg) and attaches them to a draft GitHub release.

macOS will warn that the app is from an unidentified developer because the release is not signed. To open it: right-click the app, choose Open, then confirm. Windows may show a SmartScreen warning for the same reason.

## Sign your own build

Releases are unsigned. To sign a build yourself, follow the Tauri guides:

- Windows: set `bundle.windows.certificateThumbprint` in `src-tauri/tauri.conf.json` and sign with `signtool`. See https://v2.tauri.app/distribute/sign/windows/
- macOS: set `APPLE_SIGNING_IDENTITY` and the notarization environment variables, then build. See https://v2.tauri.app/distribute/sign/macos/

## Hyprland keybind (optional)

Only one instance runs. Starting `deskauth` again focuses the open window, so a bind works as a toggle-to-front key:

```
bind = SUPER, A, exec, deskauth
```

## Where the vault is stored

The file is `vault.json`, in the Tauri app data directory for the identifier `dev.nichovski.deskauth`:

- Linux: `~/.local/share/dev.nichovski.deskauth/`
- macOS: `~/Library/Application Support/dev.nichovski.deskauth/`
- Windows: `%APPDATA%\dev.nichovski.deskauth\`

On Omarchy the app also follows the current theme colors.

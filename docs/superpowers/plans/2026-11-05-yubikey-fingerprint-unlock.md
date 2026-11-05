# YubiKey and Fingerprint Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the user unlock the Deskauth vault with a YubiKey (FIDO2 hmac-secret) or fingerprint, in one of three modes, on Linux, macOS and Windows.

**Architecture:** Vault format v2 encrypts accounts with a random vault key; key slots wrap that key under per-method KEKs (`vault.rs`, pure, no devices). Device access sits behind two traits in `unlock/` with one file per platform and fakes for tests. `commands.rs` glues them, running device calls off the async runtime and never under the vault mutex.

**Tech Stack:** Rust (Tauri 2), XChaCha20-Poly1305, Argon2id, HKDF-SHA256, `ctap-hid-fido2` 3.6, `keyring` 3, `zbus` 5, `security-framework` 3, `windows` 0.62; TypeScript UI (no framework).

**Spec:** `docs/superpowers/specs/2026-11-05-yubikey-fingerprint-unlock-design.md`

## Global Constraints

- Modes are exactly `password`, `any`, `password_yubikey` (serde `snake_case`). Slot kinds are exactly `password`, `yubikey`, `fingerprint`, `password_yubikey`.
- Argon2id fixed at m=65536 KiB, t=3, p=1, 16-byte salt, 32-byte output; any other value is rejected before the KDF runs.
- Vault key, KEKs, hmac outputs and fingerprint secrets: 32 bytes, held in `Zeroizing`, never logged, never sent to the UI, never in `Debug` output.
- Slot wrap: XChaCha20-Poly1305, fresh 24-byte nonce, AAD = `"deskauth-slot-v2:" + kind + ":" + id`. File AAD = JSON of `{version, mode, slots, nonce}` in that field order.
- HKDF info strings verbatim: `"deskauth v2 yubikey"`, `"deskauth v2 password+yubikey"`. Windows Hello challenge verbatim: `"deskauth v2 fingerprint:" + slot_id`.
- FIDO2 relying party id: `deskauth`. User presence only, no PIN, no UV, non-resident credentials. Touch timeout 30 s. Fingerprint timeout 30 s.
- Only v1 and v2 files are accepted; v1 is upgraded to v2 on password unlock.
- In `password` and `any` the password slot always exists. In `password_yubikey` only `password_yubikey` slots exist (at least one). No change may leave zero ways to unlock.
- No Argon2 run and no device call while holding `state.vault`'s mutex.
- Writes stay atomic (`write_atomic`, mode 0600).
- No network code. No new UI framework. User-facing errors are plain sentences.
- Never silence checks (`#[allow]` on clippy lints, `@ts-ignore`, `as any`). `cargo clippy -- -D warnings` and `npx tsc --noEmit` stay clean.
- Agents must not touch a real YubiKey, fingerprint reader, camera or the user's real vault, and must not send synthetic keyboard or pointer input. Hardware steps are done by the user (Task 10).

## Review Focus

1. **A YubiKey that is plugged in but not registered** (or a second FIDO device): unlock must say "This YubiKey is not registered for this vault", not hang or pick the wrong slot. Test with a fake returning an unknown credential id (Task 4).
2. **Upgrading the user's real v1 vault**: a v1 file must open with the password, be rewritten as v2 with identical accounts, and still open with the same password afterwards; a failed save leaves the v1 file untouched (Task 1).
3. **Switching out of `password_yubikey` mode with the wrong password or wrong key**: nothing is written, the old mode still works (Task 2).
4. **Fingerprint slot whose OS secret is gone** (keyring cleared): unlock fails with the "no longer set up" message and the password still works; the slot can be removed (Task 4).
5. **Touch timeout or Cancel while the vault mutex would be needed by the 1 s code poll**: the UI keeps working (codes keep refreshing when unlocked, e.g. during Add YubiKey) because no lock is held during the device call (Task 4).

---

### Task 1: Vault v2 format, password slot, v1 upgrade

**Files:**
- Modify: `src-tauri/src/vault.rs`
- Modify: `src-tauri/Cargo.toml` (add `hkdf = "0.12"`)

**Interfaces:**
- Produces (all in `vault.rs`):
  - `#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)] #[serde(rename_all = "snake_case")] pub enum Mode { Password, Any, PasswordYubikey }`
  - `enum Slot` (private, `#[serde(tag = "kind", rename_all = "snake_case")]`) with variants `Password { id, kdf, nonce, wrapped }`, `Yubikey { id, name, credential_id, salt, nonce, wrapped }`, `Fingerprint { id, platform, nonce, wrapped }`, `PasswordYubikey { id, name, kdf, credential_id, salt, nonce, wrapped }` (all byte fields base64 strings in the file).
  - `pub struct PasswordKek { salt: [u8; 16], kek: Zeroizing<[u8; 32]> }` and `pub fn PasswordKek::derive(password: &str) -> Result<PasswordKek, VaultError>` (fresh salt; the slow part, called outside the lock).
  - `pub enum Secret<'a> { Password(&'a str), Yubikey { credential_id: &'a [u8], hmac: &'a [u8; 32] }, Fingerprint { secret: &'a [u8; 32] }, PasswordYubikey { password: &'a str, credential_id: &'a [u8], hmac: &'a [u8; 32] } }`
  - `pub fn unlock_with(path: &Path, secret: Secret) -> Result<Vault, VaultError>` (Task 1 implements `Secret::Password` incl. v1 upgrade; other variants return `WrongPassword` until Task 2)
  - `pub fn unlock(path, password)` stays as a thin wrapper over `unlock_with(Secret::Password)`.
  - `pub fn create(path, password)` writes v2, mode `password`, one password slot.
  - `impl Vault { pub fn mode(&self) -> Mode; pub fn set_password(&mut self, kek: PasswordKek) -> Result<(), VaultError> }` replacing `apply_new_key`/`derive_new_key`/`NewKey` (`set_password` rewraps only the password slot; on failed save the old slot comes back).
  - New `VaultError` variants: `NotRegistered` ("This YubiKey is not registered for this vault"), `NotAllowed(String)` (rule violations, message given).

- [ ] **Step 1: Write the failing tests** in `vault.rs` tests: `create_writes_v2` (JSON has `version == 2`, `mode == "password"`, one slot of kind `password`); `round_trip_v2`; `wrong_password_v2`; `tampered_slot_fails` (edit a slot's `id` in the JSON → `WrongPassword` or `Corrupt`, never success); `tampered_mode_fails` (change `mode` → fails); `v1_upgrades_on_unlock` (write a v1 file with the old format - keep a private test helper `write_v1(path, password, accounts)` that reproduces the v1 writer - then `unlock` returns the same accounts, the file is now v2, and `unlock` again with the same password works); `v1_wrong_password_leaves_file` (bytes unchanged); `unknown_version_is_corrupt` (version 3); `set_password_rewraps` (old password fails, new works, accounts unchanged); `failed_set_password_keeps_old` (adapt the existing `failed_apply_keeps_old_key`); `bad_kdf_rejected_v2` (m_kib changed → `Corrupt` before KDF).
- [ ] **Step 2: Run** `cargo test --manifest-path src-tauri/Cargo.toml vault::` → new tests FAIL.
- [ ] **Step 3: Implement** the v2 file (`VaultFileV2 { version, mode, slots, nonce, ciphertext }`, `HeaderV2 { version, mode, slots, nonce }` for AAD), `wrap(kek, kind, id, vault_key) -> (nonce, wrapped)` / `unwrap(...)`, `Vault { accounts, path, vault_key, mode, slots }`, the v1 reader kept as a private function used only by the upgrade path. Upgrade: decrypt v1, make vault key + password slot from the same password (new salt), save v2 atomically, return the vault.
- [ ] **Step 4: Run** the vault tests and the full suite → PASS. `cargo clippy -- -D warnings` clean. Update `commands::vault_change_password` to `PasswordKek::derive` + `set_password` (same lock discipline as today).
- [ ] **Step 5: Commit** `feat(vault): v2 format with key slots and v1 upgrade`.

### Task 2: YubiKey, two-factor and fingerprint slots, mode changes

**Files:**
- Modify: `src-tauri/src/vault.rs`

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `pub struct TwoFactorKek` and `pub fn TwoFactorKek::derive(password: &str, hmac: &[u8; 32]) -> Result<TwoFactorKek, VaultError>` (fresh Argon2 salt; KEK = HKDF-SHA256(ikm = argon ‖ hmac, info `"deskauth v2 password+yubikey"`)).
  - `pub struct YubikeyInfo { pub id: String, pub name: String, pub credential_id: Vec<u8>, pub salt: [u8; 32] }`
  - `pub struct VaultInfo { pub mode: Mode, pub yubikeys: Vec<YubikeyInfo>, pub fingerprint: Option<String /* slot id */>, pub version: u32 }` and `pub fn read_info(path: &Path) -> Result<VaultInfo, VaultError>` (reads the file without any secret; for the locked screen and for building assertions). For v1 files: mode `password`, no keys.
  - On `Vault`: `pub fn info(&self) -> VaultInfo`;
    `pub fn add_yubikey(&mut self, name: &str, credential_id: &[u8], salt: [u8; 32], hmac: &[u8; 32]) -> Result<String, VaultError>` (mode `any` only);
    `pub fn add_yubikey_two_factor(&mut self, name: &str, credential_id: &[u8], salt: [u8; 32], kek: TwoFactorKek) -> Result<String, VaultError>` (mode `password_yubikey` only);
    `pub fn set_fingerprint(&mut self, slot_id: &str, platform: &str, secret: &[u8; 32]) -> Result<(), VaultError>` (mode `any` only, replaces an existing fingerprint slot; `slot_id` is chosen by the caller because the OS item is named after it - provide `pub fn new_slot_id() -> String`);
    `pub fn remove_slot(&mut self, id: &str) -> Result<(), VaultError>` (refuses the password slot and the last `password_yubikey` slot with `NotAllowed`);
    `pub fn to_password_mode(&mut self) -> Result<Vec<String>, VaultError>` (from `any`: drops yubikey + fingerprint slots, returns removed fingerprint slot ids so the caller deletes OS items);
    `pub fn to_any_mode(&mut self, kek: Option<PasswordKek>) -> Result<(), VaultError>` (from `password`: flips mode, `kek` None; from `password_yubikey`: `kek` required, replaces all slots with one password slot);
    `pub fn to_two_factor_mode(&mut self, name: &str, credential_id: &[u8], salt: [u8; 32], kek: TwoFactorKek) -> Result<Vec<String>, VaultError>` (from `password`/`any`: replaces all slots with one `password_yubikey` slot; returns removed fingerprint slot ids);
    `pub fn change_password_two_factor(&mut self, keks: Vec<(String /* slot id */, TwoFactorKek)>) -> Result<(), VaultError>` (must cover every `password_yubikey` slot, else `NotAllowed`).
  - `unlock_with` handles all `Secret` variants: `Yubikey` finds the `yubikey` slot by credential id (none → `NotRegistered`); `PasswordYubikey` finds by credential id then derives with that slot's salt; `Fingerprint` tries the single fingerprint slot. Each variant is only valid in modes where its slot kind exists, otherwise `NotAllowed("... is not enabled for this vault")`.
  - Every mutating method saves atomically and restores the previous slots/mode if the save fails.

- [ ] **Step 1: Write the failing tests:** `yubikey_slot_round_trip`; `yubikey_wrong_hmac_fails`; `unknown_credential_is_not_registered`; `two_factor_needs_both` (password alone → `NotAllowed`, hmac alone → `NotAllowed`, wrong password with right hmac → `WrongPassword`, both right → ok); `fingerprint_round_trip_and_wrong_secret`; `fingerprint_refused_in_two_factor_mode`; `cannot_remove_password_slot`; `cannot_remove_last_two_factor_slot`; `to_two_factor_drops_other_slots` (old password no longer opens; returned ids include the fingerprint slot); `to_any_from_two_factor_needs_kek` (None → `NotAllowed`); `to_password_mode_drops_methods`; `change_password_two_factor_must_cover_all`; `failed_save_restores_slots` (make the vault dir read-only on unix, call `add_yubikey`, expect `Io` and the in-memory slots unchanged); `read_info_has_no_secrets` (serialize `VaultInfo`-equivalent fields; assert only ids, names, credential ids, salts and mode).
- [ ] **Step 2: Run** `cargo test --manifest-path src-tauri/Cargo.toml vault::` → FAIL.
- [ ] **Step 3: Implement** the methods above. Yubikey KEK = HKDF-SHA256(ikm = hmac, info `"deskauth v2 yubikey"`), computed inside `vault.rs` (cheap).
- [ ] **Step 4: Run** full tests + clippy → PASS.
- [ ] **Step 5: Commit** `feat(vault): YubiKey, two-factor and fingerprint slots`.

### Task 3: Device traits and fakes

**Files:**
- Create: `src-tauri/src/unlock/mod.rs`
- Modify: `src-tauri/src/lib.rs` (`mod unlock;`)

**Interfaces:**
- Produces:
  - `#[derive(Debug, PartialEq)] pub enum DeviceError { NoDevice, NoReader, NoCredential, Timeout, Cancelled, NotSetUp, Unsupported(String), Other(String) }` with `Display` messages, in order: "No YubiKey found. Plug it in and try again." / "No fingerprint reader found." / "This YubiKey is not registered for this vault." / "Timed out waiting. Try again." / "Cancelled." / "Fingerprint unlock is no longer set up, use your password." / the given text / "Device error: {0}". Task 4 maps `NoCredential` to `VaultError::NotRegistered`.
  - `pub struct Enrolled { pub credential_id: Vec<u8>, pub salt: [u8; 32], pub hmac: Zeroizing<[u8; 32]> }`
  - `pub trait HmacKey: Send + Sync { fn available(&self) -> bool; fn enroll(&self) -> Result<Enrolled, DeviceError>; fn assert(&self, allowed: &[(Vec<u8>, [u8; 32])]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), DeviceError>; }` - `enroll` creates the credential, makes a random salt and runs one assertion to return its hmac (two touches on HID devices); `assert` returns the credential id that answered and its output.
  - `pub trait Fingerprint: Send + Sync { fn available(&self) -> bool; fn platform(&self) -> &'static str; fn enable(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError>; fn unlock(&self, slot_id: &str) -> Result<Zeroizing<[u8; 32]>, DeviceError>; fn disable(&self, slot_id: &str) -> Result<(), DeviceError>; }`
  - `pub fn platform_hmac_key() -> Box<dyn HmacKey>` and `pub fn platform_fingerprint() -> Box<dyn Fingerprint>` (cfg-selected; until Tasks 5-8 land they return a stub whose `available()` is false and every call is `Unsupported`).
  - `#[cfg(test)] pub mod fake` with `FakeKey { creds: Mutex<Vec<(Vec<u8>, [u8;32] /*device secret*/)>>, next: Mutex<Option<DeviceError>> }` computing hmac = HMAC-SHA256(device secret, salt) so different salts/keys give different outputs, and `FakeFinger { store: Mutex<HashMap<String, [u8;32]>>, next: Mutex<Option<DeviceError>> }`.

- [ ] **Step 1: Write failing tests** for the fakes: `fake_same_salt_same_hmac`; `fake_other_salt_differs`; `fake_assert_unknown_allow_list_is_no_credential` (allow list with no credential the fake holds → `Err(DeviceError::NoCredential)`); `fake_queued_error_returned_once`; `fake_finger_disable_then_unlock_is_not_set_up`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS, clippy clean.
- [ ] **Step 5: Commit** `feat(unlock): device traits, stubs and fakes`.

### Task 4: Commands for unlock methods

**Files:**
- Modify: `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces:
  - `AppState` gains `pub hmac_key: Box<dyn HmacKey>`, `pub fingerprint: Box<dyn Fingerprint>`; `AppState::new(vault_path)` uses the platform constructors; add `AppState::with_devices(path, key, finger)` for tests.
  - Serializable `UnlockMethods { mode: Mode, yubikeys: Vec<{id, name}>, fingerprint: bool, can_yubikey: bool, can_fingerprint: bool, platform: &'static str }` (`platform` from `Fingerprint::platform()`).
  - Commands (all `async`, device and Argon2 work in `tauri::async_runtime::spawn_blocking`, no vault mutex held during it): `unlock_methods`, `vault_unlock_yubikey`, `vault_unlock_fingerprint`, `vault_unlock_two_factor(password)`, `yubikey_add(name, password: Option<String>)`, `yubikey_remove(id)`, `fingerprint_enable`, `fingerprint_disable`, `set_mode(mode, password: Option<String>, name: Option<String>)`, and `vault_change_password` extended for `password_yubikey` mode (one `assert` per slot, emitting `touch-needed` with the slot name before each).
  - Emit `touch-needed { name: Option<String> }` (Tauri event) before every `enroll`/`assert`.
  - Put the logic in plain functions taking `&AppState` (and an `emit: &dyn Fn(Option<&str>)`) so tests call them without Tauri; the `#[tauri::command]` wrappers only adapt.
  - Credential lookup: an `assert` that returns a credential id not in the vault maps to `VaultError::NotRegistered`.
  - Verification rules for `set_mode` (spec "proof the user holds what the new slots need"): `password → any`: nothing; `any → password`: nothing (vault already unlocked); `→ password_yubikey`: `password` must open the current vault via `unlock_with(Password)` on the file (outside the lock), then `enroll`; leaving `password_yubikey`: `assert` + `password` must open via `unlock_with(PasswordYubikey)`, then `PasswordKek::derive(new password = same password)`. After a mode change that removed fingerprint slots, call `fingerprint.disable` for each (errors ignored, logged nowhere).
  - `fingerprint_enable`: new slot id → `fingerprint.enable(id)` → `set_fingerprint`; if the save fails, call `disable(id)`.

- [ ] **Step 1: Write failing tests** with `FakeKey`/`FakeFinger` and a tempdir vault: add key then unlock with it; unknown key → "not registered"; remove key; enable fingerprint then unlock; fingerprint with cleared fake store → `NotSetUp` message and password still works; switch to two-factor then password-only unlock refused and two-factor works; switch back to any; timeout from the fake leaves the file bytes unchanged; `unlock_methods` while locked returns names but the JSON contains no `salt`/`credential_id`/`wrapped`; change password in two-factor mode with two keys asks twice (count `emit` calls) and both keys work after.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** and register commands in `lib.rs`. **Step 4: Run** full suite + clippy → PASS.
- [ ] **Step 5: Commit** `feat: commands for YubiKey and fingerprint unlock`.

### Task 5: FIDO2 over HID (Linux, macOS)

**Files:**
- Create: `src-tauri/src/unlock/fido_hid.rs`
- Modify: `src-tauri/src/unlock/mod.rs`, `src-tauri/Cargo.toml` (`[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies] ctap-hid-fido2 = "3.6"`), `.github/workflows/ci.yml` (apt `libudev-dev`)

**Interfaces:**
- Produces: `pub struct HidKey;` implementing `HmacKey`.
  - `available()`: `!ctap_hid_fido2::get_fidokey_devices().is_empty()`.
  - Open with `FidoKeyHidFactory::create(&cfg)` where `cfg = LibCfg::init()` with `enable_log = false`, `enable_keep_alive_msg = false` (the library must print nothing).
  - `enroll`: `MakeCredentialArgsBuilder::new("deskauth", &challenge).without_pin_and_uv().extensions(&[make_credential::Extension::HmacSecret(Some(true))]).build()`; random 32-byte challenge, user id and salt; then `assert(&[(cred, salt)])`.
  - `assert`: `GetAssertionArgsBuilder::new("deskauth", &challenge).without_pin_and_uv()` + `add_credential_id` per allowed id + `extensions(&[Extension::HmacSecret(Some(salt))])`. The CTAP extension takes one salt per call, so when several keys are allowed, call once per (cred, salt) pair only after the device answered which credential it holds: first run a `without_up()` probe assertion with all ids (no touch) to learn the matching credential, then the real assertion with that credential's salt.
  - Map "no device" → `NoDevice`, CTAP `ERR_USER_ACTION_TIMEOUT`/keep-alive timeout → `Timeout`, `ERR_NO_CREDENTIALS` → `NoCredential`, anything else → `Other(short text)`.
  - No unit tests for the device itself; keep pure helpers (error mapping, picking the salt for a credential) testable and tested.
- [ ] **Steps:** tests for helpers (FAIL) → implement → `cargo test` + clippy PASS → wire into `platform_hmac_key()` for linux/macos → commit `feat(unlock): YubiKey over FIDO2 HID`.

### Task 6: Linux fingerprint (fprintd + Secret Service)

**Files:**
- Create: `src-tauri/src/unlock/finger_linux.rs`
- Modify: `src-tauri/src/unlock/mod.rs`, `src-tauri/Cargo.toml` (`[target.'cfg(target_os = "linux")'.dependencies] zbus = { version = "5", default-features = false, features = ["blocking-api", "async-io"] }` matching the version already in `Cargo.lock`, `keyring = { version = "3", features = ["sync-secret-service", "crypto-rust"] }`)

**Interfaces:**
- Produces: `pub struct FprintdFinger;` implementing `Fingerprint`, `platform() == "linux"`.
  - `available()`: system bus `net.reactivated.Fprint` `/net/reactivated/Fprint/Manager` `GetDefaultDevice` succeeds and `ListEnrolledFingers("")` is non-empty.
  - `verify() -> Result<(), DeviceError>`: `Claim("")`, subscribe to `VerifyStatus`, `VerifyStart("any")`, wait up to 30 s: `verify-match` → Ok; `verify-no-match` → `Other("Fingerprint did not match.")`; `verify-retry-*` keep waiting; `verify-disconnected`/`verify-unknown-error` → `Other`; timeout → `Timeout`. Always `VerifyStop` + `Release`, even on error.
  - `enable(id)`: `verify()`, then 32 random bytes stored with `keyring::Entry::new("deskauth", &format!("fingerprint-{id}"))` as base64 via `set_password`.
  - `unlock(id)`: `verify()`, then read the entry; `NoEntry` → `NotSetUp`.
  - `disable(id)`: delete the entry (`NoEntry` is Ok).
  - Unit-test the pure parts (status string → result, base64 round trip).
- [ ] **Steps:** tests (FAIL) → implement → tests + clippy PASS → wire into `platform_fingerprint()` for linux → commit `feat(unlock): Linux fingerprint via fprintd`.

### Task 7: macOS Touch ID

**Files:**
- Create: `src-tauri/src/unlock/finger_macos.rs`
- Modify: `src-tauri/src/unlock/mod.rs`, `src-tauri/Cargo.toml` (`[target.'cfg(target_os = "macos")'.dependencies] security-framework = "3"`)

**Interfaces:**
- Produces: `pub struct TouchIdFinger;`, `platform() == "macos"`.
  - Store/read a generic password (service `deskauth`, account `fingerprint-{id}`) with `PasswordOptions` + access control `BIOMETRY_CURRENT_SET` so reading it triggers Touch ID.
  - If creating the item fails with `errSecMissingEntitlement` (-34018, unsigned build), `enable` returns `Unsupported("Touch ID unlock needs a signed build of Deskauth.")`; `available()` stays true so the user sees the reason.
  - Item not found → `NotSetUp`; user cancel → `Cancelled`.
- [ ] **Steps:** implement; `cargo check --target aarch64-apple-darwin` is not possible locally - rely on the CI macOS job (Task 9). Pure helpers (status code → `DeviceError`) get unit tests that run on every OS. Commit `feat(unlock): macOS Touch ID`.

### Task 8: Windows (WebAuthn YubiKey + Windows Hello)

**Files:**
- Create: `src-tauri/src/unlock/fido_windows.rs`, `src-tauri/src/unlock/finger_windows.rs`
- Modify: `src-tauri/src/unlock/mod.rs`, `src-tauri/Cargo.toml` (`[target.'cfg(windows)'.dependencies] windows = { version = "0.62", features = ["Win32_Networking_WindowsWebServices", "Win32_Foundation", "Win32_UI_WindowsAndMessaging", "Security_Credentials", "Security_Cryptography", "Storage_Streams", "Foundation"] }` - adjust the feature list to what compiles)

**Interfaces:**
- `WebAuthnKey` implementing `HmacKey`: `WebAuthNGetApiVersionNumber()` below the version that supports hmac-secret salts in `GetAssertion` → `available() == false`. `enroll` via `WebAuthNAuthenticatorMakeCredential` with the hmac-secret extension and cross-platform attachment; `assert` via `WebAuthNAuthenticatorGetAssertion` with `pHmacSecretSaltValues` (per-credential salts) and the allow list. Window handle: the foreground window (`GetForegroundWindow`). Map `NTE_USER_CANCELLED` → `Cancelled`, `NTE_NOT_FOUND` → `NoCredential`.
- `HelloFinger` implementing `Fingerprint`, `platform() == "windows"`: `KeyCredentialManager::IsSupportedAsync`; `enable(id)`: `RequestCreateAsync("deskauth-{id}", ReplaceExisting)` then sign; `unlock(id)`: `OpenAsync` then `RequestSignAsync(challenge)`; secret = SHA-256(signature). `disable(id)`: `DeleteAsync`. Status `UserCanceled` → `Cancelled`, `NotFound` → `NotSetUp`.
- [ ] **Steps:** implement; compile-checked by CI Windows job (Task 9); unit-test pure helpers (status mapping, challenge string). Commit `feat(unlock): Windows WebAuthn and Windows Hello`.

### Task 9: CI on macOS and Windows

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] Add a job `cross` with `strategy.matrix.os: [macos-latest, windows-latest]`: checkout, rust stable with clippy, node 22, `npm ci`, `npm run build` (so `frontendDist` exists), `cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings`, `cargo test --manifest-path src-tauri/Cargo.toml`. Keep the Linux job and add `libudev-dev` to its apt line.
- [ ] Push the branch and check both jobs pass with `gh run watch` once (do not loop). Fix compile errors in Tasks 7-8 code here.
- [ ] Commit `ci: build and test on macOS and Windows`.

### Task 10: UI, docs, and hand test

**Files:**
- Modify: `src/api.ts`, `src/views/unlock.ts`, `src/views/settings.ts`, `src/theme.css`, `README.md`, `CHANGELOG.md`, `docs/features/2026-11-03-deskauth.md`

**Interfaces:**
- `api.ts`: `type Mode = "password" | "any" | "password_yubikey"`; `UnlockMethods`; wrappers for every Task 4 command; `onTouchNeeded(cb: (name: string | null) => void)`.
- Unlock view: reads `unlockMethods()` on render. `password`/`any`: password form as today; in `any`, buttons "Use YubiKey" (if any key registered and `can_yubikey`) and "Use fingerprint" (if set and `can_fingerprint`). `password_yubikey`: the password field's submit calls `vaultUnlockTwoFactor`. While a device call runs: status line "Touch your YubiKey" / "Touch Blue key" (from `touch-needed`) or "Scan your finger", buttons disabled.
- Settings view: a second card "Unlock methods" above "Change password": three radio options with one line each (`Password only`, `Password, YubiKey or fingerprint`, `Password and YubiKey together`), applying a change asks for what Task 4 needs (password field, key name) and shows touch status; YubiKey list with Remove (confirm dialog); "Add YubiKey" (name input, default "YubiKey"); fingerprint switch with the Linux note text from the spec when `platform` is linux; warning "Only one YubiKey is registered. If you lose it, you lose this vault. Add a backup key." when mode is `password_yubikey` with one key.
- README: an "Unlock with a YubiKey or fingerprint" section (modes, the Linux note, macOS signed-build note, Windows needs a recent WebAuthn API, macOS/Windows untested). CHANGELOG "Added" line. Feature doc section.
- [ ] Run `npx tsc --noEmit`, `npm run build`, full `cargo test`, clippy.
- [ ] UI check in the browser with the `mockIPC` harness from the screenshots session (mock the new commands): unlock screen in all three modes, settings card, touch status text. Screenshots as proof.
- [ ] **Hand test with the user (Linux, real hardware, user does every touch and scan):** user copies `~/.local/share/dev.nichovski.deskauth/vault.json` to a backup first; then build and run the app; check: v1 → v2 upgrade with password; add YubiKey; lock; unlock with YubiKey; enable fingerprint; lock; unlock with finger; unplugged key message; switch to two-factor, lock, unlock with password + touch, password alone refused; switch back to `any`; change password; auto-lock still works.
- [ ] Commit `feat(ui): unlock with YubiKey or fingerprint`.

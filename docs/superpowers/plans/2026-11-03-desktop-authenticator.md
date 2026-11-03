# Deskauth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Tauri 2 desktop TOTP app that imports Google Authenticator exports, is locked by a master password, and follows the Omarchy theme.

**Architecture:** Rust (`src-tauri/src/`) holds every secret and all logic, split into small modules with no Tauri types (`account`, `totp`, `migration`, `import`, `merge`, `vault`, `qr`, `camera`, `theme`). `commands.rs` + `lib.rs` wire them to a plain TypeScript UI (`src/`) that only receives codes, labels and a palette. Secrets never cross into the webview.

**Tech Stack:** Rust 1.99, Tauri 2, TypeScript + Vite (npm, no UI framework). Crates: `argon2`, `chacha20poly1305`, `zeroize`, `rand`, `serde`, `serde_json`, `base32`, `base64`, `hmac`, `sha1`, `sha2`, `prost`, `url`, `uuid` (v4), `rqrr`, `image`, `nokhwa` (`input-native`), `notify`, `toml`, `arboard` (`wayland-data-control`), `tauri-plugin-single-instance`. Dev: `qrcode`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-11-03-desktop-authenticator-design.md`

## Global Constraints

- App name `Deskauth`, binary/crate `deskauth`, identifier `dev.nichovski.deskauth`. No "Google" in any name.
- Vault file: `<app_data_dir>/vault.json`, mode 0600 on Unix, written via temp file + rename.
- KDF: Argon2id, `m_kib = 65536`, `t = 3`, `p = 1`, 16-byte random salt, 32-byte key.
- Cipher: XChaCha20-Poly1305, 24-byte random nonce per save, AAD = the serialized header.
- Auto-lock after 5 minutes without user activity. Clipboard cleared 30 seconds after copy, only if it still holds that code.
- Secrets (base32 or bytes) never sent to the webview. No network access anywhere in the app.
- Omarchy colors file: `$HOME/.local/state/omarchy/current/theme/colors.toml` (Linux only). Fallback palette: Tokyo Night.
- TOTP only. HOTP and MD5 entries are skipped and counted.
- Error messages returned to the UI are short and user-facing: "Wrong password", "No QR code found in image", "Camera not available", "Not a supported QR code".
- Builds on `/mnt/data` are slow: run cargo with `CARGO_TARGET_DIR=$HOME/.cache/cargo-target/deskauth`.
- Every Rust module keeps its tests in `#[cfg(test)] mod tests` in the same file. `cargo clippy -- -D warnings` must pass at every commit.

## Review Focus

1. **Real Google export decodes.** Our fixtures are encoded with our own prost structs, so a field-number mistake would pass tests. Expect: the manual check in Task 11 imports a real phone export and every code matches the phone. Test in Task 3 also pins raw protobuf bytes written by hand.
2. **`+` in base64 data.** Some tools pass the `data` param with a raw `+`, which URL query decoding turns into a space. Expect: import still works. Test in Task 3.
3. **Issuer-prefixed names.** Google often stores name as `"GitHub:user@x.com"` with issuer `"GitHub"`. Expect: name shown as `user@x.com`, not doubled. Test in Task 3.
4. **Duplicates inside one import and secret formatting.** Same secret twice in one export, or secret with lowercase/spaces/padding typed by hand. Expect: counted once, normalized. Tests in Tasks 2 and 4.
5. **Clipboard on Wayland.** `arboard` content can vanish when the `Clipboard` object is dropped. Expect: copied code stays until the 30 s clear. Keep one `Clipboard` in `AppState` for the app's lifetime (Task 8), checked manually in Task 11.

---

### Task 1: Scaffold the app and CI

**Files:**
- Create: `package.json`, `vite.config.ts`, `tsconfig.json`, `index.html`, `src/main.ts`, `src-tauri/**` (from template), `.gitignore`, `LICENSE` (MIT, "Bogdan Nichovski"), `.github/workflows/ci.yml`

**Interfaces:**
- Produces: crate `deskauth` with `src-tauri/src/lib.rs` exposing `pub fn run()`; empty modules declared in `lib.rs`: `account, totp, migration, import, merge, vault, qr, camera, theme, commands`.

- [ ] **Step 1:** Scaffold in a scratch dir (target dir is not empty), then move files in:
  `npm create tauri-app@latest deskauth -- --template vanilla-ts --manager npm --identifier dev.nichovski.deskauth --yes` inside a temp dir; copy everything except `.git` into the repo root.
- [ ] **Step 2:** In `src-tauri/tauri.conf.json`: `productName: "Deskauth"`, window `{ title: "Deskauth", width: 420, height: 640, dragDropEnabled: false }` (so HTML5 drop works), CSP `"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"`. Remove the template greet command and demo UI.
- [ ] **Step 3:** Add all crates from the Tech Stack to `src-tauri/Cargo.toml`. Create the empty module files listed above.
- [ ] **Step 4:** `.github/workflows/ci.yml` on push/PR, `ubuntu-latest`: install `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev libv4l-dev`, then `npm ci`, `npx tsc --noEmit`, `cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings`, `cargo test --manifest-path src-tauri/Cargo.toml`.
- [ ] **Step 5: Verify**
  Run: `npx tsc --noEmit && cargo test --manifest-path src-tauri/Cargo.toml && npm run tauri dev`
  Expected: tests pass (0 tests), an empty "Deskauth" window opens.
- [ ] **Step 6: Commit** `chore: scaffold Tauri 2 app and CI`

---

### Task 2: Account model and TOTP

**Files:**
- Create: `src-tauri/src/account.rs`, `src-tauri/src/totp.rs`

**Interfaces:**
- Produces:
  ```rust
  // account.rs
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum Algorithm { Sha1, Sha256, Sha512 }
  #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
  pub struct Account { pub id: String, pub issuer: String, pub name: String,
      pub secret: String /* base32, uppercase, no padding, no spaces */,
      pub algorithm: Algorithm, pub digits: u32, pub period: u64 }
  pub fn normalize_secret(input: &str) -> Result<String, String>; // strip spaces/'=', uppercase, must decode
  impl Account {
      pub fn new(issuer: &str, name: &str, secret: &str, algorithm: Algorithm, digits: u32, period: u64) -> Result<Account, String>; // new uuid v4 id, normalizes secret, digits must be 6 or 8, period > 0
      pub fn from_secret_bytes(issuer: &str, name: &str, secret: &[u8], algorithm: Algorithm, digits: u32, period: u64) -> Account;
      pub fn secret_bytes(&self) -> Vec<u8>;
  }
  // totp.rs
  pub fn code(account: &Account, unix_time: u64) -> String;
  pub fn remaining_seconds(period: u64, unix_time: u64) -> u64;
  ```

- [ ] **Step 1: Write failing tests** (`totp.rs`), RFC 6238 Appendix B, 8 digits, period 30. Secrets: SHA1 `b"12345678901234567890"`, SHA256 `b"12345678901234567890123456789012"`, SHA512 `b"1234567890123456789012345678901234567890123456789012345678901234"`.
  ```rust
  #[test] fn rfc6238_vectors() {
      let cases = [(59, "94287082", "46119246", "90693936"),
                   (1111111109, "07081804", "68084774", "25091201"),
                   (20000000000, "65353130", "77737706", "47863826")];
      // for each t: code(&sha1_acc, t) == c1, code(&sha256_acc, t) == c2, code(&sha512_acc, t) == c3
  }
  #[test] fn six_digits_zero_padded() { /* SHA1 secret above, digits 6, t=1111111109 -> "081804" */ }
  #[test] fn remaining() { assert_eq!(remaining_seconds(30, 59), 1); assert_eq!(remaining_seconds(30, 60), 30); }
  ```
  And in `account.rs`:
  ```rust
  #[test] fn normalizes_secret() { assert_eq!(normalize_secret("jbsw y3dp ehpk 3pxp==").unwrap(), "JBSWY3DPEHPK3PXP"); }
  #[test] fn rejects_bad_secret() { assert!(normalize_secret("not base32!").is_err()); assert!(normalize_secret("").is_err()); }
  #[test] fn rejects_bad_digits() { assert!(Account::new("a","b","JBSWY3DPEHPK3PXP",Algorithm::Sha1,7,30).is_err()); }
  ```
- [ ] **Step 2:** Run `cargo test --manifest-path src-tauri/Cargo.toml totp account` -> FAIL (not defined).
- [ ] **Step 3:** Implement. HMAC via `hmac::Hmac<Sha1|Sha256|Sha512>`, counter = `unix_time / period` as big-endian u64, dynamic truncation per RFC 4226, `% 10^digits`, zero-pad. Base32 = RFC 4648 alphabet, no padding.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: account model and TOTP generation`

---

### Task 3: Parse Google migration and otpauth URLs

**Files:**
- Create: `src-tauri/src/migration.rs`

**Interfaces:**
- Consumes: `Account::from_secret_bytes`, `Account::new`, `Algorithm` (Task 2).
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq)] pub struct Batch { pub id: i32, pub index: u32, pub size: u32 }
  #[derive(Debug)] pub struct Parsed { pub accounts: Vec<Account>, pub skipped_unsupported: usize, pub batch: Option<Batch> }
  pub fn parse_uri(uri: &str) -> Result<Parsed, String>; // otpauth-migration://offline?data=... or otpauth://totp/...; anything else -> Err("Not a supported QR code")
  ```
  Protobuf (prost derive, written by hand, no protoc):
  `MigrationPayload { otp_parameters: repeated OtpParameters = 1, version: int32 = 2, batch_size: int32 = 3, batch_index: int32 = 4, batch_id: int32 = 5 }`,
  `OtpParameters { secret: bytes = 1, name: string = 2, issuer: string = 3, algorithm: int32 = 4, digits: int32 = 5, type: int32 = 6, counter: int64 = 7 }`.
  Enums: algorithm `0|1 -> SHA1, 2 -> SHA256, 3 -> SHA512, 4 -> MD5 (skip)`; digits `0|1 -> 6, 2 -> 8`; type `1 -> HOTP (skip), 0|2 -> TOTP`. Period is always 30. `batch` is `Some` only when `batch_size > 1`.

- [ ] **Step 1: Write failing tests**
  ```rust
  #[test] fn decodes_migration_payload() {
      // build MigrationPayload with 2 TOTP (one SHA256/8 digits) + 1 HOTP, base64 (standard), percent-encode, wrap in URL
      // parsed.accounts.len()==2, skipped_unsupported==1, accounts[1].algorithm==Sha256, digits==8, period==30, batch==None
  }
  #[test] fn decodes_hand_written_bytes() {
      // raw bytes: 0a 13 0a 05 48 65 6c 6c 6f 12 01 61 1a 01 62 20 01 28 01 30 02  10 01 18 01 20 00
      // = one OtpParameters{secret:"Hello", name:"a", issuer:"b", SHA1, 6 digits, TOTP}, version 1, batch_size 1
      // -> one account, issuer "b", name "a", secret_bytes()==b"Hello"
  }
  #[test] fn plus_turned_into_space_still_decodes() { /* same URL with data containing '+' left raw (not %2B) parses identically */ }
  #[test] fn strips_issuer_prefix_from_name() { /* name "GitHub:me@x.com", issuer "GitHub" -> name "me@x.com" */ }
  #[test] fn reads_batch() { /* batch_size 3, batch_index 1, batch_id 77 -> batch == Some(Batch{id:77,index:1,size:3}) */ }
  #[test] fn parses_otpauth() {
      let p = parse_uri("otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30").unwrap();
      // one account: issuer "ACME Co", name "john@example.com"
  }
  #[test] fn otpauth_defaults() { /* "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" -> issuer "", name "x", Sha1, 6, 30 */ }
  #[test] fn rejects_other() { assert!(parse_uri("https://example.com").is_err()); assert!(parse_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err()); }
  ```
- [ ] **Step 2:** Run `cargo test ... migration` -> FAIL.
- [ ] **Step 3:** Implement with `url::Url` + `query_pairs`; before base64-decoding `data`, replace `' '` with `'+'`. Name prefix: if `name` starts with `"{issuer}:"`, drop it and trim. For `otpauth://` with no `issuer` param but a `Label:` prefix in the path, use the prefix as issuer.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: parse Google migration and otpauth URLs`

---

### Task 4: Import session and merge

**Files:**
- Create: `src-tauri/src/import.rs`, `src-tauri/src/merge.rs`

**Interfaces:**
- Consumes: `parse_uri`, `Parsed`, `Batch` (Task 3), `Account` (Task 2).
- Produces:
  ```rust
  // merge.rs
  #[derive(Debug, Serialize, PartialEq)] pub struct MergeResult { pub added: usize, pub skipped_duplicates: usize, pub skipped_unsupported: usize }
  pub fn merge(existing: &mut Vec<Account>, incoming: Vec<Account>) -> MergeResult; // duplicate = equal secret_bytes(), also within `incoming`; skipped_unsupported = 0 here
  // import.rs
  #[derive(Debug, Clone, Serialize, PartialEq)] pub struct ImportProgress { pub batches_seen: Vec<u32>, pub batch_size: Option<u32>, pub accounts: usize, pub complete: bool }
  #[derive(Default)] pub struct ImportSession { /* private */ }
  impl ImportSession {
      pub fn add_uri(&mut self, uri: &str) -> Result<ImportProgress, String>; // same batch index twice = no-op; different batch id = start over with this one
      pub fn progress(&self) -> ImportProgress;
      pub fn take(&mut self) -> (Vec<Account>, usize /* skipped_unsupported */); // resets the session
  }
  ```
  `complete` = no batch info, or all indices `0..size` seen.

- [ ] **Step 1: Write failing tests**
  ```rust
  // merge.rs
  #[test] fn same_import_twice_adds_zero() { /* merge(v,[a,b]) -> added 2; merge(v,[a,b]) again -> added 0, skipped_duplicates 2 */ }
  #[test] fn one_new_adds_one() { /* existing [a,b], incoming [a,b,c] -> added 1 */ }
  #[test] fn renamed_same_secret_is_duplicate() { /* incoming a' = a with other issuer/name -> added 0 */ }
  #[test] fn duplicate_inside_incoming() { /* existing [], incoming [a,a] -> added 1, skipped_duplicates 1 */ }
  // import.rs
  #[test] fn single_qr_completes() { /* add_uri(non-batched migration) -> complete true */ }
  #[test] fn batches_complete_after_all() { /* size 2: index 0 -> complete false, batches_seen [0]; index 0 again -> no change; index 1 -> complete true, accounts summed */ }
  #[test] fn new_batch_id_restarts() { /* id 1 index 0, then id 2 index 0 -> batches_seen [0], accounts only from id 2 */ }
  #[test] fn take_resets() { /* after take(), progress().accounts == 0 */ }
  ```
- [ ] **Step 2:** Run `cargo test ... merge import` -> FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: multi-QR import session and merge`

---

### Task 5: Encrypted vault

**Files:**
- Create: `src-tauri/src/vault.rs`

**Interfaces:**
- Consumes: `Account` (Task 2).
- Produces:
  ```rust
  #[derive(Debug, PartialEq)] pub enum VaultError { WrongPassword, Corrupt(String), Io(String) }
  impl std::fmt::Display for VaultError // "Wrong password" / "Vault file is damaged: {0}" / "Could not read vault: {0}"
  pub struct Vault { pub accounts: Vec<Account>, /* private: path, key: Zeroizing<[u8;32]>, header */ }
  pub fn exists(path: &Path) -> bool;
  pub fn create(path: &Path, password: &str) -> Result<Vault, VaultError>; // empty accounts, saves immediately; fails if file exists
  pub fn unlock(path: &Path, password: &str) -> Result<Vault, VaultError>;
  pub fn delete(path: &Path) -> Result<(), VaultError>;
  impl Vault { pub fn save(&self) -> Result<(), VaultError>; pub fn change_password(&mut self, new_password: &str) -> Result<(), VaultError>; }
  impl Drop for Vault // zeroize every account.secret
  ```
  File JSON: `{ "version": 1, "kdf": { "alg": "argon2id", "m_kib", "t", "p", "salt" }, "nonce", "ciphertext" }` (base64 standard). AAD = `serde_json::to_vec(&Header { version, kdf, nonce })` with fields in that order. Plaintext = `serde_json::to_vec(&accounts)`.
  Errors: header JSON/base64 invalid -> `Corrupt`; AEAD failure -> `WrongPassword`; fs errors -> `Io`.

- [ ] **Step 1: Write failing tests** (use `tempfile::tempdir()`)
  ```rust
  #[test] fn round_trip() { /* create, push account, save; unlock with same password -> accounts equal */ }
  #[test] fn wrong_password() { assert_eq!(unlock(&p, "nope").err(), Some(VaultError::WrongPassword)); }
  #[test] fn tampered_header_fails() { /* change kdf.t from 3 to 2 in the file -> unlock(correct pw) is Err */ }
  #[test] fn garbage_is_corrupt() { /* file "hello" -> Err(Corrupt(_)) */ }
  #[test] fn new_nonce_each_save() { /* two saves -> different nonce strings */ }
  #[test] fn change_password() { /* change -> old pw WrongPassword, new pw unlocks; salt changed */ }
  #[test] fn create_refuses_existing() { /* second create on same path -> Err */ }
  #[cfg(unix)] #[test] fn file_mode_0600() { /* metadata().permissions().mode() & 0o777 == 0o600 */ }
  ```
- [ ] **Step 2:** Run `cargo test ... vault` -> FAIL.
- [ ] **Step 3:** Implement. Save = write `<path>.tmp` (mode 0600 on Unix via `OpenOptionsExt`), `sync_all`, `rename`. `change_password` makes a new salt, derives a new key, saves.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: encrypted vault with Argon2id and XChaCha20-Poly1305`

---

### Task 6: QR decoding

**Files:**
- Create: `src-tauri/src/qr.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn decode_luma(img: &image::GrayImage) -> Vec<String>;
  pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>, String>; // Err("No QR code found in image") when empty or unreadable
  ```

- [ ] **Step 1: Write failing tests** (generate fixtures with dev-dep `qrcode` rendered to `image::Luma<u8>`, encode as PNG in memory)
  ```rust
  #[test] fn decodes_png() { /* QR of "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" -> vec![that string] */ }
  #[test] fn decodes_small_qr_in_large_image() { /* paste the QR into a 1600x1200 white image at (700,500) -> found */ }
  #[test] fn no_qr() { /* blank 200x200 PNG -> Err("No QR code found in image") */ }
  #[test] fn not_an_image() { assert!(decode_image_bytes(b"abc").is_err()); }
  ```
- [ ] **Step 2:** Run `cargo test ... qr` -> FAIL.
- [ ] **Step 3:** Implement with `image::load_from_memory(..).to_luma8()` and `rqrr::PreparedImage`.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: QR decoding from images`

---

### Task 7: Omarchy theme

**Files:**
- Create: `src-tauri/src/theme.rs`

**Interfaces:**
- Produces:
  ```rust
  pub type Palette = std::collections::BTreeMap<String, String>; // CSS var name (with "--") -> "#rrggbb"
  pub fn default_palette() -> Palette; // Tokyo Night
  pub fn parse_colors_toml(text: &str) -> Palette; // missing/invalid keys fall back to default_palette()
  pub fn omarchy_colors_path() -> Option<PathBuf>; // Linux + file exists, else None
  pub fn current_palette() -> Palette;
  pub fn watch(on_change: impl Fn(Palette) + Send + 'static) -> Option<notify::RecommendedWatcher>; // Linux only
  ```
  Mapping and Tokyo Night defaults:
  `--bg`=`background` `#1a1b26`, `--bg-alt`=`lighter_background` `#24283b`, `--fg`=`foreground` `#a9b1d6`, `--fg-dim`=`dark_foreground` `#565f89`, `--fg-bright`=`bright_foreground` `#c0caf5`, `--accent`=`accent` `#7aa2f7`, `--selection`=`selection` `#292e42`, `--muted`=`muted` `#414868`, `--danger`=`red` `#f7768e`, `--warn`=`yellow` `#e0af68`, `--ok`=`green` `#9ece6a`.
  Watch: non-recursive on `$HOME/.local/state/omarchy/current` (Omarchy swaps the `theme` directory inside it), debounce 200 ms, then call `on_change(current_palette())`.

- [ ] **Step 1: Write failing tests**
  ```rust
  #[test] fn parses_full_file() { /* toml with accent="#ff0000", background="#000000" -> palette["--accent"]=="#ff0000", ["--bg"]=="#000000" */ }
  #[test] fn missing_keys_fall_back() { /* toml with only accent -> ["--ok"] == "#9ece6a" */ }
  #[test] fn invalid_values_fall_back() { /* accent="blue" -> ["--accent"]=="#7aa2f7" */ }
  #[test] fn bad_toml_gives_default() { assert_eq!(parse_colors_toml("{{{"), default_palette()); }
  #[test] fn palette_has_all_vars() { assert_eq!(default_palette().len(), 11); }
  ```
- [ ] **Step 2:** Run `cargo test ... theme` -> FAIL.
- [ ] **Step 3:** Implement. Valid value = `#` + 6 hex digits.
- [ ] **Step 4:** Run tests -> PASS.
- [ ] **Step 5: Commit** `feat: read and watch Omarchy theme colors`

---

### Task 8: App state, commands, setup/unlock/list UI

**Files:**
- Create: `src-tauri/src/commands.rs`, `src/api.ts`, `src/views/setup.ts`, `src/views/unlock.ts`, `src/views/list.ts`, `src/theme.css`
- Modify: `src-tauri/src/lib.rs`, `src/main.ts`, `index.html`

**Interfaces:**
- Consumes: Tasks 2, 4, 5, 7.
- Produces (Tauri commands, all return `Result<T, String>`):
  ```rust
  pub struct AppState { vault: Mutex<Option<Vault>>, vault_path: PathBuf, last_activity: Mutex<Instant>,
                        clipboard: Mutex<arboard::Clipboard>, import: Mutex<ImportSession>, camera: Mutex<Option<camera::CameraHandle>> }
  #[derive(Serialize)] pub struct CodeView { id: String, issuer: String, name: String, code: String, remaining: u64, period: u64 }
  vault_status() -> String            // "none" | "locked" | "unlocked"
  vault_create(password: String) -> ()   // UI enforces min length 8 and confirmation
  vault_unlock(password: String) -> ()
  vault_lock() -> ()
  activity() -> ()
  codes() -> Vec<CodeView>            // sorted by issuer then name, case-insensitive
  copy_code(id: String) -> ()         // copies, spawns 30 s timer that clears only if clipboard text == code
  get_theme() -> Palette
  ```
  Events: `"locked"` (no payload), `"theme"` (Palette).
  TS: `src/api.ts` exports one typed async function per command (`vaultStatus`, `vaultCreate`, ...) plus `onLocked(cb)`, `onTheme(cb)`.

- [ ] **Step 1:** `lib.rs::run()`: register single-instance plugin (focus main window on second launch), build `AppState` with `vault_path = app.path().app_data_dir()?.join("vault.json")` (create dir), start `theme::watch` emitting `"theme"`, spawn auto-lock thread: every 5 s, if unlocked and `last_activity` older than 300 s -> drop vault, emit `"locked"`. Every command that touches the vault also refreshes `last_activity`.
- [ ] **Step 2:** UI: `main.ts` applies `get_theme()` palette to `document.documentElement.style` and listens to `"theme"`; routes by `vault_status()` to setup / unlock / list. Setup: password + confirm, min 8 chars, warns that a lost password cannot be recovered. Unlock: one field, shows "Wrong password" on error. List: search box autofocused, rows (issuer, name, code as `123 456` / `1234 5678`, countdown ring from `remaining/period`), poll `codes()` every 1 s, Enter copies top match, click copies, "Copied" toast, lock button. `activity()` on keydown/pointermove, throttled to once per 10 s. All colors from CSS variables in `theme.css`; codes in `ui-monospace`.
- [ ] **Step 3: Verify**
  Run: `npx tsc --noEmit && cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings && cargo test --manifest-path src-tauri/Cargo.toml && npm run tauri dev`
  Expected: first run shows setup; after setup an empty list; restart -> unlock screen; wrong password shows "Wrong password"; `omarchy-theme-next` (or switching theme from the menu) recolors the window in about 1 s.
- [ ] **Step 4: Commit** `feat: vault lifecycle, code list and theming UI`

---

### Task 9: Import and add screens (image, camera, manual)

**Files:**
- Create: `src-tauri/src/camera.rs`, `src/views/import.ts`, `src/views/add.ts`, `src-tauri/Info.plist` (`NSCameraUsageDescription` = "Deskauth uses the camera to scan QR codes.")
- Modify: `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`, `src/api.ts`, `src/views/list.ts`

**Interfaces:**
- Consumes: `ImportSession`, `merge`, `MergeResult` (Task 4), `qr::decode_image_bytes`, `qr::decode_luma` (Task 6), `Account::new` (Task 2).
- Produces:
  ```rust
  // camera.rs
  #[derive(Serialize, Clone)] pub struct CameraInfo { pub index: u32, pub name: String }
  pub struct Frame { pub preview_jpeg: Vec<u8> /* max 480px wide */, pub decoded: Vec<String> }
  pub fn list_cameras() -> Result<Vec<CameraInfo>, String>;
  pub fn start(index: u32, on_frame: impl Fn(Frame) + Send + 'static) -> Result<CameraHandle, String>; // decodes ~5 fps on its own thread
  pub struct CameraHandle; impl CameraHandle { pub fn stop(self); } impl Drop for CameraHandle // stops the stream
  // commands
  import_image(bytes: Vec<u8>) -> ImportProgress   // every decoded string goes through ImportSession::add_uri; Err only if none was accepted
  camera_list() -> Vec<CameraInfo>
  camera_start(index: u32) -> ()                    // emits "camera-frame" { preview: "data:image/jpeg;base64,...", progress: ImportProgress, error: Option<String> }
  camera_stop() -> ()
  import_finish() -> MergeResult                    // take() + merge into vault + save; stops camera; skipped_unsupported from take()
  import_cancel() -> ()
  account_add_manual(issuer: String, name: String, secret: String, algorithm: String, digits: u32, period: u64) -> ()
  ```
  `macOS`: call `nokhwa::nokhwa_initialize` before the first `list_cameras`. Camera errors map to "Camera not available".

- [ ] **Step 1:** Implement `camera.rs` and the commands. When `progress.complete` becomes true during a camera scan, the UI calls `import_finish` automatically.
- [ ] **Step 2:** UI import screen: tabs "Camera" (camera picker if >1, live preview, "batch 2 of 3 scanned"), "Image" (file input + drop zone, accepts png/jpg). Buttons "Finish import" (enabled when accounts > 0) and "Cancel". Result line: "Added 5, skipped 2 already present, 1 unsupported". The list screen gets "Import / Re-import" and "Add account" buttons. The add screen: issuer, name, secret, collapsed advanced (algorithm SHA1/SHA256/SHA512, digits 6/8, period default 30), plus "Scan QR" that reuses the import flow (an `otpauth://` QR adds one account).
- [ ] **Step 3: Verify**
  Run: `npx tsc --noEmit && cargo clippy ... -- -D warnings && cargo test ... && npm run tauri dev`
  Expected: dropping a PNG from Task 6's test fixture style (generate one with `qrencode -o /tmp/x.png 'otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test'`) adds "Test / me"; dropping it again reports "Added 0, skipped 1 already present"; camera preview shows on `/dev/video0` and scanning that PNG on a phone screen adds nothing new.
- [ ] **Step 4: Commit** `feat: import from camera and images, manual add`

---

### Task 10: Account editing, password change, damaged vault

**Files:**
- Modify: `src-tauri/src/commands.rs`, `src/api.ts`, `src/views/list.ts`, `src/views/unlock.ts`
- Create: `src/views/settings.ts`

**Interfaces:**
- Produces commands:
  ```rust
  account_rename(id: String, issuer: String, name: String) -> ()
  account_delete(id: String) -> ()
  vault_change_password(current: String, new_password: String) -> () // verifies current by unlocking the file; Err("Wrong password")
  vault_reset() -> ()                                                  // deletes vault file, state -> "none"
  ```
  `vault_unlock` returns the `VaultError` Display text, so a damaged file shows "Vault file is damaged: ...".

- [ ] **Step 1:** Row menu (right click or `⋯`): Rename (inline form), Delete (confirm "Delete GitHub / me@x.com? This cannot be undone."). Settings screen: change password (current, new, confirm, min 8). Unlock screen: when the error starts with "Vault file is damaged", show "Delete vault and start over" with a confirm that says accounts must be imported again.
- [ ] **Step 2: Verify**
  Run: `npx tsc --noEmit && cargo clippy ... -- -D warnings && cargo test ... && npm run tauri dev`
  Expected: rename and delete persist across restart; changed password works and the old one fails; writing `hello` into `vault.json` shows the damaged message and the reset path returns to setup.
- [ ] **Step 3: Commit** `feat: rename/delete accounts, change password, reset damaged vault`

---

### Task 11: Release workflow, PKGBUILD, README, real-phone check

**Files:**
- Create: `.github/workflows/release.yml`, `packaging/arch/PKGBUILD`, `README.md`

- [ ] **Step 1:** `release.yml` on tag `v*`: matrix `ubuntu-22.04`, `windows-latest`, `macos-latest` (universal: `--target universal-apple-darwin`), `tauri-apps/tauri-action@v0` with `tagName: ${{ github.ref_name }}`, `releaseDraft: true`, no signing secrets. Outputs AppImage + .deb, .msi, .dmg.
- [ ] **Step 2:** `PKGBUILD`: builds from the local checkout (`npm ci && npm run tauri build -- --no-bundle`), installs the binary to `/usr/bin/deskauth`, a `.desktop` file and the icon. Depends: `webkit2gtk-4.1`, `v4l-utils`. Makedepends: `rust`, `npm`.
- [ ] **Step 3:** README: what it is, security trade-off (codes on the same computer as passwords; master password is the only protection; no recovery), import steps (Google Authenticator > Transfer accounts > Export > scan with camera; iOS screenshots work, Android blocks them), re-import, build from source, install on Arch via `makepkg -si` in `packaging/arch`, sign your own build (Windows: `signtool`/Tauri `certificateThumbprint`; macOS: `APPLE_SIGNING_IDENTITY` + notarization env vars per Tauri docs), unsigned macOS warning, optional Hyprland bind `bind = SUPER, A, exec, deskauth`.
- [ ] **Step 4: Verify on this machine**
  Run: `cd packaging/arch && makepkg -si`, then launch `deskauth`.
  Expected, checked by hand with the real phone: import every export batch by camera, codes match the phone for 3 accounts, re-import adds 0, copied code pastes in another app and is gone 30 s later, auto-lock fires after 5 min idle, theme switch recolors.
- [ ] **Step 5: Commit** `chore: release workflow, Arch PKGBUILD and README`

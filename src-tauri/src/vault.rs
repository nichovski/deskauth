//! Encrypted vault file. A random vault key encrypts the accounts (XChaCha20-Poly1305); each slot
//! holds that key wrapped by a key-encryption key (KEK) only one unlock method can produce.
//! The header (version, mode, slots, nonce) is bound to the ciphertext as AAD.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm as Argon2Alg, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::Account;

const VERSION_V1: u32 = 1;
const VERSION: u32 = 2;
const ALG: &str = "argon2id";
const M_KIB: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const ID_LEN: usize = 16;
const SLOT_AAD_PREFIX: &str = "deskauth-slot-v2:";
const KIND_PASSWORD: &str = "password";

#[derive(Debug, PartialEq)]
pub enum VaultError {
    WrongPassword,
    NotRegistered,
    NotAllowed(String),
    Corrupt(String),
    Io(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::WrongPassword => write!(f, "Wrong password"),
            VaultError::NotRegistered => write!(f, "This YubiKey is not registered for this vault"),
            VaultError::NotAllowed(m) => write!(f, "{m}"),
            VaultError::Corrupt(m) => write!(f, "Vault file is damaged: {m}"),
            VaultError::Io(m) => write!(f, "Could not read vault: {m}"),
        }
    }
}

impl std::error::Error for VaultError {}

/// How strict unlocking is; decides which slot kinds the file may hold.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Password,
    Any,
    PasswordYubikey,
}

#[derive(Serialize, Deserialize, Clone)]
struct Kdf {
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

impl Kdf {
    fn new(salt: &[u8; SALT_LEN]) -> Kdf {
        Kdf {
            alg: ALG.into(),
            m_kib: M_KIB,
            t: T_COST,
            p: P_COST,
            salt: B64.encode(salt),
        }
    }

    /// Rejects anything but our own parameters before spending memory on the KDF.
    fn checked_salt(&self) -> Result<[u8; SALT_LEN], VaultError> {
        if self.alg != ALG || self.m_kib != M_KIB || self.t != T_COST || self.p != P_COST {
            return Err(VaultError::Corrupt("unsupported key derivation settings".into()));
        }
        decode_fixed::<SALT_LEN>(&self.salt, "salt")
    }
}

/// One way to unlock: the vault key wrapped under that method's KEK. Byte fields are base64.
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Slot {
    Password {
        id: String,
        kdf: Kdf,
        nonce: String,
        wrapped: String,
    },
    Yubikey {
        id: String,
        name: String,
        credential_id: String,
        salt: String,
        nonce: String,
        wrapped: String,
    },
    Fingerprint {
        id: String,
        platform: String,
        nonce: String,
        wrapped: String,
    },
    PasswordYubikey {
        id: String,
        name: String,
        kdf: Kdf,
        credential_id: String,
        salt: String,
        nonce: String,
        wrapped: String,
    },
}

/// The authenticated part of a v2 file. Field order is part of the AAD format.
#[derive(Serialize)]
struct HeaderV2<'a> {
    version: u32,
    mode: Mode,
    slots: &'a [Slot],
    nonce: &'a str,
}

#[derive(Serialize, Deserialize)]
struct VaultFileV2 {
    version: u32,
    mode: Mode,
    slots: Vec<Slot>,
    nonce: String,
    ciphertext: String,
}

/// The authenticated part of a v1 file, where the password key encrypted the accounts directly.
/// Only read, to upgrade. Field order is part of the AAD format.
#[derive(Serialize, Deserialize)]
struct HeaderV1 {
    version: u32,
    kdf: Kdf,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFileV1 {
    version: u32,
    kdf: Kdf,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

/// What an unlock attempt offers. Only `Password` opens a vault so far; the rest are refused.
pub enum Secret<'a> {
    Password(&'a str),
    Yubikey {
        credential_id: &'a [u8],
        hmac: &'a [u8; 32],
    },
    Fingerprint {
        secret: &'a [u8; 32],
    },
    PasswordYubikey {
        password: &'a str,
        credential_id: &'a [u8],
        hmac: &'a [u8; 32],
    },
}

pub struct Vault {
    pub accounts: Vec<Account>,
    path: PathBuf,
    vault_key: Zeroizing<[u8; KEY_LEN]>,
    mode: Mode,
    slots: Vec<Slot>,
}

/// A fresh salt and the password KEK derived from it. Made without the vault, so the slow KDF needs no lock.
pub struct PasswordKek {
    salt: [u8; SALT_LEN],
    kek: Zeroizing<[u8; KEY_LEN]>,
}

impl PasswordKek {
    pub fn derive(password: &str) -> Result<PasswordKek, VaultError> {
        let salt = random_bytes::<SALT_LEN>();
        let kek = derive_key(password, &salt)?;
        Ok(PasswordKek { salt, kek })
    }
}

fn io_err(e: std::io::Error) -> VaultError {
    VaultError::Io(e.to_string())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let params = Params::new(M_KIB, T_COST, P_COST, Some(KEY_LEN))
        .map_err(|e| VaultError::Corrupt(format!("bad kdf parameters: {e}")))?;
    let argon = Argon2::new(Argon2Alg::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(value).map_err(|e| VaultError::Corrupt(e.to_string()))
}

fn decode_fixed<const N: usize>(s: &str, what: &str) -> Result<[u8; N], VaultError> {
    let v = B64
        .decode(s)
        .map_err(|_| VaultError::Corrupt(format!("{what} is not valid base64")))?;
    v.try_into()
        .map_err(|_| VaultError::Corrupt(format!("{what} has the wrong length")))
}

fn decode(s: &str, what: &str) -> Result<Vec<u8>, VaultError> {
    B64.decode(s)
        .map_err(|_| VaultError::Corrupt(format!("{what} is not valid base64")))
}

fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    msg: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| VaultError::Corrupt("encryption failed".into()))
}

/// A failed tag check means the key (so the password) was wrong, or the file was edited.
fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    msg: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map(Zeroizing::new)
        .map_err(|_| VaultError::WrongPassword)
}

fn slot_aad(kind: &str, id: &str) -> Vec<u8> {
    format!("{SLOT_AAD_PREFIX}{kind}:{id}").into_bytes()
}

/// Wraps the vault key under `kek`; returns the base64 nonce and wrapped key.
fn wrap(
    kek: &[u8; KEY_LEN],
    kind: &str,
    id: &str,
    vault_key: &[u8; KEY_LEN],
) -> Result<(String, String), VaultError> {
    let nonce = random_bytes::<NONCE_LEN>();
    let wrapped = seal(kek, &nonce, vault_key, &slot_aad(kind, id))?;
    Ok((B64.encode(nonce), B64.encode(wrapped)))
}

fn unwrap(
    kek: &[u8; KEY_LEN],
    kind: &str,
    id: &str,
    nonce: &str,
    wrapped: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let nonce = decode_fixed::<NONCE_LEN>(nonce, "slot nonce")?;
    let wrapped = decode(wrapped, "wrapped key")?;
    let plain = open(kek, &nonce, &wrapped, &slot_aad(kind, id))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if plain.len() != KEY_LEN {
        return Err(VaultError::Corrupt("wrapped key has the wrong length".into()));
    }
    key.copy_from_slice(&plain);
    Ok(key)
}

fn password_slot(
    id: String,
    kek: &PasswordKek,
    vault_key: &[u8; KEY_LEN],
) -> Result<Slot, VaultError> {
    let (nonce, wrapped) = wrap(&kek.kek, KIND_PASSWORD, &id, vault_key)?;
    Ok(Slot::Password {
        id,
        kdf: Kdf::new(&kek.salt),
        nonce,
        wrapped,
    })
}

fn new_id() -> String {
    B64.encode(random_bytes::<ID_LEN>())
}

/// Decrypts the account list. The caller validates it once the secrets are owned by a `Vault`.
fn decrypt_accounts(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<Account>, VaultError> {
    let plaintext = open(key, nonce, ciphertext, aad)?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| VaultError::Corrupt("vault contents are invalid".into()))
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

pub fn create(path: &Path, password: &str) -> Result<Vault, VaultError> {
    if path.exists() {
        return Err(VaultError::Io("vault already exists".into()));
    }
    let kek = PasswordKek::derive(password)?;
    let vault_key = Zeroizing::new(random_bytes::<KEY_LEN>());
    let slot = password_slot(new_id(), &kek, &vault_key)?;
    let vault = Vault {
        accounts: Vec::new(),
        path: path.to_path_buf(),
        vault_key,
        mode: Mode::Password,
        slots: vec![slot],
    };
    vault.save()?;
    Ok(vault)
}

pub fn unlock(path: &Path, password: &str) -> Result<Vault, VaultError> {
    unlock_with(path, Secret::Password(password))
}

pub fn unlock_with(path: &Path, secret: Secret) -> Result<Vault, VaultError> {
    let bytes = std::fs::read(path).map_err(io_err)?;
    let version: VersionOnly =
        serde_json::from_slice(&bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    match (version.version, secret) {
        (VERSION_V1, Secret::Password(password)) => upgrade_v1(path, &bytes, password),
        (VERSION_V1, _) => Err(VaultError::WrongPassword),
        (VERSION, secret) => unlock_v2(path, &bytes, secret),
        _ => Err(VaultError::Corrupt("unsupported version".into())),
    }
}

fn unlock_v2(path: &Path, bytes: &[u8], secret: Secret) -> Result<Vault, VaultError> {
    let file: VaultFileV2 =
        serde_json::from_slice(bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
    let ciphertext = decode(&file.ciphertext, "ciphertext")?;

    let vault_key = match secret {
        Secret::Password(password) => {
            let (id, kdf, slot_nonce, wrapped) = file
                .slots
                .iter()
                .find_map(|s| match s {
                    Slot::Password { id, kdf, nonce, wrapped } => Some((id, kdf, nonce, wrapped)),
                    _ => None,
                })
                .ok_or_else(|| {
                    VaultError::NotAllowed("Password-only unlock is not enabled for this vault".into())
                })?;
            let salt = kdf.checked_salt()?;
            let kek = derive_key(password, &salt)?;
            unwrap(&kek, KIND_PASSWORD, id, slot_nonce, wrapped)?
        }
        _ => return Err(VaultError::WrongPassword),
    };

    let header = HeaderV2 {
        version: file.version,
        mode: file.mode,
        slots: &file.slots,
        nonce: &file.nonce,
    };
    let accounts = decrypt_accounts(&vault_key, &nonce, &ciphertext, &to_json(&header)?)?;
    // Wrap now so secrets are wiped even if validation fails below.
    let vault = Vault {
        accounts,
        path: path.to_path_buf(),
        vault_key,
        mode: file.mode,
        slots: file.slots,
    };
    vault.validate()?;
    Ok(vault)
}

/// Opens a v1 file with the password and rewrites it as v2 (new vault key, one password slot
/// with a new salt, mode `password`). If the save fails the v1 file stays as it was.
fn upgrade_v1(path: &Path, bytes: &[u8], password: &str) -> Result<Vault, VaultError> {
    let accounts = read_v1(bytes, password)?;
    let mut vault = Vault {
        accounts,
        path: path.to_path_buf(),
        vault_key: Zeroizing::new(random_bytes::<KEY_LEN>()),
        mode: Mode::Password,
        slots: Vec::new(),
    };
    vault.validate()?;
    let kek = PasswordKek::derive(password)?;
    vault.slots.push(password_slot(new_id(), &kek, &vault.vault_key)?);
    vault.save()?;
    Ok(vault)
}

fn read_v1(bytes: &[u8], password: &str) -> Result<Vec<Account>, VaultError> {
    let file: VaultFileV1 =
        serde_json::from_slice(bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let salt = file.kdf.checked_salt()?;
    let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
    let ciphertext = decode(&file.ciphertext, "ciphertext")?;
    let header = HeaderV1 {
        version: file.version,
        kdf: file.kdf,
        nonce: file.nonce,
    };
    let key = derive_key(password, &salt)?;
    decrypt_accounts(&key, &nonce, &ciphertext, &to_json(&header)?)
}

pub fn delete(path: &Path) -> Result<(), VaultError> {
    std::fs::remove_file(path).map_err(io_err)
}

impl Vault {
    pub fn mode(&self) -> Mode {
        self.mode
    }

    fn validate(&self) -> Result<(), VaultError> {
        for a in &self.accounts {
            a.validate().map_err(VaultError::Corrupt)?;
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), VaultError> {
        let nonce = random_bytes::<NONCE_LEN>();
        let nonce_b64 = B64.encode(nonce);
        let header = HeaderV2 {
            version: VERSION,
            mode: self.mode,
            slots: &self.slots,
            nonce: &nonce_b64,
        };
        let plaintext = Zeroizing::new(to_json(&self.accounts)?);
        let ciphertext = seal(&self.vault_key, &nonce, &plaintext, &to_json(&header)?)?;
        let file = VaultFileV2 {
            version: VERSION,
            mode: self.mode,
            slots: self.slots.clone(),
            nonce: nonce_b64,
            ciphertext: B64.encode(ciphertext),
        };
        write_atomic(&self.path, &to_json(&file)?)
    }

    /// Rewraps the vault key in the password slot under `kek` and saves. The accounts are not
    /// re-encrypted. On a failed save the old slot comes back.
    pub fn set_password(&mut self, kek: PasswordKek) -> Result<(), VaultError> {
        let (index, id) = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(i, s)| match s {
                Slot::Password { id, .. } => Some((i, id.clone())),
                _ => None,
            })
            .ok_or_else(|| VaultError::NotAllowed("This vault has no password slot".into()))?;
        let new = password_slot(id, &kek, &self.vault_key)?;
        let old = std::mem::replace(&mut self.slots[index], new);
        if let Err(e) = self.save() {
            self.slots[index] = old;
            return Err(e);
        }
        Ok(())
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);

    let result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Algorithm;

    fn sample() -> Account {
        Account::new("GitHub", "me@example.com", "JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30)
            .unwrap()
    }

    fn read_json(p: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    fn write_json(p: &Path, j: &serde_json::Value) {
        std::fs::write(p, serde_json::to_vec(j).unwrap()).unwrap();
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vault.json");
        (dir, p)
    }

    /// Writes a file the way the v1 app did: the Argon2id key encrypts the accounts directly.
    fn write_v1(path: &Path, password: &str, accounts: &[Account]) {
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(password, &salt).unwrap();
        let nonce = random_bytes::<NONCE_LEN>();
        let header = HeaderV1 {
            version: VERSION_V1,
            kdf: Kdf::new(&salt),
            nonce: B64.encode(nonce),
        };
        let aad = serde_json::to_vec(&header).unwrap();
        let plaintext = serde_json::to_vec(accounts).unwrap();
        let ciphertext = seal(&key, &nonce, &plaintext, &aad).unwrap();
        let file = VaultFileV1 {
            version: header.version,
            kdf: header.kdf,
            nonce: header.nonce,
            ciphertext: B64.encode(ciphertext),
        };
        std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
    }

    #[test]
    fn create_writes_v2() {
        let (_d, p) = setup();
        let v = create(&p, "pw").unwrap();
        assert_eq!(v.mode(), Mode::Password);
        let j = read_json(&p);
        assert_eq!(j["version"], 2);
        assert_eq!(j["mode"], "password");
        let slots = j["slots"].as_array().unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0]["kind"], "password");
        assert_eq!(slots[0]["kdf"]["alg"], "argon2id");
    }

    #[test]
    fn round_trip_v2() {
        let (_d, p) = setup();
        let mut v = create(&p, "pw").unwrap();
        assert!(exists(&p));
        v.accounts.push(sample());
        v.save().unwrap();
        let expected = v.accounts.clone();
        let u = unlock(&p, "pw").unwrap();
        assert_eq!(u.accounts, expected);
        assert_eq!(u.mode(), Mode::Password);
    }

    #[test]
    fn wrong_password_v2() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        assert_eq!(unlock(&p, "nope").err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn tampered_slot_fails() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        j["slots"][0]["id"] = "AAAAAAAAAAAAAAAAAAAAAA==".into();
        write_json(&p, &j);
        assert!(matches!(
            unlock(&p, "pw"),
            Err(VaultError::WrongPassword | VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn tampered_mode_fails() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        j["mode"] = "any".into();
        write_json(&p, &j);
        assert!(unlock(&p, "pw").is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        j["nonce"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        write_json(&p, &j);
        assert!(unlock(&p, "pw").is_err());
    }

    #[test]
    fn bad_kdf_rejected_v2() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        assert_eq!(j["slots"][0]["kdf"]["m_kib"], 65536);
        // A smaller value would only give WrongPassword if the KDF ran; Corrupt proves it did not.
        j["slots"][0]["kdf"]["m_kib"] = 4096.into();
        write_json(&p, &j);
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn unknown_version_is_corrupt() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        j["version"] = 3.into();
        write_json(&p, &j);
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn v1_upgrades_on_unlock() {
        let (_d, p) = setup();
        let accounts = vec![sample()];
        write_v1(&p, "pw", &accounts);
        assert_eq!(read_json(&p)["version"], 1);
        let v = unlock(&p, "pw").unwrap();
        assert_eq!(v.accounts, accounts);
        assert_eq!(v.mode(), Mode::Password);
        let j = read_json(&p);
        assert_eq!(j["version"], 2);
        assert_eq!(j["mode"], "password");
        assert_eq!(j["slots"][0]["kind"], "password");
        assert_eq!(unlock(&p, "pw").unwrap().accounts, accounts);
        assert_eq!(unlock(&p, "nope").err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn v1_wrong_password_leaves_file() {
        let (_d, p) = setup();
        write_v1(&p, "pw", &[sample()]);
        let before = std::fs::read(&p).unwrap();
        assert_eq!(unlock(&p, "nope").err(), Some(VaultError::WrongPassword));
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn v1_failed_upgrade_leaves_file() {
        use std::os::unix::fs::PermissionsExt;
        let (d, p) = setup();
        write_v1(&p, "pw", &[sample()]);
        let before = std::fs::read(&p).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = unlock(&p, "pw");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn garbage_is_corrupt() {
        let (_d, p) = setup();
        std::fs::write(&p, "hello").unwrap();
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn missing_file_is_io() {
        let (_d, p) = setup();
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Io(_))));
    }

    #[test]
    fn new_nonce_each_save() {
        let (_d, p) = setup();
        let v = create(&p, "pw").unwrap();
        let n1 = read_json(&p)["nonce"].as_str().unwrap().to_string();
        v.save().unwrap();
        let n2 = read_json(&p)["nonce"].as_str().unwrap().to_string();
        assert_ne!(n1, n2);
    }

    #[test]
    fn set_password_rewraps() {
        let (_d, p) = setup();
        let mut v = create(&p, "old").unwrap();
        v.accounts.push(sample());
        v.save().unwrap();
        let expected = v.accounts.clone();
        let salt1 = read_json(&p)["slots"][0]["kdf"]["salt"].as_str().unwrap().to_string();
        v.set_password(PasswordKek::derive("new").unwrap()).unwrap();
        let j = read_json(&p);
        assert_eq!(j["slots"].as_array().unwrap().len(), 1);
        assert_ne!(j["slots"][0]["kdf"]["salt"].as_str().unwrap(), salt1);
        assert_eq!(unlock(&p, "old").err(), Some(VaultError::WrongPassword));
        assert_eq!(unlock(&p, "new").unwrap().accounts, expected);
    }

    #[test]
    fn failed_set_password_keeps_old() {
        let (d, p) = setup();
        let mut v = create(&p, "old").unwrap();
        let kek = PasswordKek::derive("new").unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_dir(d.path()).unwrap();
        assert!(v.set_password(kek).is_err());
        std::fs::create_dir(d.path()).unwrap();
        v.save().unwrap();
        assert!(unlock(&p, "old").is_ok());
        assert_eq!(unlock(&p, "new").err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn create_refuses_existing() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        assert!(create(&p, "pw").is_err());
        assert!(unlock(&p, "pw").is_ok());
    }

    #[test]
    fn invalid_account_in_plaintext_is_corrupt() {
        let (_d, p) = setup();
        let mut v = create(&p, "pw").unwrap();
        let mut bad = sample();
        bad.digits = 7;
        v.accounts.push(bad);
        v.save().unwrap();
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn delete_removes_file() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        delete(&p).unwrap();
        assert!(!exists(&p));
    }

    #[test]
    fn no_tmp_left_behind() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        assert!(!p.with_extension("json.tmp").exists());
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

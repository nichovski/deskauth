//! Encrypted vault file. A random vault key encrypts the accounts (XChaCha20-Poly1305); each slot
//! holds that key wrapped by a key-encryption key (KEK) only one unlock method can produce.
//! The header (version, mode, slots, nonce) is bound to the ciphertext as AAD.

use std::collections::HashSet;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm as Argon2Alg, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
const KIND_YUBIKEY: &str = "yubikey";
const KIND_FINGERPRINT: &str = "fingerprint";
const KIND_PASSWORD_YUBIKEY: &str = "password_yubikey";
const HKDF_YUBIKEY: &str = "deskauth v2 yubikey";
const HKDF_TWO_FACTOR: &str = "deskauth v2 password+yubikey";
const YUBIKEY_SALT_LEN: usize = 32;

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

/// What an unlock attempt offers. Each variant only works in modes that hold its slot kind.
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

/// A fresh salt and the password+YubiKey KEK derived from it, made without the vault like `PasswordKek`.
pub struct TwoFactorKek {
    salt: [u8; SALT_LEN],
    kek: Zeroizing<[u8; KEY_LEN]>,
}

impl TwoFactorKek {
    pub fn derive(password: &str, hmac: &[u8; 32]) -> Result<TwoFactorKek, VaultError> {
        let salt = random_bytes::<SALT_LEN>();
        let argon = derive_key(password, &salt)?;
        let kek = two_factor_kek(&argon, hmac)?;
        Ok(TwoFactorKek { salt, kek })
    }
}

/// A registered YubiKey as the locked screen sees it: enough to ask the key for its hmac-secret.
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct YubikeyInfo {
    pub id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    pub salt: [u8; YUBIKEY_SALT_LEN],
}

/// The unlock setup, readable without any secret. `yubikeys` holds the slots of the kind the
/// mode uses (`yubikey` in `any`, `password_yubikey` in `password_yubikey`).
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct VaultInfo {
    pub mode: Mode,
    pub yubikeys: Vec<YubikeyInfo>,
    pub fingerprint: Option<String>,
    pub version: u32,
}

impl Slot {
    fn id(&self) -> &str {
        match self {
            Slot::Password { id, .. }
            | Slot::Yubikey { id, .. }
            | Slot::Fingerprint { id, .. }
            | Slot::PasswordYubikey { id, .. } => id,
        }
    }

    /// The YubiKey fields of a `yubikey` or `password_yubikey` slot, decoded.
    fn yubikey_info(&self) -> Option<Result<YubikeyInfo, VaultError>> {
        match self {
            Slot::Yubikey { id, name, credential_id, salt, .. }
            | Slot::PasswordYubikey { id, name, credential_id, salt, .. } => {
                let decoded = decode(credential_id, "credential id").and_then(|credential_id| {
                    Ok(YubikeyInfo {
                        id: id.clone(),
                        name: name.clone(),
                        credential_id,
                        salt: decode_fixed::<YUBIKEY_SALT_LEN>(salt, "YubiKey salt")?,
                    })
                });
                Some(decoded)
            }
            _ => None,
        }
    }

    fn has_credential(&self, credential_id: &[u8]) -> bool {
        match self {
            Slot::Yubikey { credential_id: c, .. } | Slot::PasswordYubikey { credential_id: c, .. } => {
                B64.decode(c).is_ok_and(|c| c == credential_id)
            }
            _ => false,
        }
    }
}

fn yubikey_infos(slots: &[Slot]) -> Result<Vec<YubikeyInfo>, VaultError> {
    slots.iter().filter_map(Slot::yubikey_info).collect()
}

fn fingerprint_ids(slots: &[Slot]) -> Vec<String> {
    slots
        .iter()
        .filter_map(|s| match s {
            Slot::Fingerprint { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect()
}

/// The mode/slot rule: `password` holds only the password slot; `any` holds the password slot,
/// YubiKey slots and at most one fingerprint slot; `password_yubikey` holds one or more two-factor
/// slots and nothing else. Also requires unique slot ids and credential ids, and decodable
/// YubiKey fields.
fn check_slots(mode: Mode, slots: &[Slot]) -> Result<(), VaultError> {
    let count = |kind: fn(&Slot) -> bool| slots.iter().filter(|s| kind(s)).count();
    let passwords = count(|s| matches!(s, Slot::Password { .. }));
    let fingerprints = count(|s| matches!(s, Slot::Fingerprint { .. }));
    let two_factor = count(|s| matches!(s, Slot::PasswordYubikey { .. }));
    let fits = match mode {
        Mode::Password => passwords == 1 && slots.len() == 1,
        Mode::Any => passwords == 1 && fingerprints <= 1 && two_factor == 0,
        Mode::PasswordYubikey => two_factor >= 1 && two_factor == slots.len(),
    };
    if !fits {
        return Err(VaultError::Corrupt("unlock methods do not match the mode".into()));
    }
    let mut ids = HashSet::new();
    if !slots.iter().all(|s| ids.insert(s.id())) {
        return Err(VaultError::Corrupt("two unlock methods share an id".into()));
    }
    let mut credentials = HashSet::new();
    for info in yubikey_infos(slots)? {
        if !credentials.insert(info.credential_id) {
            return Err(VaultError::Corrupt("a YubiKey is registered twice".into()));
        }
    }
    Ok(())
}

fn not_enabled(what: &str) -> VaultError {
    VaultError::NotAllowed(format!("{what} is not enabled for this vault"))
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

fn hkdf(ikm: &[u8], info: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info.as_bytes(), kek.as_mut())
        .map_err(|_| VaultError::Corrupt("key derivation failed".into()))?;
    Ok(kek)
}

fn yubikey_kek(hmac: &[u8; 32]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    hkdf(hmac, HKDF_YUBIKEY)
}

/// HKDF over the Argon2id key followed by the hmac-secret output.
fn two_factor_kek(
    argon: &[u8; KEY_LEN],
    hmac: &[u8; 32],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
    ikm[..KEY_LEN].copy_from_slice(argon);
    ikm[KEY_LEN..].copy_from_slice(hmac);
    hkdf(ikm.as_ref(), HKDF_TWO_FACTOR)
}

/// A `password_yubikey` slot. `credential_id` and `salt` are already base64.
fn two_factor_slot(
    id: String,
    name: String,
    credential_id: String,
    salt: String,
    kek: &TwoFactorKek,
    vault_key: &[u8; KEY_LEN],
) -> Result<Slot, VaultError> {
    let (nonce, wrapped) = wrap(&kek.kek, KIND_PASSWORD_YUBIKEY, &id, vault_key)?;
    Ok(Slot::PasswordYubikey {
        id,
        name,
        kdf: Kdf::new(&kek.salt),
        credential_id,
        salt,
        nonce,
        wrapped,
    })
}

/// A random slot id. Public because the fingerprint slot's OS item is named after it.
pub fn new_slot_id() -> String {
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
    let slot = password_slot(new_slot_id(), &kek, &vault_key)?;
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
        (VERSION_V1, _) => Err(VaultError::NotAllowed(
            "Only the password unlocks this vault".into(),
        )),
        (VERSION, secret) => unlock_v2(path, &bytes, secret),
        _ => Err(VaultError::Corrupt("unsupported version".into())),
    }
}

/// Reads the mode and registered methods without any secret, for the locked screen.
/// The header is not authenticated until unlock; an edited one only makes unlocking fail.
pub fn read_info(path: &Path) -> Result<VaultInfo, VaultError> {
    let bytes = std::fs::read(path).map_err(io_err)?;
    let version: VersionOnly =
        serde_json::from_slice(&bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    match version.version {
        VERSION_V1 => Ok(VaultInfo {
            mode: Mode::Password,
            yubikeys: Vec::new(),
            fingerprint: None,
            version: VERSION_V1,
        }),
        VERSION => {
            let file = parse_v2(&bytes)?;
            Ok(VaultInfo {
                mode: file.mode,
                yubikeys: yubikey_infos(&file.slots)?,
                fingerprint: fingerprint_ids(&file.slots).into_iter().next(),
                version: VERSION,
            })
        }
        _ => Err(VaultError::Corrupt("unsupported version".into())),
    }
}

/// Parses a v2 file and checks its slots fit its mode, before any key derivation.
fn parse_v2(bytes: &[u8]) -> Result<VaultFileV2, VaultError> {
    let file: VaultFileV2 =
        serde_json::from_slice(bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    check_slots(file.mode, &file.slots)?;
    Ok(file)
}

fn unlock_v2(path: &Path, bytes: &[u8], secret: Secret) -> Result<Vault, VaultError> {
    let file = parse_v2(bytes)?;
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
                .ok_or_else(|| not_enabled("Password-only unlock"))?;
            let salt = kdf.checked_salt()?;
            let kek = derive_key(password, &salt)?;
            unwrap(&kek, KIND_PASSWORD, id, slot_nonce, wrapped)?
        }
        Secret::Yubikey { credential_id, hmac } => {
            if file.mode != Mode::Any {
                return Err(not_enabled("YubiKey-only unlock"));
            }
            let (id, slot_nonce, wrapped) = file
                .slots
                .iter()
                .filter(|s| s.has_credential(credential_id))
                .find_map(|s| match s {
                    Slot::Yubikey { id, nonce, wrapped, .. } => Some((id, nonce, wrapped)),
                    _ => None,
                })
                .ok_or(VaultError::NotRegistered)?;
            let kek = yubikey_kek(hmac)?;
            unwrap(&kek, KIND_YUBIKEY, id, slot_nonce, wrapped)?
        }
        Secret::PasswordYubikey {
            password,
            credential_id,
            hmac,
        } => {
            if file.mode != Mode::PasswordYubikey {
                return Err(not_enabled("Password and YubiKey unlock"));
            }
            let (id, kdf, slot_nonce, wrapped) = file
                .slots
                .iter()
                .filter(|s| s.has_credential(credential_id))
                .find_map(|s| match s {
                    Slot::PasswordYubikey { id, kdf, nonce, wrapped, .. } => {
                        Some((id, kdf, nonce, wrapped))
                    }
                    _ => None,
                })
                .ok_or(VaultError::NotRegistered)?;
            let salt = kdf.checked_salt()?;
            let argon = derive_key(password, &salt)?;
            let kek = two_factor_kek(&argon, hmac)?;
            unwrap(&kek, KIND_PASSWORD_YUBIKEY, id, slot_nonce, wrapped)?
        }
        Secret::Fingerprint { secret } => {
            let (id, slot_nonce, wrapped) = file
                .slots
                .iter()
                .find_map(|s| match s {
                    Slot::Fingerprint { id, nonce, wrapped, .. } => Some((id, nonce, wrapped)),
                    _ => None,
                })
                .ok_or_else(|| not_enabled("Fingerprint unlock"))?;
            unwrap(secret, KIND_FINGERPRINT, id, slot_nonce, wrapped)?
        }
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
    vault.slots.push(password_slot(new_slot_id(), &kek, &vault.vault_key)?);
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
        let mut slots = self.slots.clone();
        slots[index] = password_slot(id, &kek, &self.vault_key)?;
        self.commit(self.mode, slots)
    }

    pub fn info(&self) -> VaultInfo {
        VaultInfo {
            mode: self.mode,
            // check_slots accepted these slots on load and on every change, so this cannot fail.
            yubikeys: yubikey_infos(&self.slots).unwrap_or_default(),
            fingerprint: fingerprint_ids(&self.slots).into_iter().next(),
            version: VERSION,
        }
    }

    /// Switches to `mode` and `slots` if they fit the mode/slot rule and the save succeeds;
    /// otherwise keeps the previous mode and slots.
    fn commit(&mut self, mode: Mode, slots: Vec<Slot>) -> Result<(), VaultError> {
        check_slots(mode, &slots)?;
        let old_mode = std::mem::replace(&mut self.mode, mode);
        let old_slots = std::mem::replace(&mut self.slots, slots);
        if let Err(e) = self.save() {
            self.mode = old_mode;
            self.slots = old_slots;
            return Err(e);
        }
        Ok(())
    }

    fn require_mode(&self, mode: Mode, what: &str) -> Result<(), VaultError> {
        if self.mode != mode {
            return Err(not_enabled(what));
        }
        Ok(())
    }

    fn require_new_credential(&self, credential_id: &[u8]) -> Result<(), VaultError> {
        if self.slots.iter().any(|s| s.has_credential(credential_id)) {
            return Err(VaultError::NotAllowed("This YubiKey is already registered".into()));
        }
        Ok(())
    }

    /// Adds a YubiKey that unlocks on its own (mode `any`). Returns the new slot id.
    pub fn add_yubikey(
        &mut self,
        name: &str,
        credential_id: &[u8],
        salt: [u8; YUBIKEY_SALT_LEN],
        hmac: &[u8; 32],
    ) -> Result<String, VaultError> {
        self.require_mode(Mode::Any, "YubiKey-only unlock")?;
        self.require_new_credential(credential_id)?;
        let id = new_slot_id();
        let kek = yubikey_kek(hmac)?;
        let (nonce, wrapped) = wrap(&kek, KIND_YUBIKEY, &id, &self.vault_key)?;
        let mut slots = self.slots.clone();
        slots.push(Slot::Yubikey {
            id: id.clone(),
            name: name.into(),
            credential_id: B64.encode(credential_id),
            salt: B64.encode(salt),
            nonce,
            wrapped,
        });
        self.commit(self.mode, slots)?;
        Ok(id)
    }

    /// Adds a YubiKey that unlocks together with the password (mode `password_yubikey`).
    /// Returns the new slot id.
    pub fn add_yubikey_two_factor(
        &mut self,
        name: &str,
        credential_id: &[u8],
        salt: [u8; YUBIKEY_SALT_LEN],
        kek: TwoFactorKek,
    ) -> Result<String, VaultError> {
        self.require_mode(Mode::PasswordYubikey, "Password and YubiKey unlock")?;
        self.require_new_credential(credential_id)?;
        let id = new_slot_id();
        let slot = two_factor_slot(
            id.clone(),
            name.into(),
            B64.encode(credential_id),
            B64.encode(salt),
            &kek,
            &self.vault_key,
        )?;
        let mut slots = self.slots.clone();
        slots.push(slot);
        self.commit(self.mode, slots)?;
        Ok(id)
    }

    /// Sets the fingerprint slot (mode `any`), replacing any existing one. `slot_id` comes from
    /// the caller because the OS item holding `secret` is named after it.
    pub fn set_fingerprint(
        &mut self,
        slot_id: &str,
        platform: &str,
        secret: &[u8; 32],
    ) -> Result<(), VaultError> {
        self.require_mode(Mode::Any, "Fingerprint unlock")?;
        let (nonce, wrapped) = wrap(secret, KIND_FINGERPRINT, slot_id, &self.vault_key)?;
        let mut slots: Vec<Slot> = self
            .slots
            .iter()
            .filter(|s| !matches!(s, Slot::Fingerprint { .. }))
            .cloned()
            .collect();
        slots.push(Slot::Fingerprint {
            id: slot_id.into(),
            platform: platform.into(),
            nonce,
            wrapped,
        });
        self.commit(self.mode, slots)
    }

    /// Removes one unlock method. The password slot and the last two-factor slot stay.
    pub fn remove_slot(&mut self, id: &str) -> Result<(), VaultError> {
        let slot = self
            .slots
            .iter()
            .find(|s| s.id() == id)
            .ok_or_else(|| VaultError::NotAllowed("This unlock method is not registered".into()))?;
        match slot {
            Slot::Password { .. } => {
                return Err(VaultError::NotAllowed("The password cannot be removed".into()));
            }
            Slot::PasswordYubikey { .. } if self.slots.len() == 1 => {
                return Err(VaultError::NotAllowed(
                    "The last YubiKey cannot be removed, or the vault could not be unlocked".into(),
                ));
            }
            _ => {}
        }
        let slots = self.slots.iter().filter(|s| s.id() != id).cloned().collect();
        self.commit(self.mode, slots)
    }

    /// From `any` (or `password`): keeps only the password slot. Returns the removed fingerprint
    /// slot ids so the caller can delete their OS items.
    pub fn to_password_mode(&mut self) -> Result<Vec<String>, VaultError> {
        if self.mode == Mode::PasswordYubikey {
            return Err(VaultError::NotAllowed(
                "This vault has no password-only unlock to keep".into(),
            ));
        }
        let removed = fingerprint_ids(&self.slots);
        let slots = self
            .slots
            .iter()
            .filter(|s| matches!(s, Slot::Password { .. }))
            .cloned()
            .collect();
        self.commit(Mode::Password, slots)?;
        Ok(removed)
    }

    /// From `password`: only flips the mode, `kek` must be None. From `password_yubikey`: `kek`
    /// is required and one password slot replaces all slots.
    pub fn to_any_mode(&mut self, kek: Option<PasswordKek>) -> Result<(), VaultError> {
        match (self.mode, kek) {
            (Mode::Password, None) => self.commit(Mode::Any, self.slots.clone()),
            (Mode::PasswordYubikey, Some(kek)) => {
                let slot = password_slot(new_slot_id(), &kek, &self.vault_key)?;
                self.commit(Mode::Any, vec![slot])
            }
            (Mode::PasswordYubikey, None) => Err(VaultError::NotAllowed(
                "A new password is needed to leave password and YubiKey mode".into(),
            )),
            (Mode::Password, Some(_)) => Err(VaultError::NotAllowed(
                "The password is changed separately in this mode".into(),
            )),
            (Mode::Any, _) => Err(VaultError::NotAllowed("The vault already uses this mode".into())),
        }
    }

    /// From `password` or `any`: one `password_yubikey` slot replaces all slots. Returns the
    /// removed fingerprint slot ids so the caller can delete their OS items.
    pub fn to_two_factor_mode(
        &mut self,
        name: &str,
        credential_id: &[u8],
        salt: [u8; YUBIKEY_SALT_LEN],
        kek: TwoFactorKek,
    ) -> Result<Vec<String>, VaultError> {
        if self.mode == Mode::PasswordYubikey {
            return Err(VaultError::NotAllowed("The vault already uses this mode".into()));
        }
        let removed = fingerprint_ids(&self.slots);
        let slot = two_factor_slot(
            new_slot_id(),
            name.into(),
            B64.encode(credential_id),
            B64.encode(salt),
            &kek,
            &self.vault_key,
        )?;
        self.commit(Mode::PasswordYubikey, vec![slot])?;
        Ok(removed)
    }

    /// Changes the password in mode `password_yubikey`. Needs a new KEK for every two-factor
    /// slot (each made with that slot's YubiKey), keyed by slot id.
    pub fn change_password_two_factor(
        &mut self,
        keks: Vec<(String, TwoFactorKek)>,
    ) -> Result<(), VaultError> {
        self.require_mode(Mode::PasswordYubikey, "Password and YubiKey unlock")?;
        let not_covered =
            || VaultError::NotAllowed("Every registered YubiKey is needed to change the password".into());
        if keks.len() != self.slots.len() {
            return Err(not_covered());
        }
        // Slot ids are unique, so equal counts and a KEK for each slot means a KEK for every slot.
        let mut slots = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let Slot::PasswordYubikey { id, name, credential_id, salt, .. } = slot else {
                return Err(VaultError::Corrupt("unlock methods do not match the mode".into()));
            };
            let kek = keks
                .iter()
                .find_map(|(k, kek)| (k == id).then_some(kek))
                .ok_or_else(not_covered)?;
            slots.push(two_factor_slot(
                id.clone(),
                name.clone(),
                credential_id.clone(),
                salt.clone(),
                kek,
                &self.vault_key,
            )?);
        }
        self.commit(self.mode, slots)
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

    const CRED: &[u8] = b"credential-1";
    const CRED2: &[u8] = b"credential-2";
    const SALT: [u8; 32] = [7u8; 32];
    const HMAC: [u8; 32] = [1u8; 32];
    const HMAC2: [u8; 32] = [2u8; 32];
    const FP: [u8; 32] = [9u8; 32];

    fn yubikey<'a>(credential_id: &'a [u8], hmac: &'a [u8; 32]) -> Secret<'a> {
        Secret::Yubikey {
            credential_id,
            hmac,
        }
    }

    fn two_factor<'a>(password: &'a str, credential_id: &'a [u8], hmac: &'a [u8; 32]) -> Secret<'a> {
        Secret::PasswordYubikey {
            password,
            credential_id,
            hmac,
        }
    }

    /// A vault in mode `any` with one account.
    fn any_vault(p: &Path) -> Vault {
        let mut v = create(p, "pw").unwrap();
        v.accounts.push(sample());
        v.to_any_mode(None).unwrap();
        v
    }

    /// A vault in mode `password_yubikey` with one key (CRED/HMAC) and one account.
    fn two_factor_vault(p: &Path) -> Vault {
        let mut v = create(p, "pw").unwrap();
        v.accounts.push(sample());
        let kek = TwoFactorKek::derive("pw", &HMAC).unwrap();
        v.to_two_factor_mode("Blue", CRED, SALT, kek).unwrap();
        v
    }

    #[test]
    fn yubikey_slot_round_trip() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        let id = v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        let expected = v.accounts.clone();
        let u = unlock_with(&p, yubikey(CRED, &HMAC)).unwrap();
        assert_eq!(u.accounts, expected);
        assert_eq!(u.mode(), Mode::Any);
        assert_eq!(unlock(&p, "pw").unwrap().accounts, expected);
        let info = u.info();
        assert_eq!(info.yubikeys.len(), 1);
        assert_eq!(info.yubikeys[0].id, id);
        assert_eq!(info.yubikeys[0].name, "Blue");
        assert_eq!(info.yubikeys[0].credential_id, CRED);
        assert_eq!(info.yubikeys[0].salt, SALT);
        assert_eq!(read_json(&p)["slots"][1]["kind"], "yubikey");
    }

    #[test]
    fn yubikey_wrong_hmac_fails() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        assert_eq!(
            unlock_with(&p, yubikey(CRED, &HMAC2)).err(),
            Some(VaultError::WrongPassword)
        );
    }

    #[test]
    fn unknown_credential_is_not_registered() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        assert_eq!(
            unlock_with(&p, yubikey(CRED2, &HMAC)).err(),
            Some(VaultError::NotRegistered)
        );
    }

    #[test]
    fn yubikey_refused_in_password_mode() {
        let (_d, p) = setup();
        let mut v = create(&p, "pw").unwrap();
        assert!(matches!(
            v.add_yubikey("Blue", CRED, SALT, &HMAC),
            Err(VaultError::NotAllowed(_))
        ));
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotAllowed(_))
        ));
    }

    #[test]
    fn two_factor_needs_both() {
        let (_d, p) = setup();
        let v = two_factor_vault(&p);
        let expected = v.accounts.clone();
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::NotAllowed(_))));
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotAllowed(_))
        ));
        assert_eq!(
            unlock_with(&p, two_factor("nope", CRED, &HMAC)).err(),
            Some(VaultError::WrongPassword)
        );
        assert_eq!(
            unlock_with(&p, two_factor("pw", CRED, &HMAC2)).err(),
            Some(VaultError::WrongPassword)
        );
        assert_eq!(
            unlock_with(&p, two_factor("pw", CRED2, &HMAC)).err(),
            Some(VaultError::NotRegistered)
        );
        let u = unlock_with(&p, two_factor("pw", CRED, &HMAC)).unwrap();
        assert_eq!(u.accounts, expected);
        assert_eq!(u.mode(), Mode::PasswordYubikey);
    }

    #[test]
    fn two_factor_second_key() {
        let (_d, p) = setup();
        let mut v = two_factor_vault(&p);
        let kek = TwoFactorKek::derive("pw", &HMAC2).unwrap();
        v.add_yubikey_two_factor("Red", CRED2, SALT, kek).unwrap();
        assert!(unlock_with(&p, two_factor("pw", CRED2, &HMAC2)).is_ok());
        assert!(unlock_with(&p, two_factor("pw", CRED, &HMAC)).is_ok());
        assert_eq!(v.info().yubikeys.len(), 2);
    }

    #[test]
    fn fingerprint_round_trip_and_wrong_secret() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        let id = new_slot_id();
        v.set_fingerprint(&id, "linux", &FP).unwrap();
        assert_eq!(v.info().fingerprint, Some(id.clone()));
        let u = unlock_with(&p, Secret::Fingerprint { secret: &FP }).unwrap();
        assert_eq!(u.accounts, v.accounts);
        assert_eq!(
            unlock_with(&p, Secret::Fingerprint { secret: &[0u8; 32] }).err(),
            Some(VaultError::WrongPassword)
        );
        // Setting it again replaces the slot.
        let id2 = new_slot_id();
        v.set_fingerprint(&id2, "linux", &HMAC).unwrap();
        let j = read_json(&p);
        let kinds: Vec<_> = j["slots"].as_array().unwrap().iter().map(|s| s["kind"].clone()).collect();
        assert_eq!(kinds, vec!["password", "fingerprint"]);
        assert_eq!(v.info().fingerprint, Some(id2));
        assert!(unlock_with(&p, Secret::Fingerprint { secret: &HMAC }).is_ok());
        assert_eq!(
            unlock_with(&p, Secret::Fingerprint { secret: &FP }).err(),
            Some(VaultError::WrongPassword)
        );
    }

    #[test]
    fn fingerprint_refused_in_two_factor_mode() {
        let (_d, p) = setup();
        let mut v = two_factor_vault(&p);
        assert!(matches!(
            v.set_fingerprint(&new_slot_id(), "linux", &FP),
            Err(VaultError::NotAllowed(_))
        ));
        assert!(matches!(
            unlock_with(&p, Secret::Fingerprint { secret: &FP }),
            Err(VaultError::NotAllowed(_))
        ));
    }

    #[test]
    fn cannot_remove_password_slot() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        let yk = v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        let pw_id = read_json(&p)["slots"][0]["id"].as_str().unwrap().to_string();
        assert!(matches!(v.remove_slot(&pw_id), Err(VaultError::NotAllowed(_))));
        v.remove_slot(&yk).unwrap();
        assert!(v.info().yubikeys.is_empty());
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotRegistered)
        ));
        assert!(unlock(&p, "pw").is_ok());
    }

    #[test]
    fn cannot_remove_last_two_factor_slot() {
        let (_d, p) = setup();
        let mut v = two_factor_vault(&p);
        let first = v.info().yubikeys[0].id.clone();
        assert!(matches!(v.remove_slot(&first), Err(VaultError::NotAllowed(_))));
        let kek = TwoFactorKek::derive("pw", &HMAC2).unwrap();
        let second = v.add_yubikey_two_factor("Red", CRED2, SALT, kek).unwrap();
        v.remove_slot(&first).unwrap();
        assert!(matches!(v.remove_slot(&second), Err(VaultError::NotAllowed(_))));
        assert!(unlock_with(&p, two_factor("pw", CRED2, &HMAC2)).is_ok());
    }

    #[test]
    fn to_two_factor_drops_other_slots() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        let fp = new_slot_id();
        v.set_fingerprint(&fp, "linux", &FP).unwrap();
        let kek = TwoFactorKek::derive("pw2", &HMAC2).unwrap();
        let removed = v.to_two_factor_mode("Red", CRED2, SALT, kek).unwrap();
        assert_eq!(removed, vec![fp]);
        assert_eq!(v.mode(), Mode::PasswordYubikey);
        let j = read_json(&p);
        assert_eq!(j["mode"], "password_yubikey");
        assert_eq!(j["slots"].as_array().unwrap().len(), 1);
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::NotAllowed(_))));
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotAllowed(_))
        ));
        assert!(matches!(
            unlock_with(&p, Secret::Fingerprint { secret: &FP }),
            Err(VaultError::NotAllowed(_))
        ));
        assert_eq!(
            unlock_with(&p, two_factor("pw2", CRED2, &HMAC2)).unwrap().accounts,
            v.accounts
        );
    }

    #[test]
    fn to_any_from_two_factor_needs_kek() {
        let (_d, p) = setup();
        let mut v = two_factor_vault(&p);
        assert!(matches!(v.to_any_mode(None), Err(VaultError::NotAllowed(_))));
        assert_eq!(v.mode(), Mode::PasswordYubikey);
        v.to_any_mode(Some(PasswordKek::derive("new").unwrap())).unwrap();
        assert_eq!(v.mode(), Mode::Any);
        assert!(v.info().yubikeys.is_empty());
        assert_eq!(unlock(&p, "new").unwrap().accounts, v.accounts);
        assert!(matches!(
            unlock_with(&p, two_factor("pw", CRED, &HMAC)),
            Err(VaultError::NotAllowed(_))
        ));
    }

    #[test]
    fn to_password_mode_drops_methods() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        let fp = new_slot_id();
        v.set_fingerprint(&fp, "linux", &FP).unwrap();
        assert_eq!(v.to_password_mode().unwrap(), vec![fp]);
        assert_eq!(v.mode(), Mode::Password);
        let j = read_json(&p);
        assert_eq!(j["mode"], "password");
        assert_eq!(j["slots"].as_array().unwrap().len(), 1);
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotAllowed(_))
        ));
        assert!(unlock(&p, "pw").is_ok());
    }

    #[test]
    fn change_password_two_factor_must_cover_all() {
        let (_d, p) = setup();
        let mut v = two_factor_vault(&p);
        let first = v.info().yubikeys[0].id.clone();
        let kek = TwoFactorKek::derive("pw", &HMAC2).unwrap();
        let second = v.add_yubikey_two_factor("Red", CRED2, SALT, kek).unwrap();
        let partial = vec![(first.clone(), TwoFactorKek::derive("new", &HMAC).unwrap())];
        assert!(matches!(
            v.change_password_two_factor(partial),
            Err(VaultError::NotAllowed(_))
        ));
        assert!(unlock_with(&p, two_factor("pw", CRED, &HMAC)).is_ok());
        let all = vec![
            (first, TwoFactorKek::derive("new", &HMAC).unwrap()),
            (second, TwoFactorKek::derive("new", &HMAC2).unwrap()),
        ];
        v.change_password_two_factor(all).unwrap();
        assert_eq!(
            unlock_with(&p, two_factor("pw", CRED, &HMAC)).err(),
            Some(VaultError::WrongPassword)
        );
        assert!(unlock_with(&p, two_factor("new", CRED, &HMAC)).is_ok());
        assert!(unlock_with(&p, two_factor("new", CRED2, &HMAC2)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn failed_save_restores_slots() {
        use std::os::unix::fs::PermissionsExt;
        let (d, p) = setup();
        let mut v = any_vault(&p);
        let before = v.info();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = v.add_yubikey("Blue", CRED, SALT, &HMAC);
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert_eq!(v.info(), before);
        v.save().unwrap();
        assert!(matches!(
            unlock_with(&p, yubikey(CRED, &HMAC)),
            Err(VaultError::NotRegistered)
        ));
    }

    #[test]
    fn read_info_has_no_secrets() {
        let (_d, p) = setup();
        let mut v = any_vault(&p);
        v.add_yubikey("Blue", CRED, SALT, &HMAC).unwrap();
        let fp = new_slot_id();
        v.set_fingerprint(&fp, "linux", &FP).unwrap();
        let info = read_info(&p).unwrap();
        assert_eq!(info, v.info());
        assert_eq!(info.mode, Mode::Any);
        assert_eq!(info.version, 2);
        assert_eq!(info.fingerprint, Some(fp));
        let j = serde_json::to_value(&info).unwrap();
        let mut keys: Vec<_> = j.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["fingerprint", "mode", "version", "yubikeys"]);
        let mut yk_keys: Vec<_> = j["yubikeys"][0].as_object().unwrap().keys().cloned().collect();
        yk_keys.sort();
        assert_eq!(yk_keys, vec!["credential_id", "id", "name", "salt"]);
        let text = j.to_string();
        for word in ["wrapped", "nonce", "kdf", "ciphertext"] {
            assert!(!text.contains(word), "{word} leaked");
        }
    }

    #[test]
    fn read_info_v1_is_password_mode() {
        let (_d, p) = setup();
        write_v1(&p, "pw", &[]);
        let info = read_info(&p).unwrap();
        assert_eq!(info.mode, Mode::Password);
        assert_eq!(info.version, 1);
        assert!(info.yubikeys.is_empty());
        assert_eq!(info.fingerprint, None);
    }

    #[test]
    fn extra_slot_breaking_mode_is_corrupt() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        let fake = serde_json::json!({
            "id": "AAAAAAAAAAAAAAAAAAAAAA==",
            "kind": "yubikey",
            "name": "Fake",
            "credential_id": B64.encode(CRED),
            "salt": B64.encode(SALT),
            "nonce": B64.encode([0u8; NONCE_LEN]),
            "wrapped": B64.encode([0u8; 48]),
        });
        j["slots"].as_array_mut().unwrap().push(fake);
        write_json(&p, &j);
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
        assert!(matches!(read_info(&p), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn second_password_slot_is_corrupt() {
        let (_d, p) = setup();
        any_vault(&p);
        let mut j = read_json(&p);
        let mut extra = j["slots"][0].clone();
        extra["id"] = "AAAAAAAAAAAAAAAAAAAAAA==".into();
        j["slots"].as_array_mut().unwrap().push(extra);
        write_json(&p, &j);
        assert!(matches!(unlock(&p, "pw"), Err(VaultError::Corrupt(_))));
    }
}

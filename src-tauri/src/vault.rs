//! Encrypted vault file: Argon2id key derivation + XChaCha20-Poly1305.
//! The header (version, kdf params, nonce) is bound to the ciphertext as AAD.

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

const VERSION: u32 = 1;
const ALG: &str = "argon2id";
const M_KIB: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, PartialEq)]
pub enum VaultError {
    WrongPassword,
    Corrupt(String),
    Io(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::WrongPassword => write!(f, "Wrong password"),
            VaultError::Corrupt(m) => write!(f, "Vault file is damaged: {m}"),
            VaultError::Io(m) => write!(f, "Could not read vault: {m}"),
        }
    }
}

impl std::error::Error for VaultError {}

#[derive(Serialize, Deserialize, Clone)]
struct Kdf {
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// The authenticated part of the file. Field order is part of the AAD format.
#[derive(Serialize, Deserialize, Clone)]
struct Header {
    version: u32,
    kdf: Kdf,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: Kdf,
    nonce: String,
    ciphertext: String,
}

pub struct Vault {
    pub accounts: Vec<Account>,
    path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
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

fn aad(header: &Header) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(header).map_err(|e| VaultError::Corrupt(e.to_string()))
}

fn decode_fixed<const N: usize>(s: &str, what: &str) -> Result<[u8; N], VaultError> {
    let v = B64
        .decode(s)
        .map_err(|_| VaultError::Corrupt(format!("{what} is not valid base64")))?;
    v.try_into()
        .map_err(|_| VaultError::Corrupt(format!("{what} has the wrong length")))
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

pub fn create(path: &Path, password: &str) -> Result<Vault, VaultError> {
    if path.exists() {
        return Err(VaultError::Io("vault already exists".into()));
    }
    let salt = random_bytes::<SALT_LEN>();
    let key = derive_key(password, &salt)?;
    let vault = Vault {
        accounts: Vec::new(),
        path: path.to_path_buf(),
        key,
        salt,
    };
    vault.save()?;
    Ok(vault)
}

pub fn unlock(path: &Path, password: &str) -> Result<Vault, VaultError> {
    let bytes = std::fs::read(path).map_err(io_err)?;
    let file: VaultFile =
        serde_json::from_slice(&bytes).map_err(|e| VaultError::Corrupt(e.to_string()))?;

    if file.version != VERSION {
        return Err(VaultError::Corrupt("unsupported version".into()));
    }
    // Reject anything but our own parameters before spending memory on the KDF.
    if file.kdf.alg != ALG
        || file.kdf.m_kib != M_KIB
        || file.kdf.t != T_COST
        || file.kdf.p != P_COST
    {
        return Err(VaultError::Corrupt("unsupported key derivation settings".into()));
    }
    let salt = decode_fixed::<SALT_LEN>(&file.kdf.salt, "salt")?;
    let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
    let ciphertext = B64
        .decode(&file.ciphertext)
        .map_err(|_| VaultError::Corrupt("ciphertext is not valid base64".into()))?;

    let header = Header {
        version: file.version,
        kdf: file.kdf,
        nonce: file.nonce,
    };
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&header)?,
                },
            )
            .map_err(|_| VaultError::WrongPassword)?,
    );

    let accounts: Vec<Account> = serde_json::from_slice(&plaintext)
        .map_err(|_| VaultError::Corrupt("vault contents are invalid".into()))?;
    // Wrap now so secrets are wiped even if validation fails below.
    let vault = Vault {
        accounts,
        path: path.to_path_buf(),
        key,
        salt,
    };
    for a in &vault.accounts {
        a.validate().map_err(VaultError::Corrupt)?;
    }
    Ok(vault)
}

pub fn delete(path: &Path) -> Result<(), VaultError> {
    std::fs::remove_file(path).map_err(io_err)
}

impl Vault {
    pub fn save(&self) -> Result<(), VaultError> {
        let nonce = random_bytes::<NONCE_LEN>();
        let header = Header {
            version: VERSION,
            kdf: Kdf {
                alg: ALG.into(),
                m_kib: M_KIB,
                t: T_COST,
                p: P_COST,
                salt: B64.encode(self.salt),
            },
            nonce: B64.encode(nonce),
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.accounts).map_err(|e| VaultError::Corrupt(e.to_string()))?,
        );
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad(&header)?,
                },
            )
            .map_err(|_| VaultError::Corrupt("encryption failed".into()))?;
        let file = VaultFile {
            version: header.version,
            kdf: header.kdf,
            nonce: header.nonce,
            ciphertext: B64.encode(ciphertext),
        };
        let out = serde_json::to_vec(&file).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &out)
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(new_password, &salt)?;
        let old_key = std::mem::replace(&mut self.key, key);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        if let Err(e) = self.save() {
            self.key = old_key;
            self.salt = old_salt;
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

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vault.json");
        (dir, p)
    }

    #[test]
    fn round_trip() {
        let (_d, p) = setup();
        let mut v = create(&p, "pw").unwrap();
        assert!(exists(&p));
        v.accounts.push(sample());
        v.save().unwrap();
        let expected = v.accounts.clone();
        let u = unlock(&p, "pw").unwrap();
        assert_eq!(u.accounts, expected);
    }

    #[test]
    fn wrong_password() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        assert_eq!(unlock(&p, "nope").err(), Some(VaultError::WrongPassword));
    }

    #[test]
    fn tampered_header_fails() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        assert_eq!(j["kdf"]["t"], 3);
        j["kdf"]["t"] = 2.into();
        std::fs::write(&p, serde_json::to_vec(&j).unwrap()).unwrap();
        assert!(unlock(&p, "pw").is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let (_d, p) = setup();
        create(&p, "pw").unwrap();
        let mut j = read_json(&p);
        j["nonce"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        std::fs::write(&p, serde_json::to_vec(&j).unwrap()).unwrap();
        assert!(unlock(&p, "pw").is_err());
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
    fn change_password() {
        let (_d, p) = setup();
        let mut v = create(&p, "old").unwrap();
        v.accounts.push(sample());
        v.save().unwrap();
        let salt1 = read_json(&p)["kdf"]["salt"].as_str().unwrap().to_string();
        v.change_password("new").unwrap();
        let salt2 = read_json(&p)["kdf"]["salt"].as_str().unwrap().to_string();
        assert_ne!(salt1, salt2);
        assert_eq!(unlock(&p, "old").err(), Some(VaultError::WrongPassword));
        assert_eq!(unlock(&p, "new").unwrap().accounts.len(), 1);
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

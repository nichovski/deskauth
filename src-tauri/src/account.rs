use serde::{Deserialize, Serialize};

const B32: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub name: String,
    /// base32, uppercase, no padding, no spaces
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

pub fn normalize_secret(input: &str) -> Result<String, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect::<String>()
        .to_uppercase();
    if cleaned.is_empty() {
        return Err("secret is empty".into());
    }
    match base32::decode(B32, &cleaned) {
        Some(bytes) if !bytes.is_empty() => Ok(cleaned),
        _ => Err("secret is not valid base32".into()),
    }
}

impl Account {
    pub fn new(
        issuer: &str,
        name: &str,
        secret: &str,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Account, String> {
        if digits != 6 && digits != 8 {
            return Err("digits must be 6 or 8".into());
        }
        if period == 0 {
            return Err("period must be greater than 0".into());
        }
        Ok(Account {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.to_string(),
            name: name.to_string(),
            secret: normalize_secret(secret)?,
            algorithm,
            digits,
            period,
        })
    }

    pub fn from_secret_bytes(
        issuer: &str,
        name: &str,
        secret: &[u8],
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Account {
        Account {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.to_string(),
            name: name.to_string(),
            secret: base32::encode(B32, secret),
            algorithm,
            digits,
            period,
        }
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        base32::decode(B32, &self.secret).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_secret() {
        assert_eq!(normalize_secret("jbsw y3dp ehpk 3pxp==").unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn rejects_bad_secret() {
        assert!(normalize_secret("not base32!").is_err());
        assert!(normalize_secret("").is_err());
    }

    #[test]
    fn rejects_bad_digits() {
        assert!(Account::new("a", "b", "JBSWY3DPEHPK3PXP", Algorithm::Sha1, 7, 30).is_err());
    }
}

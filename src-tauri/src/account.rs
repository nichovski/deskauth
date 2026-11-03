use serde::{Deserialize, Serialize};
use std::fmt;

const B32: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
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

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

fn decodes_to_bytes(secret: &str) -> bool {
    matches!(base32::decode(B32, secret), Some(b) if !b.is_empty())
}

pub fn normalize_secret(input: &str) -> Result<String, String> {
    let squeezed: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let cleaned = squeezed.trim_end_matches('=').to_string();
    if cleaned.is_empty() {
        return Err("secret is empty".into());
    }
    if !decodes_to_bytes(&cleaned) {
        return Err("secret is not valid base32".into());
    }
    Ok(cleaned)
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
        let account = Account {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.to_string(),
            name: name.to_string(),
            secret: normalize_secret(secret)?,
            algorithm,
            digits,
            period,
        };
        account.validate()?;
        Ok(account)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.digits != 6 && self.digits != 8 {
            return Err("digits must be 6 or 8".into());
        }
        if self.period == 0 {
            return Err("period must be greater than 0".into());
        }
        if !decodes_to_bytes(&self.secret) {
            return Err("secret is not valid base32".into());
        }
        Ok(())
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

    #[test]
    fn rejects_misplaced_padding() {
        assert!(normalize_secret("AB=CD").is_err());
    }

    #[test]
    fn debug_redacts_secret() {
        let a = Account::new("a", "b", "JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30).unwrap();
        assert!(!format!("{:?}", a).contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn validate_rejects_invalid() {
        let mut a = Account::new("a", "b", "JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30).unwrap();
        assert!(a.validate().is_ok());
        a.digits = 10;
        assert!(a.validate().is_err());
        a.digits = 6;
        a.period = 0;
        assert!(a.validate().is_err());
        a.period = 30;
        a.secret = "not base32!".into();
        assert!(a.validate().is_err());
    }

    #[test]
    fn new_succeeds_and_round_trips() {
        let a = Account::new("a", "b", "jbsw y3dp ehpk 3pxp", Algorithm::Sha1, 6, 30).unwrap();
        assert!(!a.id.is_empty());
        assert_eq!(a.secret_bytes(), b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn algorithm_serializes_uppercase() {
        assert_eq!(serde_json::to_string(&Algorithm::Sha1).unwrap(), "\"SHA1\"");
    }
}

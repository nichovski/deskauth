use crate::account::Account;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, PartialEq)]
pub struct MergeResult {
    pub added: usize,
    pub skipped_duplicates: usize,
    pub skipped_unsupported: usize,
}

/// A duplicate is an account with the same secret bytes, in `existing` or earlier in `incoming`.
pub fn merge(existing: &mut Vec<Account>, incoming: Vec<Account>) -> MergeResult {
    // Zeroizing is not Hashable; a vault holds few accounts, so a linear scan is fine.
    let mut seen: Vec<Zeroizing<Vec<u8>>> = existing.iter().map(Account::secret_bytes).collect();
    let mut added = 0;
    let mut skipped_duplicates = 0;
    for account in incoming {
        let bytes = account.secret_bytes();
        if !seen.iter().any(|s| s[..] == bytes[..]) {
            seen.push(bytes);
            existing.push(account);
            added += 1;
        } else {
            skipped_duplicates += 1;
        }
    }
    MergeResult { added, skipped_duplicates, skipped_unsupported: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Algorithm;

    fn acct(issuer: &str, secret: &[u8]) -> Account {
        Account::from_secret_bytes(issuer, "me", secret, Algorithm::Sha1, 6, 30)
    }

    #[test]
    fn same_import_twice_adds_zero() {
        let mut v = Vec::new();
        let r = merge(&mut v, vec![acct("A", b"one"), acct("B", b"two")]);
        assert_eq!(r, MergeResult { added: 2, skipped_duplicates: 0, skipped_unsupported: 0 });
        let r = merge(&mut v, vec![acct("A", b"one"), acct("B", b"two")]);
        assert_eq!(r, MergeResult { added: 0, skipped_duplicates: 2, skipped_unsupported: 0 });
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn one_new_adds_one() {
        let mut v = vec![acct("A", b"one"), acct("B", b"two")];
        let r = merge(&mut v, vec![acct("A", b"one"), acct("B", b"two"), acct("C", b"three")]);
        assert_eq!(r.added, 1);
        assert_eq!(r.skipped_duplicates, 2);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn renamed_same_secret_is_duplicate() {
        let mut v = vec![acct("A", b"one")];
        let r = merge(&mut v, vec![acct("Renamed", b"one")]);
        assert_eq!(r.added, 0);
        assert_eq!(v[0].issuer, "A");
    }

    #[test]
    fn duplicate_inside_incoming() {
        let mut v = Vec::new();
        let r = merge(&mut v, vec![acct("A", b"one"), acct("A", b"one")]);
        assert_eq!(r, MergeResult { added: 1, skipped_duplicates: 1, skipped_unsupported: 0 });
    }
}

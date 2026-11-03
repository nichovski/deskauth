use crate::account::Account;
use crate::migration::parse_uri;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ImportProgress {
    pub batches_seen: Vec<u32>,
    pub batch_size: Option<u32>,
    pub accounts: usize,
    pub skipped_unsupported: usize,
    pub complete: bool,
}

#[derive(Default)]
pub struct ImportSession {
    batch_id: Option<i32>,
    batch_size: Option<u32>,
    seen: BTreeSet<u32>,
    accounts: Vec<Account>,
    skipped_unsupported: usize,
    /// Hashes of non-batched QR contents already counted, so a QR held in view is not counted again.
    seen_plain: BTreeSet<u64>,
}

impl ImportSession {
    pub fn add_uri(&mut self, uri: &str) -> Result<ImportProgress, String> {
        let parsed = parse_uri(uri)?;
        match parsed.batch {
            Some(batch) => {
                if self.batch_id != Some(batch.id) {
                    *self = ImportSession { batch_id: Some(batch.id), batch_size: Some(batch.size), ..Default::default() };
                }
                if self.seen.insert(batch.index) {
                    self.accounts.extend(parsed.accounts);
                    self.skipped_unsupported += parsed.skipped_unsupported;
                }
            }
            None => {
                let mut hasher = DefaultHasher::new();
                uri.hash(&mut hasher);
                if self.seen_plain.insert(hasher.finish()) {
                    self.accounts.extend(parsed.accounts);
                    self.skipped_unsupported += parsed.skipped_unsupported;
                }
            }
        }
        Ok(self.progress())
    }

    pub fn progress(&self) -> ImportProgress {
        let complete = match self.batch_size {
            Some(size) => (0..size).all(|i| self.seen.contains(&i)),
            None => true,
        };
        ImportProgress {
            batches_seen: self.seen.iter().copied().collect(),
            batch_size: self.batch_size,
            accounts: self.accounts.len(),
            skipped_unsupported: self.skipped_unsupported,
            complete,
        }
    }

    pub fn take(&mut self) -> (Vec<Account>, usize) {
        let s = std::mem::take(self);
        (s.accounts, s.skipped_unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct Payload {
        #[prost(message, repeated, tag = "1")]
        otp_parameters: Vec<Otp>,
        #[prost(int32, tag = "2")]
        version: i32,
        #[prost(int32, tag = "3")]
        batch_size: i32,
        #[prost(int32, tag = "4")]
        batch_index: i32,
        #[prost(int32, tag = "5")]
        batch_id: i32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct Otp {
        #[prost(bytes = "vec", tag = "1")]
        secret: Vec<u8>,
        #[prost(string, tag = "2")]
        name: String,
        #[prost(string, tag = "3")]
        issuer: String,
        #[prost(int32, tag = "4")]
        algorithm: i32,
        #[prost(int32, tag = "5")]
        digits: i32,
        #[prost(int32, tag = "6")]
        r#type: i32,
        #[prost(int64, tag = "7")]
        counter: i64,
    }

    fn migration_uri(secrets: &[&[u8]], size: i32, index: i32, id: i32) -> String {
        let otp_parameters = secrets
            .iter()
            .map(|s| Otp { secret: s.to_vec(), name: "n".into(), issuer: "i".into(), algorithm: 1, digits: 1, r#type: 2, counter: 0 })
            .collect();
        let p = Payload { otp_parameters, version: 1, batch_size: size, batch_index: index, batch_id: id };
        let data = base64::engine::general_purpose::STANDARD.encode(p.encode_to_vec());
        let data = data.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
        format!("otpauth-migration://offline?data={data}")
    }

    #[test]
    fn single_qr_completes() {
        let mut s = ImportSession::default();
        let p = s.add_uri(&migration_uri(&[b"one", b"two"], 1, 0, 5)).unwrap();
        assert!(p.complete);
        assert_eq!(p.accounts, 2);
        let p = ImportSession::default()
            .add_uri("otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&issuer=Acme")
            .unwrap();
        assert!(p.complete);
        assert_eq!(p.accounts, 1);
    }

    #[test]
    fn batches_complete_after_all() {
        let mut s = ImportSession::default();
        let p = s.add_uri(&migration_uri(&[b"one"], 2, 0, 9)).unwrap();
        assert!(!p.complete);
        assert_eq!(p.batches_seen, vec![0]);
        assert_eq!(p.batch_size, Some(2));
        let again = s.add_uri(&migration_uri(&[b"one"], 2, 0, 9)).unwrap();
        assert_eq!(again, p);
        let p = s.add_uri(&migration_uri(&[b"two", b"three"], 2, 1, 9)).unwrap();
        assert!(p.complete);
        assert_eq!(p.batches_seen, vec![0, 1]);
        assert_eq!(p.accounts, 3);
    }

    #[test]
    fn new_batch_id_restarts() {
        let mut s = ImportSession::default();
        s.add_uri(&migration_uri(&[b"one"], 2, 0, 1)).unwrap();
        let p = s.add_uri(&migration_uri(&[b"two", b"three"], 2, 0, 2)).unwrap();
        assert_eq!(p.batches_seen, vec![0]);
        assert_eq!(p.accounts, 2);
        assert!(!p.complete);
    }

    #[test]
    fn skipped_unsupported_accumulates_once_per_batch() {
        let mut s = ImportSession::default();
        // type 1 (HOTP) is unsupported and skipped by the parser
        let hotp = |idx| {
            let p = Payload {
                otp_parameters: vec![Otp { secret: b"h".to_vec(), name: "n".into(), issuer: "i".into(), algorithm: 1, digits: 1, r#type: 1, counter: 0 }],
                version: 1, batch_size: 2, batch_index: idx, batch_id: 3,
            };
            let d = base64::engine::general_purpose::STANDARD.encode(p.encode_to_vec());
            format!("otpauth-migration://offline?data={}", d.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"))
        };
        s.add_uri(&hotp(0)).unwrap();
        s.add_uri(&hotp(0)).unwrap();
        s.add_uri(&hotp(1)).unwrap();
        assert_eq!(s.take().1, 2);
    }

    #[test]
    fn same_plain_qr_is_counted_once() {
        let mut s = ImportSession::default();
        let hotp = "otpauth-migration://offline?data=".to_string() + &{
            let p = Payload {
                otp_parameters: vec![Otp { secret: b"h".to_vec(), name: "n".into(), issuer: "i".into(), algorithm: 1, digits: 1, r#type: 1, counter: 0 }],
                version: 1, batch_size: 0, batch_index: 0, batch_id: 0,
            };
            let d = base64::engine::general_purpose::STANDARD.encode(p.encode_to_vec());
            d.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
        };
        for _ in 0..5 {
            s.add_uri(&hotp).unwrap();
        }
        let plain = "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
        s.add_uri(plain).unwrap();
        let p = s.add_uri(plain).unwrap();
        assert_eq!((p.accounts, p.skipped_unsupported), (1, 1));
    }

    #[test]
    fn take_resets() {
        let mut s = ImportSession::default();
        s.add_uri(&migration_uri(&[b"one"], 1, 0, 1)).unwrap();
        let (accounts, skipped) = s.take();
        assert_eq!((accounts.len(), skipped), (1, 0));
        assert_eq!(s.progress().accounts, 0);
        assert!(s.progress().batches_seen.is_empty());
    }
}

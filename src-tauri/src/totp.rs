use crate::account::{Account, Algorithm};
use hmac::{Hmac, Mac};

fn hmac_digest<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn code(account: &Account, unix_time: u64) -> String {
    let counter = (unix_time / account.period).to_be_bytes();
    let key = account.secret_bytes();
    let hash = match account.algorithm {
        Algorithm::Sha1 => hmac_digest::<Hmac<sha1::Sha1>>(&key, &counter),
        Algorithm::Sha256 => hmac_digest::<Hmac<sha2::Sha256>>(&key, &counter),
        Algorithm::Sha512 => hmac_digest::<Hmac<sha2::Sha512>>(&key, &counter),
    };
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let value = bin % 10u32.pow(account.digits);
    format!("{:0width$}", value, width = account.digits as usize)
}

pub fn remaining_seconds(period: u64, unix_time: u64) -> u64 {
    period - unix_time % period
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Algorithm};

    fn acc(secret: &[u8], alg: Algorithm, digits: u32) -> Account {
        Account::from_secret_bytes("i", "n", secret, alg, digits, 30)
    }

    #[test]
    fn rfc6238_vectors() {
        let sha1 = acc(b"12345678901234567890", Algorithm::Sha1, 8);
        let sha256 = acc(b"12345678901234567890123456789012", Algorithm::Sha256, 8);
        let sha512 = acc(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            Algorithm::Sha512,
            8,
        );
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c2, c3) in cases {
            assert_eq!(code(&sha1, t), c1);
            assert_eq!(code(&sha256, t), c2);
            assert_eq!(code(&sha512, t), c3);
        }
    }

    #[test]
    fn six_digits_zero_padded() {
        let a = acc(b"12345678901234567890", Algorithm::Sha1, 6);
        assert_eq!(code(&a, 1111111109), "081804");
    }

    #[test]
    fn remaining() {
        assert_eq!(remaining_seconds(30, 59), 1);
        assert_eq!(remaining_seconds(30, 60), 30);
    }
}

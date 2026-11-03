use crate::account::{Account, Algorithm};
use base64::Engine;
use prost::Message;

const UNSUPPORTED: &str = "Not a supported QR code";

#[derive(Debug, Clone, PartialEq)]
pub struct Batch {
    pub id: i32,
    pub index: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct Parsed {
    pub accounts: Vec<Account>,
    pub skipped_unsupported: usize,
    pub batch: Option<Batch>,
}

#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    otp_parameters: Vec<OtpParameters>,
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
struct OtpParameters {
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

pub fn parse_uri(uri: &str) -> Result<Parsed, String> {
    let url = url::Url::parse(uri.trim()).map_err(|_| UNSUPPORTED.to_string())?;
    match (url.scheme(), url.host_str()) {
        ("otpauth-migration", _) => parse_migration(&url),
        ("otpauth", Some(kind)) if kind.eq_ignore_ascii_case("totp") => parse_otpauth(&url),
        _ => Err(UNSUPPORTED.into()),
    }
}

fn parse_migration(url: &url::Url) -> Result<Parsed, String> {
    let data = url
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.replace(' ', "+"))
        .ok_or_else(|| UNSUPPORTED.to_string())?;
    let bytes = lenient_base64()
        .decode(data.trim())
        .map_err(|_| UNSUPPORTED.to_string())?;
    let payload = MigrationPayload::decode(bytes.as_slice()).map_err(|_| UNSUPPORTED.to_string())?;

    let mut accounts = Vec::new();
    let mut skipped_unsupported = 0;
    for p in &payload.otp_parameters {
        match account_from_params(p) {
            Some(a) => accounts.push(a),
            None => skipped_unsupported += 1,
        }
    }
    let batch = (payload.batch_size > 1).then(|| Batch {
        id: payload.batch_id,
        index: payload.batch_index.max(0) as u32,
        size: payload.batch_size as u32,
    });
    Ok(Parsed { accounts, skipped_unsupported, batch })
}

fn lenient_base64() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

/// None means unsupported (HOTP, MD5, unknown enum values, or no secret).
fn account_from_params(p: &OtpParameters) -> Option<Account> {
    if p.secret.is_empty() || !matches!(p.r#type, 0 | 2) {
        return None;
    }
    let algorithm = match p.algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return None,
    };
    let digits = match p.digits {
        0 | 1 => 6,
        2 => 8,
        _ => return None,
    };
    let name = strip_issuer_prefix(&p.name, &p.issuer);
    Some(Account::from_secret_bytes(&p.issuer, &name, &p.secret, algorithm, digits, 30))
}

fn strip_issuer_prefix(name: &str, issuer: &str) -> String {
    if !issuer.is_empty()
        && let Some(rest) = name.strip_prefix(&format!("{issuer}:"))
    {
        return rest.trim().to_string();
    }
    name.to_string()
}

fn parse_otpauth(url: &url::Url) -> Result<Parsed, String> {
    let label = percent_decode(url.path().trim_start_matches('/'));
    let (label_issuer, label_name) = match label.split_once(':') {
        Some((i, n)) => (i.trim().to_string(), n.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let (mut secret, mut issuer, mut algorithm, mut digits, mut period) =
        (None, None, Algorithm::Sha1, 6u32, 30u64);
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret = Some(v.into_owned()),
            "issuer" => issuer = Some(v.into_owned()),
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err("unsupported algorithm".into()),
                }
            }
            "digits" => digits = v.parse().map_err(|_| "digits must be 6 or 8".to_string())?,
            "period" => period = v.parse().map_err(|_| "period must be a number".to_string())?,
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| "missing secret".to_string())?;

    let (issuer, name) = match issuer.filter(|i| !i.is_empty()) {
        Some(i) => {
            let name = if label_issuer == i { label_name } else { strip_issuer_prefix(&label, &i) };
            (i, name)
        }
        None => (label_issuer, label_name),
    };
    let account = Account::new(&issuer, &name, &secret, algorithm, digits, period)?;
    Ok(Parsed { accounts: vec![account], skipped_unsupported: 0, batch: None })
}

/// Percent-decoding only; unlike form decoding, '+' stays '+'.
fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp(secret: &[u8], name: &str, issuer: &str, algorithm: i32, digits: i32, ty: i32) -> OtpParameters {
        OtpParameters { secret: secret.to_vec(), name: name.into(), issuer: issuer.into(), algorithm, digits, r#type: ty, counter: 0 }
    }

    fn payload(params: Vec<OtpParameters>, size: i32, index: i32, id: i32) -> MigrationPayload {
        MigrationPayload { otp_parameters: params, version: 1, batch_size: size, batch_index: index, batch_id: id }
    }

    fn encode(p: &MigrationPayload) -> String {
        base64::engine::general_purpose::STANDARD.encode(p.encode_to_vec())
    }

    fn url_with(data: &str) -> String {
        format!("otpauth-migration://offline?data={data}")
    }

    fn pct(s: &str) -> String {
        s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
    }

    #[test]
    fn decodes_migration_payload() {
        let p = payload(
            vec![
                otp(b"secret-one", "a@x.com", "A", 1, 1, 2),
                otp(b"secret-two", "b@x.com", "B", 2, 2, 2),
                otp(b"secret-hotp", "c@x.com", "C", 1, 1, 1),
            ],
            1, 0, 0,
        );
        let parsed = parse_uri(&url_with(&pct(&encode(&p)))).unwrap();
        assert_eq!(parsed.accounts.len(), 2);
        assert_eq!(parsed.skipped_unsupported, 1);
        assert_eq!(parsed.accounts[1].algorithm, Algorithm::Sha256);
        assert_eq!(parsed.accounts[1].digits, 8);
        assert_eq!(parsed.accounts[1].period, 30);
        assert_eq!(parsed.accounts[0].secret_bytes(), b"secret-one");
        assert_eq!(parsed.batch, None);
    }

    #[test]
    fn decodes_hand_written_bytes() {
        let bytes: Vec<u8> = vec![
            0x0a, 0x13, 0x0a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x12, 0x01, 0x61, 0x1a, 0x01, 0x62,
            0x20, 0x01, 0x28, 0x01, 0x30, 0x02, 0x10, 0x01, 0x18, 0x01, 0x20, 0x00,
        ];
        let data = pct(&base64::engine::general_purpose::STANDARD.encode(bytes));
        let parsed = parse_uri(&url_with(&data)).unwrap();
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(parsed.accounts[0].issuer, "b");
        assert_eq!(parsed.accounts[0].name, "a");
        assert_eq!(parsed.accounts[0].secret_bytes(), b"Hello");
    }

    #[test]
    fn plus_turned_into_space_still_decodes() {
        let secret: Vec<u8> = (0u8..=255)
            .map(|b| vec![b; 6])
            .find(|s| encode(&payload(vec![otp(s, "n", "i", 1, 1, 2)], 1, 0, 0)).contains('+'))
            .expect("some secret encodes with '+'");
        let p = payload(vec![otp(&secret, "n", "i", 1, 1, 2)], 1, 0, 0);
        let b64 = encode(&p);
        let raw = parse_uri(&url_with(&b64)).unwrap();
        let escaped = parse_uri(&url_with(&pct(&b64))).unwrap();
        assert_eq!(raw.accounts.len(), 1);
        assert_eq!(raw.accounts[0].secret, escaped.accounts[0].secret);
        assert_eq!(raw.accounts[0].secret_bytes(), secret);
    }

    #[test]
    fn strips_issuer_prefix_from_name() {
        let p = payload(vec![otp(b"s", "GitHub:me@x.com", "GitHub", 1, 1, 2)], 1, 0, 0);
        let parsed = parse_uri(&url_with(&pct(&encode(&p)))).unwrap();
        assert_eq!(parsed.accounts[0].name, "me@x.com");
        assert_eq!(parsed.accounts[0].issuer, "GitHub");
    }

    #[test]
    fn reads_batch() {
        let p = payload(vec![otp(b"s", "n", "i", 1, 1, 2)], 3, 1, 77);
        let parsed = parse_uri(&url_with(&pct(&encode(&p)))).unwrap();
        assert_eq!(parsed.batch, Some(Batch { id: 77, index: 1, size: 3 }));
    }

    #[test]
    fn skips_md5_unknown_digits_and_empty_secret() {
        let p = payload(
            vec![
                otp(b"s", "md5", "i", 4, 1, 2),
                otp(b"s", "dig", "i", 1, 9, 2),
                otp(b"", "empty", "i", 1, 1, 2),
                otp(b"s", "ok", "i", 3, 0, 0),
            ],
            1, 0, 0,
        );
        let parsed = parse_uri(&url_with(&pct(&encode(&p)))).unwrap();
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(parsed.skipped_unsupported, 3);
        assert_eq!(parsed.accounts[0].algorithm, Algorithm::Sha512);
        assert_eq!(parsed.accounts[0].digits, 6);
    }

    #[test]
    fn rejects_garbage_migration_data() {
        assert_eq!(parse_uri("otpauth-migration://offline?data=!!!").unwrap_err(), "Not a supported QR code");
        assert_eq!(parse_uri("otpauth-migration://offline").unwrap_err(), "Not a supported QR code");
    }

    #[test]
    fn parses_otpauth() {
        let p = parse_uri("otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30").unwrap();
        assert_eq!(p.accounts.len(), 1);
        assert_eq!(p.accounts[0].issuer, "ACME Co");
        assert_eq!(p.accounts[0].name, "john@example.com");
        assert_eq!(p.skipped_unsupported, 0);
        assert_eq!(p.batch, None);
    }

    #[test]
    fn otpauth_defaults() {
        let p = parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        let a = &p.accounts[0];
        assert_eq!((a.issuer.as_str(), a.name.as_str()), ("", "x"));
        assert_eq!((a.algorithm, a.digits, a.period), (Algorithm::Sha1, 6, 30));
    }

    #[test]
    fn otpauth_issuer_from_label_prefix() {
        let p = parse_uri("otpauth://totp/GitHub:me@x.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.accounts[0].issuer, "GitHub");
        assert_eq!(p.accounts[0].name, "me@x.com");
    }

    #[test]
    fn otpauth_plus_in_label_is_kept() {
        let p = parse_uri("otpauth://totp/me+tag@x.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.accounts[0].name, "me+tag@x.com");
    }

    #[test]
    fn otpauth_label_percent_decoding() {
        let name = |label: &str| {
            parse_uri(&format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP")).unwrap().accounts[0].name.clone()
        };
        assert_eq!(name("%E2%82%AC"), "\u{20ac}");
        assert_eq!(name("abc%"), "abc%");
        assert_eq!(name("a%zzb"), "a%zzb");
        assert_eq!(name("a%+Ab"), "a%+Ab");
    }

    #[test]
    fn otpauth_bad_values_are_errors() {
        assert!(parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7").is_err());
        assert!(parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").is_err());
        assert!(parse_uri("otpauth://totp/x").is_err());
    }

    #[test]
    fn rejects_other() {
        assert_eq!(parse_uri("https://example.com").unwrap_err(), "Not a supported QR code");
        assert_eq!(parse_uri("not a url").unwrap_err(), "Not a supported QR code");
        assert_eq!(parse_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").unwrap_err(), "Not a supported QR code");
    }
}

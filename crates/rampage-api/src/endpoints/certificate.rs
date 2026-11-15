//! X.509 certificates embedded in bytes, PEM (`-----BEGIN CERTIFICATE-----`) or DER (`30 82 len len 30 82`), read
//! with `x509-parser` for the names a device would trust or present.

use serde::Serialize;
use sha2::{Digest, Sha256};

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";
/// The longest PEM body read, and the most certificates and DER parse attempts per call.
const MAX_PEM_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATES: usize = 256;
const MAX_DER_ATTEMPTS: usize = 10_000;
/// The smallest DER certificate taken (a minimal EC certificate is about 300 bytes).
const MIN_DER_BYTES: usize = 128;
/// SANs kept per certificate.
const MAX_NAMES: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    /// Offset of the PEM header or DER sequence in the bytes scanned, and its length there.
    #[serde(skip)]
    pub offset: usize,
    #[serde(skip)]
    pub length: usize,
    pub encoding: &'static str,
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// DNS names, IP addresses and URIs from the subject alternative names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    pub not_after: String,
    pub self_signed: bool,
    pub ca: bool,
    /// SHA-256 of the DER certificate, hex.
    pub sha256: String,
    /// The SPKI pin of its public key (`sha256/` and base64 SHA-256 of SubjectPublicKeyInfo).
    pub spki_pin: String,
}

/// The certificates in `bytes`, PEM blocks and DER sequences, in offset order.
pub fn certificates(bytes: &[u8]) -> Vec<Certificate> {
    let mut found = Vec::new();
    let mut search = 0;
    while found.len() < MAX_CERTIFICATES
        && let Some(at) = memchr::memmem::find(&bytes[search..], PEM_BEGIN)
    {
        let start = search + at;
        search = start + PEM_BEGIN.len();
        let window = &bytes[search..bytes.len().min(search + MAX_PEM_BYTES)];
        let Some(body_length) = memchr::memmem::find(window, PEM_END) else { continue };
        let Some(der) = base64_decode(&window[..body_length]) else { continue };
        let length = PEM_BEGIN.len() + body_length + PEM_END.len();
        if let Some(certificate) = parse(&der, "pem", start, length) {
            found.push(certificate);
        }
        search = start + length;
    }
    let mut attempts = 0;
    let mut at = 0;
    while found.len() < MAX_CERTIFICATES
        && attempts < MAX_DER_ATTEMPTS
        && let Some(offset) = memchr::memmem::find(&bytes[at..], &[0x30, 0x82])
    {
        let start = at + offset;
        at = start + 1;
        let Some(header) = bytes.get(start..start + 6) else { break };
        if header[4..6] != [0x30, 0x82] {
            continue;
        }
        let length = 4 + usize::from(u16::from_be_bytes([header[2], header[3]]));
        let Some(der) = bytes.get(start..start + length) else { continue };
        if length < MIN_DER_BYTES {
            continue;
        }
        attempts += 1;
        if let Some(certificate) = parse(der, "der", start, length) {
            found.push(certificate);
            at = start + length;
        }
    }
    found.sort_by_key(|certificate| certificate.offset);
    found
}

fn parse(der: &[u8], encoding: &'static str, offset: usize, length: usize) -> Option<Certificate> {
    let (rest, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    if !rest.is_empty() && encoding == "der" {
        return None;
    }
    let common_name =
        certificate.subject().iter_common_name().next().and_then(|name| name.as_str().ok()).map(str::to_owned);
    let mut alt_names = Vec::new();
    if let Ok(Some(names)) = certificate.subject_alternative_name() {
        use x509_parser::extensions::GeneralName;
        for name in names.value.general_names.iter().take(MAX_NAMES) {
            match name {
                GeneralName::DNSName(name) | GeneralName::URI(name) => alt_names.push((*name).to_owned()),
                GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => alt_names.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string()),
                    16 => alt_names.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let der = &der[..der.len() - rest.len()];
    Some(Certificate {
        offset,
        length,
        encoding,
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        common_name,
        alt_names,
        not_after: certificate.validity().not_after.to_string(),
        self_signed: certificate.subject() == certificate.issuer(),
        ca: certificate.is_ca(),
        sha256: Sha256::digest(der).iter().map(|byte| format!("{byte:02x}")).collect(),
        spki_pin: format!("sha256/{}", base64_encode(&Sha256::digest(certificate.public_key().raw))),
    })
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[(word >> (18 - 6 * index) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes base64 text, ignoring whitespace and the backslash-n of C string escapes; `None` on other characters.
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut word = 0u32;
    let mut bits = 0;
    let mut previous = 0u8;
    for &byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' if previous == b'\\' && matches!(byte, b'n' | b'r') => {
                previous = byte;
                continue;
            }
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\\' | b'"' | b'\n' | b'\r' | b'\t' | b' ' => {
                previous = byte;
                continue;
            }
            _ => return None,
        };
        previous = byte;
        word = word << 6 | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((word >> bits) as u8);
            word &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let encoded = base64_encode(bytes);
            assert_eq!(base64_decode(encoded.as_bytes()).unwrap(), bytes, "{encoded}");
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode(b"Zm9v\\nYmFy").unwrap(), b"foobar");
        assert!(base64_decode(b"Zm9v*").is_none());
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        let mut bytes = vec![0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xfc];
        bytes.resize(0x104, 0x41);
        bytes.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----");
        assert!(certificates(&bytes).is_empty());
    }
}

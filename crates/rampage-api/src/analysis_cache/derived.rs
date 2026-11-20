//! Framing of a derived-fact payload: magic, the entry's own key and kind, then the owner's body. A row whose
//! framing names another key or kind (a row copied under another key, say) is refused before its body is decoded.

use super::DerivedKind;
use super::codec::Malformed;

const MAGIC: &[u8; 8] = b"RPGDRVD\0";
/// The longest key accepted: `<kind>:` and 64 hexadecimal digits, with room to spare.
const MAX_KEY: usize = 256;

pub(super) fn frame(kind: DerivedKind, key: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 5 + key.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.push(kind.tag());
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(body);
    out
}

/// The body of a payload [`frame`] wrote for exactly `kind` and `key`.
pub(super) fn unframe(kind: DerivedKind, key: &str, mut payload: Vec<u8>) -> Result<Vec<u8>, Malformed> {
    let header = MAGIC.len() + 1 + 4;
    if payload.len() < header || &payload[..MAGIC.len()] != MAGIC {
        return Err(Malformed("bad magic"));
    }
    if payload[MAGIC.len()] != kind.tag() {
        return Err(Malformed("embedded kind differs"));
    }
    let length = u32::from_le_bytes(payload[MAGIC.len() + 1..header].try_into().expect("four bytes")) as usize;
    if length > MAX_KEY || payload.len() - header < length {
        return Err(Malformed("embedded key length"));
    }
    if &payload[header..header + length] != key.as_bytes() {
        return Err(Malformed("embedded key differs"));
    }
    payload.drain(..header + length);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips_and_refuses_another_key_kind_or_truncation() {
        let payload = frame(DerivedKind::Decompile, "decompile:ab", b"body");
        assert_eq!(unframe(DerivedKind::Decompile, "decompile:ab", payload.clone()).unwrap(), b"body");
        assert!(unframe(DerivedKind::Decompile, "decompile:ac", payload.clone()).is_err());
        let mut other_kind = payload.clone();
        other_kind[MAGIC.len()] = 0xff;
        assert!(unframe(DerivedKind::Decompile, "decompile:ab", other_kind).is_err());
        for cut in 0..MAGIC.len() + 5 + "decompile:ab".len() {
            assert!(unframe(DerivedKind::Decompile, "decompile:ab", payload[..cut].to_vec()).is_err(), "{cut}");
        }
        let mut huge = payload;
        huge[MAGIC.len() + 1..MAGIC.len() + 5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unframe(DerivedKind::Decompile, "decompile:ab", huge).is_err());
    }
}

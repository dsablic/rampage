//! Disassembles hex AArch32 instruction words from stdin, one per line, printing `word<TAB>text<TAB>encoding<TAB>mnemonic`
//! with labels relative to PC (as `llvm-mc` prints them). The argument picks the set: `A32`, `T16` or `T32`
//! (32-bit Thumb words hold the first halfword in bits 31..16). Used to compare against LLVM.

use std::io::{BufRead, Write};

use rampage_arch::aarch32::{ItState, LabelStyle, decode_a32, decode_t32, format};

fn main() {
    let set = std::env::args().nth(1).expect("set: A32, T16 or T32");
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        let Some(word) = line.split_whitespace().next() else { continue };
        let Ok(value) = u32::from_str_radix(word, 16) else { continue };
        let decoded = match set.as_str() {
            "A32" => decode_a32(value),
            "T16" => decode_t32(value as u16, None, ItState::default()),
            _ => decode_t32((value >> 16) as u16, Some(value as u16), ItState::default()),
        };
        let text = decoded.and_then(|decoded| format(&decoded, 0, LabelStyle::Relative)).unwrap_or_default();
        let encoding = decoded.map_or("", |decoded| decoded.encoding.name);
        let mnemonic = decoded.map_or("", |decoded| decoded.mnemonic());
        writeln!(out, "{word}\t{text}\t{encoding}\t{mnemonic}").expect("write stdout");
    }
}

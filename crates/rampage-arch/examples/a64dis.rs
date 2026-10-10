//! Disassembles hex A64 instruction words from stdin, one per line, printing `word<TAB>text<TAB>encoding` with labels
//! relative to the instruction (as `llvm-mc` prints them). Used to compare against LLVM.

use std::io::{BufRead, Write};

use rampage_arch::a64::{LabelStyle, decode_word, format_word};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        let Some(word) = line.split_whitespace().next() else { continue };
        let Ok(value) = u32::from_str_radix(word, 16) else { continue };
        let text = format_word(value, 0, LabelStyle::Relative).unwrap_or_default();
        let encoding = decode_word(value).map_or("", |decoded| decoded.encoding.name);
        writeln!(out, "{word}\t{text}\t{encoding}").expect("write stdout");
    }
}

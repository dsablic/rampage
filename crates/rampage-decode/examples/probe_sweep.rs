//! Measures the compression probe: for each content and each encoder variant, whether the probe's first
//! candidate decodes the original bytes, its verdict and the time taken, with and without the decoded size.
//!
//! `cargo run --release -p rampage-decode --example probe_sweep [-- FILE...]` uses generated firmware-like
//! content (64 KiB and 1 MiB) and the first MiB of each FILE. Owned inputs only; nothing is written.

use std::time::Instant;

use rampage_decode::encode::{self, Random};
use rampage_decode::probe::{Codec, ProbeOptions, Verdict, probe};
use rampage_decode::{DecodeOptions, Decoder, FlagOrder, Lz4Block, Lzss, OffsetMode, ReferenceLayout};

fn variants() -> Vec<(&'static str, Lzss)> {
    let classic = Lzss::classic_4k(4078, 0);
    vec![
        ("classic-4k", classic),
        ("classic-ring0", Lzss { initial_write_offset: 0, ..classic }),
        ("ring1234-fill20", Lzss { initial_write_offset: 1234, dictionary_fill: 0x20, ..classic }),
        (
            "msb-literal0-be16-dist1",
            Lzss {
                flag_order: FlagOrder::MsbFirst,
                literal_flag: false,
                layout: ReferenceLayout::Be16OffsetLow,
                offset_mode: OffsetMode::DistanceMinusOne,
                initial_write_offset: 0,
                ..classic
            },
        ),
        (
            "w11-mm2-le16len-dist",
            Lzss {
                window_bits: 11,
                min_match: 2,
                layout: ReferenceLayout::Le16LengthLow,
                offset_mode: OffsetMode::Distance,
                initial_write_offset: 0,
                ..classic
            },
        ),
        (
            "w13-be16len-ring",
            Lzss { window_bits: 13, layout: ReferenceLayout::Be16LengthLow, initial_write_offset: 8182, ..classic },
        ),
        (
            "w10-mm2-msb-le16-ring",
            Lzss {
                window_bits: 10,
                min_match: 2,
                layout: ReferenceLayout::Le16OffsetLow,
                flag_order: FlagOrder::MsbFirst,
                initial_write_offset: 959,
                ..classic
            },
        ),
    ]
}

/// Whether `codec` decodes `stream` to `original`.
fn decodes(codec: Codec, stream: &[u8], original: &[u8]) -> bool {
    let options = DecodeOptions {
        expected_output_size: original.len(),
        max_output_size: 64 << 20,
        max_expansion_ratio: 1 << 20,
        max_steps: u64::MAX,
    };
    let result = match codec {
        Codec::Lzss(lzss) => lzss.decode(stream, &options, &mut || false),
        Codec::Lz4Block => Lz4Block.decode(stream, &options, &mut || false),
    };
    result.is_ok_and(|decoded| decoded.bytes == original)
}

fn run(name: &str, stream: &[u8], original: Option<&[u8]>) {
    let sizes = if original.is_some() { vec![original.map(<[u8]>::len), None] } else { vec![None] };
    for expected in sizes {
        let started = Instant::now();
        let options = ProbeOptions {
            expected_output_size: expected,
            max_output_size: expected.unwrap_or((16 << 20).min(stream.len() * 128)),
            max_steps: 768 << 20,
        };
        let report = probe(stream, &options, &mut || false);
        let elapsed = started.elapsed();
        let first = report.candidates.first();
        let correct = match (first, original) {
            (Some(candidate), Some(original)) => decodes(candidate.codec, stream, original),
            _ => false,
        };
        let verdict = first.map_or(Verdict::Weak, |candidate| candidate.verdict);
        println!(
            "{name:<40} {:<8} in {:>8} first {:<10} correct {:<5} alternatives {} steps {:>10} {:>7.0} ms{}",
            if expected.is_some() { "size" } else { "no-size" },
            stream.len(),
            format!("{verdict:?}"),
            correct,
            first.map_or(0, |candidate| candidate.parse_equivalents),
            report.steps,
            elapsed.as_secs_f64() * 1000.0,
            report.stopped_early.map_or(String::new(), |reason| format!(" stopped: {reason}")),
        );
        if std::env::var_os("PROBE_SWEEP_DETAIL").is_some() {
            for candidate in report.candidates.iter().take(4) {
                println!(
                    "    {:?} extendable {} {:.3} entropy {:.3} size {} {:?}",
                    candidate.verdict,
                    candidate.extendable_matches,
                    candidate.extendable_fraction,
                    candidate.output_entropy,
                    candidate.output_size,
                    candidate.codec
                );
            }
        }
    }
}

fn main() {
    let mut contents: Vec<(String, Vec<u8>)> = vec![
        ("synthetic-64k".into(), encode::synthetic_firmware(64 << 10, 7)),
        ("synthetic-1m".into(), encode::synthetic_firmware(1 << 20, 8)),
    ];
    for path in std::env::args().skip(1) {
        let mut bytes = std::fs::read(&path).expect("readable input");
        bytes.truncate(1 << 20);
        contents.push((path.rsplit('/').next().unwrap_or(&path).to_owned(), bytes));
    }
    for (name, content) in &contents {
        for (variant_name, variant) in variants() {
            run(&format!("{name} {variant_name}"), &encode::lzss(&variant, content), Some(content));
        }
        run(&format!("{name} lz4-block"), &encode::lz4_block(content), Some(content));
        run(&format!("{name} uncompressed"), content, None);
    }
    run("random-1m", &Random(5).bytes(1 << 20), None);
}

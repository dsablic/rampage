use std::path::PathBuf;

use assert_cmd::Command;
use predicates::str::contains;
use rampage_decode::encode;
use rampage_decode::{Lzss, OffsetMode, ReferenceLayout};
use serde_json::Value;

struct Input(PathBuf);

impl Input {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-cli-compression-{name}-{}.bin", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn rampage() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS");
    command
}

#[test]
fn layout_flags_the_component_and_probe_prints_a_decode_command_that_reproduces_it() {
    let original = encode::synthetic_firmware(12 << 10, 41);
    let variant = Lzss {
        window_bits: 12,
        layout: ReferenceLayout::Le16OffsetLow,
        offset_mode: OffsetMode::Distance,
        ..Lzss::classic_4k(0, 0)
    };
    let payload = encode::lzss(&variant, &original);
    let sum = payload.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
    let mut image = vec![0xff; 256];
    for word in [0x0800_0000u32, payload.len() as u32, original.len() as u32, sum] {
        image.extend(word.to_le_bytes());
    }
    image.extend(&payload);
    image.extend([0xff; 256]);
    let input = Input::new("component", &image);

    rampage()
        .args(["binary", "layout"])
        .arg(&input.0)
        .assert()
        .success()
        .stdout(contains("compressed_component_candidate: payload 0x110"))
        .stdout(contains("byte_sum32 at 0x10c verified"))
        .stdout(contains(format!("decoded-size candidates {}", original.len())));

    let output = rampage()
        .args(["--json", "binary", "probe-compression"])
        .arg(&input.0)
        .args(["--offset", "0x110", "--length", &payload.len().to_string()])
        .args(["--expected-output-size", &original.len().to_string(), "--candidate-limit", "2"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let best = &report["candidates"][0];
    assert_eq!(best["verdict"], "confident", "{report:#}");
    let arguments = &best["decode_arguments"];

    let output = rampage()
        .args(["--json", "binary", "decode"])
        .arg(&input.0)
        .args(["--codec", "lzss", "--lzss", &arguments["lzss"].to_string()])
        .args(["--offset", "0x110", "--length", &payload.len().to_string()])
        .args(["--expected-output-size", &original.len().to_string(), "--preview-size", "0"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["output_sha256"], best["output_sha256"]);

    rampage()
        .args(["binary", "probe-compression"])
        .arg(&input.0)
        .args(["--offset", "0x110", "--length", &payload.len().to_string()])
        .assert()
        .success()
        .stdout(contains("no expected output size"))
        .stdout(contains("rampage binary decode"))
        .stdout(contains("not tried:"));
}

#[test]
fn probe_rejects_native_image_selectors_and_decode_rejects_malformed_lzss_parameters() {
    let input = Input::new("refusals", &[0; 64]);
    rampage()
        .args(["--arch", "arm64", "binary", "probe-compression"])
        .arg(&input.0)
        .args(["--offset", "0", "--length", "64"])
        .assert()
        .failure()
        .stderr(contains("does not accept --arch"));
    rampage()
        .args(["binary", "decode"])
        .arg(&input.0)
        .args(["--codec", "lzss", "--lzss", "{\"window_bits\":12}", "--offset", "0", "--length", "64"])
        .args(["--expected-output-size", "64"])
        .assert()
        .failure()
        .stderr(contains("--lzss"));
}

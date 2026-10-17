use std::path::PathBuf;

use rampage_eval::decompiled_signature_batch;
use rampage_loaders::Binary;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests").join(path)
}

#[test]
fn signature_health_separates_returned_c_address_mismatch_and_call_error() {
    let binary = Binary::open(fixture("fixtures/bin/hello-x64.elf")).unwrap();
    let main = binary.symbol_by_name("main").unwrap().address;
    let batch = decompiled_signature_batch(binary, [main, main + 1, 0xdead]);
    let exact = &batch.observations[0];
    assert_eq!(exact.status, "returned");
    assert_eq!(exact.returned_address, Some(main));
    assert!(exact.c_bytes > 0);
    assert!(batch.signatures[&main].is_ok());
    let mismatch = &batch.observations[1];
    assert_eq!(mismatch.status, "address_mismatch");
    assert!(mismatch.c_bytes > 0);
    assert!(batch.signatures[&(main + 1)].is_err());
    let failure = &batch.observations[2];
    assert_eq!(failure.status, "error");
    assert_eq!(failure.returned_address, None);
    assert_eq!(failure.c_bytes, 0);
    assert!(batch.signatures[&0xdead].is_err());
    assert!(batch.timing_boundary.contains("First call"));
}

#[test]
fn warning_bearing_output_does_not_become_clean_recovery_in_health_metrics() {
    let binary = Binary::open(fixture("data/runtime-x64-bad-code.snapshot.json")).unwrap();
    let batch = decompiled_signature_batch(binary, [0x1000]);
    let observation = &batch.observations[0];
    assert_eq!(observation.status, "returned");
    assert_eq!(observation.bad_data, Some(true));
    assert!(observation.warning_count.is_some_and(|count| count > 0));
    assert!(observation.c_bytes > 0);
    let json = serde_json::to_value(observation).unwrap();
    assert!(json["elapsed_us"].is_u64());
    assert_eq!(json["requested_address"], "0x1000");
}

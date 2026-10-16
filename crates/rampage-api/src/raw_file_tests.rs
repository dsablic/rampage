use super::*;

#[test]
fn invalid_raw_mappings_fail_before_source_access() {
    let base = serde_json::json!({"offset": 0, "length": 4, "arch": "arm", "mode": "thumb",
        "base_address": "0x1000", "code_byte_order": "little", "data_byte_order": "little"});
    for (field, value) in [
        ("length", serde_json::json!(4097)),
        ("arch", serde_json::json!("mips")),
        ("mode", serde_json::json!("native")),
        ("base_address", serde_json::json!("0x1001")),
        ("code_byte_order", serde_json::json!("big")),
        ("instruction_limit", serde_json::json!(0)),
    ] {
        let mut input = base.clone();
        input[field] = value;
        let request: RawFileRequest = serde_json::from_value(input).unwrap();
        let error = inspect_raw_file(Path::new("/nonexistent/raw-source"), &request).unwrap_err();
        assert!(matches!(error, ApiError::Invalid(_)), "{error}");
    }
}

#[cfg(unix)]
#[test]
#[ignore = "requires centrally assembled raw-window.s .text via RAMPAGE_RAW_FIXTURE"]
fn compiler_owned_thumb_window_preserves_literal_bytes_and_source_coordinates() {
    let file = std::env::var_os("RAMPAGE_RAW_FIXTURE").expect("set RAMPAGE_RAW_FIXTURE to owned .text bytes");
    let length = std::fs::metadata(&file).unwrap().len();
    let request: RawFileRequest = serde_json::from_value(serde_json::json!({
        "offset": 0, "length": length, "arch": "arm", "mode": "thumb", "base_address": "0x2000",
        "code_byte_order": "little", "data_byte_order": "little", "instruction_limit": 3,
    }))
    .unwrap();
    let report = inspect_raw_file(Path::new(&file), &request).unwrap();
    assert_eq!(report.mapping.rows.len(), 3);
    assert_eq!(report.mapping.rows[0].observation.len, 4);
    assert_eq!(report.mapping.rows[1].observation.data_ref, Some(0x2008));
    assert_eq!(report.mapping.rows[1].observation.immediate, Some(0x89abcdef));
    assert_eq!(report.mapping.rows[2].observation.flow, rampage_arch::Flow::Return);
    assert_eq!(report.mapping.consumed_bytes, 8);
    assert_eq!(report.undecoded_prefix_hex, "efcdab89");
    assert_eq!(report.source_coordinate_space, "original_file_byte_offset");
}

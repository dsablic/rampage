//! A synthetic DEX file read back: header, verification, tables, class data, code and disassembly.

use rampage_dex::Dex;
use rampage_dex::dex::{Member, access_names, java_name};
use rampage_dex::insn::{RefKind, disassemble, references};
use rampage_dex::testkit::{CAPTURE_CLASS, SAMPLE_URL, sample_classes, write_dex};

fn sample(version: u16) -> Dex {
    Dex::parse(write_dex(&sample_classes(), version)).unwrap()
}

fn method_body(dex: &Dex, name: &str) -> rampage_dex::dex::CodeItem {
    let mut budget = usize::MAX;
    for index in 0..dex.class_count() {
        let class = dex.class_def(index).unwrap();
        for method in dex.class_data(&class, &mut budget).unwrap().methods() {
            if dex.method(method.method_idx).unwrap().name == name {
                return dex.code_item(method.code_off).unwrap();
            }
        }
    }
    panic!("no method {name}");
}

#[test]
fn every_version_parses_and_verifies() {
    for version in 35..=41 {
        let dex = sample(version);
        assert_eq!(dex.header.version, version);
        assert!(dex.header.checksum_valid, "{version}");
        assert!(dex.header.signature_valid, "{version}");
        assert!(dex.warnings.is_empty(), "{version}: {:?}", dex.warnings);
        assert_eq!(dex.class_count(), 2);
        assert!(dex.map.iter().any(|item| item.kind == "code_item"));
    }
}

#[test]
fn a_bad_checksum_is_reported_not_refused() {
    let mut bytes = write_dex(&sample_classes(), 35);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let dex = Dex::parse(bytes).unwrap();
    assert!(!dex.header.checksum_valid);
    assert!(!dex.header.signature_valid);
    assert!(dex.warnings.iter().any(|warning| warning.contains("checksum")));
    assert!(dex.warnings.iter().any(|warning| warning.contains("SHA-1")));
}

#[test]
fn classes_methods_and_hierarchy_resolve() {
    let dex = sample(35);
    let mut budget = usize::MAX;
    let capture = (0..dex.class_count())
        .map(|index| dex.class_def(index).unwrap())
        .find(|class| dex.type_text(class.class_idx) == CAPTURE_CLASS)
        .unwrap();
    assert_eq!(dex.superclasses(&capture), ["Ljava/lang/Object;"]);
    assert_eq!(dex.string_text(capture.source_file_idx), "Capture.java");
    let data = dex.class_data(&capture, &mut budget).unwrap();
    assert_eq!(data.static_fields.len(), 1);
    assert_eq!(data.instance_fields.len(), 1);
    let names: Vec<String> = data.methods().map(|method| dex.method(method.method_idx).unwrap().name).collect();
    assert_eq!(names.len(), 6);
    let native = data.methods().find(|method| method.access & 0x100 != 0).unwrap();
    assert_eq!(native.code_off, 0);
    assert_eq!(dex.method_text(native.method_idx), format!("{CAPTURE_CLASS}->nativeEncode([B)I"));
    assert_eq!(access_names(native.access, Member::Method), ["public", "native"]);
    assert_eq!(java_name(CAPTURE_CLASS), "com.example.recorder.Capture");
    assert_eq!(java_name("[[I"), "int[][]");
}

#[test]
fn disassembly_resolves_references() {
    let dex = sample(35);
    let start = method_body(&dex, "start");
    let lines: Vec<String> = disassemble(&dex, &start.insns)
        .iter()
        .map(|insn| format!("{} {}", insn.mnemonic, insn.operands).trim_end().to_owned())
        .collect();
    assert_eq!(
        lines,
        [
            "new-instance v0, Landroid/media/AudioRecord;",
            "invoke-virtual {v0}, Landroid/media/AudioRecord;->startRecording()V",
            &format!("const-string v1, \"{SAMPLE_URL}\""),
            &format!("invoke-static {{v1}}, {CAPTURE_CLASS}->send(Ljava/lang/String;)V"),
            "return-void",
        ]
    );
    let mut seen = Vec::new();
    references(&start.insns, |kind, index, address| seen.push((kind, index, address)));
    assert_eq!(seen.iter().filter(|(kind, _, _)| *kind == RefKind::Method).count(), 2);
    let (_, string, _) = seen.iter().find(|(kind, _, _)| *kind == RefKind::String).unwrap();
    assert_eq!(dex.string_text(*string), SAMPLE_URL);
}

#[test]
fn switch_payloads_and_tries_decode() {
    let dex = sample(35);
    let dispatch = method_body(&dex, "dispatch");
    let insns = disassemble(&dex, &dispatch.insns);
    assert_eq!(insns[0].operands, "v1, :0008");
    let payload = insns.iter().find(|insn| insn.mnemonic == "packed-switch-payload").unwrap();
    assert_eq!(payload.address, 8);
    assert_eq!(payload.operands, "first_key=0x10, targets=[:0005]");
    assert_eq!(payload.targets, [5]);
    let guarded = method_body(&dex, "guarded");
    assert_eq!(guarded.tries.len(), 1);
    let handler = &guarded.catches(&guarded.tries[0])[0];
    assert_eq!(dex.type_text(handler.type_idx.unwrap()), "Ljava/io/IOException;");
    assert_eq!(handler.address, 4);
}

#[test]
fn every_opcode_decodes_without_panicking() {
    let dex = sample(35);
    for code in 0..=255u16 {
        for second in [0u16, 0x1234, 0xffff] {
            let body = [code | 0x5100, second, 0xffff, 0x0004, 0x7777];
            let insns = disassemble(&dex, &body);
            assert!(!insns.is_empty());
            let total: u32 = insns.iter().map(|insn| insn.units).sum();
            assert_eq!(total as usize, body.len());
        }
    }
}

//! Structured pseudocode on the privacy fixture's methods: loops, if/else, folded calls and constructors, and
//! bounded output on large bodies.

use rampage_dex::Dex;
use rampage_dex::pseudo::{PseudoLimits, pseudocode};
use rampage_dex::testkit::{Asm, ClassSpec, watch_classes, write_dex};

fn method(dex: &Dex, text: &str) -> Vec<String> {
    let mut budget = usize::MAX;
    for index in 0..dex.class_count() {
        let class = dex.class_def(index).unwrap();
        for method in dex.class_data(&class, &mut budget).unwrap().methods() {
            if dex.method_text(method.method_idx) == text {
                let code = dex.code_item(method.code_off).unwrap();
                return pseudocode(dex, text, method.access, &code, PseudoLimits::default()).lines;
            }
        }
    }
    panic!("no {text}");
}

#[test]
fn loops_branches_calls_and_constructors_read_as_structured_code() {
    let dex = Dex::parse(write_dex(&watch_classes(), 35)).unwrap();
    let decode = method(&dex, "Lcom/example/watch/Codec;->decode(Ljava/lang/String;)Ljava/lang/String;");
    eprintln!("{}", decode.join("\n"));
    assert_eq!(decode[0], "static String Codec.decode(String p1) {");
    let text = decode.join("\n");
    assert!(text.contains("v0 = p1.toCharArray();"), "{text}");
    assert!(text.contains("while (true) {"), "{text}");
    assert!(text.contains("if (v1 >= v2) break;"), "{text}");
    assert!(!text.contains("continue;"), "{text}");
    assert!(text.contains("v2 = v2 ^ 0x5a;"), "{text}");
    assert!(text.contains("v3 = new String(v0);"), "{text}");
    assert!(!text.contains("goto"), "{text}");
    let get = method(&dex, "Lcom/example/watch/Strings;->get(I)Ljava/lang/String;").join("\n");
    eprintln!("{get}");
    assert!(get.contains("v0 = Strings.DATA;") && get.contains("if (v2 == 0) break;"), "{get}");
    assert!(get.contains("v1 = new StringBuilder();"), "{get}");
    let upload = method(&dex, "Lcom/example/watch/Uploader;->upload([B)V").join("\n");
    eprintln!("{upload}");
    assert!(upload.contains("v0 = Codec.decode(v0);") && upload.contains("v1 = new URL(v0);"), "{upload}");
    let receive =
        method(&dex, "Lcom/example/watch/BootReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V");
    let receive = receive.join("\n");
    eprintln!("{receive}");
    assert!(receive.contains("void BootReceiver.onReceive(Context p1, Intent p2) {"), "{receive}");
    assert!(receive.contains("v1 = CaptureService.class;"), "{receive}");
    assert!(receive.contains("p1.startForegroundService(v0);"), "{receive}");
}

#[test]
fn if_else_and_unstructured_jumps_keep_their_meaning() {
    // run(int p1): if (p1 == 0) { v0 = "a" } else { v0 = "b" }; return v0
    let body = Asm::new().if_zero(0x39, 1, 5).const_string(0, "a").goto(3).const_string(0, "b").return_object(0);
    let class = ClassSpec::new("Lcom/example/p/P;", "Ljava/lang/Object;").method(
        "run",
        "Ljava/lang/String;",
        &["I"],
        0x9,
        Some(body.code(2, 1, 0)),
    );
    let dex = Dex::parse(write_dex(&[class], 35)).unwrap();
    let text = method(&dex, "Lcom/example/p/P;->run(I)Ljava/lang/String;").join("\n");
    eprintln!("{text}");
    assert!(text.contains("if (p1 == 0) {"), "{text}");
    assert!(text.contains("} else {"), "{text}");
    assert!(!text.contains("goto"), "{text}");

    // A long straight body is cut at max_lines and says so.
    let mut long = Asm::new();
    for _ in 0..3000 {
        long = long.const4(0, 1);
    }
    let class = ClassSpec::new("Lcom/example/p/Q;", "Ljava/lang/Object;").method(
        "run",
        "V",
        &[],
        0x9,
        Some(long.return_void().code(1, 0, 0)),
    );
    let dex = Dex::parse(write_dex(&[class], 35)).unwrap();
    let mut budget = usize::MAX;
    let def = dex.class_def(0).unwrap();
    let encoded = dex.class_data(&def, &mut budget).unwrap().direct_methods[0];
    let code = dex.code_item(encoded.code_off).unwrap();
    let limits = PseudoLimits { max_lines: 100, ..PseudoLimits::default() };
    let out = pseudocode(&dex, "Lcom/example/p/Q;->run()V", encoded.access, &code, limits);
    assert!(out.truncated);
    assert!(out.lines.len() <= 110);
}

#[test]
fn deep_nesting_falls_back_to_gotos_within_bounds() {
    // 4000 forward ifs all jumping to one return: each then-part nests the next.
    let count = 4000i32;
    let mut body = Asm::new();
    for index in 0..count {
        let offset = (count - index) * 2;
        body = body.if_zero(0x38, 0, offset as i16);
    }
    let class = ClassSpec::new("Lcom/example/p/N;", "Ljava/lang/Object;").method(
        "run",
        "V",
        &["I"],
        0x9,
        Some(body.return_void().code(1, 1, 0)),
    );
    let dex = Dex::parse(write_dex(&[class], 35)).unwrap();
    let started = std::time::Instant::now();
    let lines = method(&dex, "Lcom/example/p/N;->run(I)V");
    eprintln!("4000 nested ifs: {:?}, {} lines", started.elapsed(), lines.len());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let text = lines.join("\n");
    assert!(text.contains("goto L_"), "deep levels fall back to gotos");
    assert!(lines.iter().all(|line| line.len() < 400));
}

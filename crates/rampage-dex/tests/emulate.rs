//! String decryption: decoder call sites found and emulated on the privacy fixture's classes, a Base64 decoder,
//! and hostile decoders (endless loops, recursion, huge arrays, unmodelled instructions) stopped by their budgets.

use std::time::{Duration, Instant};

use rampage_dex::Dex;
use rampage_dex::emulate::{DecodeLimits, Emulator, Stop, Value, decode_strings};
use rampage_dex::graph::{AppGraph, GraphLimits};
use rampage_dex::testkit::{Asm, ClassSpec, DIRECT, STATIC, WATCH_HOST, WATCH_URL, watch_classes, write_dex};

const OBJECT: &str = "Ljava/lang/Object;";
const STRING: &str = "Ljava/lang/String;";

#[test]
fn the_fixture_decoders_yield_the_hidden_url_and_host() {
    let dex = Dex::parse(write_dex(&watch_classes(), 35)).unwrap();
    let graph = AppGraph::build(&[&dex], GraphLimits::default());
    let found = decode_strings(&[&dex], &graph, DecodeLimits::default());
    let url = found.strings.iter().find(|found| found.output == WATCH_URL).expect("the XOR-decoded URL");
    assert_eq!(url.decoder, "Lcom/example/watch/Codec;->decode(Ljava/lang/String;)Ljava/lang/String;");
    assert_eq!(url.caller, "Lcom/example/watch/Uploader;->upload([B)V");
    assert_eq!(url.inputs.len(), 1);
    assert!(url.inputs[0].starts_with('"'));
    let host = found.strings.iter().find(|found| found.output == WATCH_HOST).expect("the byte-array host");
    assert_eq!(host.caller, "Lcom/example/watch/Snapshot;->take()V");
    assert_eq!(host.inputs, ["0"]);
    assert!(host.steps > 20, "{host:?}");
    assert_eq!(found.strings.len(), 2, "{:?}", found.strings);
    eprintln!("{url:?}\n{host:?}");
}

/// One class `Lcom/example/h/D;` with static `run(<params>)String` holding `body`, a caller passing `args` as
/// constants, and `extra` methods.
fn decoder(body: Asm, registers: u16, ins: u16, params: &[&str], extra: Vec<ClassSpec>) -> (Dex, String) {
    let signature = format!("Lcom/example/h/D;->run({})Ljava/lang/String;", params.concat());
    let class = ClassSpec::new("Lcom/example/h/D;", OBJECT).method(
        "run",
        STRING,
        params,
        0x9,
        Some(body.code(registers, ins, 4)),
    );
    let mut classes = vec![class];
    classes.extend(extra);
    (Dex::parse(write_dex(&classes, 35)).unwrap(), signature)
}

fn run(dex: &Dex, signature: &str, args: Vec<Value>) -> (Result<Value, Stop>, u64, Duration) {
    let graph = AppGraph::build(&[dex], GraphLimits::default());
    let dexes = [dex];
    let mut emulator = Emulator::new(&dexes, &graph, DecodeLimits::default());
    let started = Instant::now();
    let result = emulator.call(graph.id(signature).unwrap(), args);
    (result, emulator.steps, started.elapsed())
}

fn string(text: &str) -> Value {
    Value::Str(std::rc::Rc::new(text.encode_utf16().collect()))
}

#[test]
fn base64_and_string_builders_decode() {
    // run(String s): new String(Base64.decode(s, 0)) + "/v1"
    let body = Asm::new()
        .const4(0, 0)
        .invoke(STATIC, &[3, 0], "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B")
        .move_result_object(0)
        .new_instance(1, STRING)
        .invoke(DIRECT, &[1, 0], "Ljava/lang/String;-><init>([B)V")
        .new_instance(2, "Ljava/lang/StringBuilder;")
        .invoke(DIRECT, &[2, 1], "Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V")
        .const_string(0, "/v1")
        .invoke(0x6e, &[2, 0], "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;")
        .invoke(0x6e, &[2], "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;")
        .move_result_object(0)
        .return_object(0);
    let (dex, signature) = decoder(body, 4, 1, &[STRING], Vec::new());
    let (result, steps, _) = run(&dex, &signature, vec![string("aHR0cHM6Ly9hcGkuZXhhbXBsZS5vcmc=")]);
    match result {
        Ok(Value::Str(units)) => assert_eq!(String::from_utf16_lossy(&units), "https://api.example.org/v1"),
        other => panic!("{other:?}"),
    }
    assert!(steps < 20);
}

#[test]
fn hostile_decoders_stop_at_their_budgets() {
    let mut timings = Vec::new();
    // An endless loop: goto itself.
    let (dex, signature) = decoder(Asm::new().goto(0), 1, 1, &["I"], Vec::new());
    let (result, steps, elapsed) = run(&dex, &signature, vec![Value::Int(1)]);
    assert_eq!(result.unwrap_err(), Stop::Budget("steps"));
    assert_eq!(steps, DecodeLimits::default().max_steps + 1);
    timings.push(("endless loop", elapsed));

    // Unbounded recursion: run(i) calls run(i).
    let body = Asm::new()
        .invoke(STATIC, &[0], "Lcom/example/h/D;->run(I)Ljava/lang/String;")
        .move_result_object(0)
        .return_object(0);
    let (dex, signature) = decoder(body, 1, 1, &["I"], Vec::new());
    let (result, _, elapsed) = run(&dex, &signature, vec![Value::Int(1)]);
    assert_eq!(result.unwrap_err(), Stop::Budget("depth"));
    timings.push(("recursion", elapsed));

    // A huge array, and many arrays below the per-array limit.
    let body = Asm::new().const32(0, i32::MAX).new_array(0, 0, "[B").const4(0, 0).return_object(0);
    let (dex, signature) = decoder(body, 1, 1, &["I"], Vec::new());
    let (result, _, elapsed) = run(&dex, &signature, vec![Value::Int(1)]);
    assert_eq!(result.unwrap_err(), Stop::Budget("allocation"));
    timings.push(("huge array", elapsed));
    let body = Asm::new().const32(0, 60_000).new_array(1, 0, "[I").goto(-2);
    let (dex, signature) = decoder(body, 2, 1, &["I"], Vec::new());
    let (result, _, elapsed) = run(&dex, &signature, vec![Value::Int(1)]);
    assert_eq!(result.unwrap_err(), Stop::Budget("allocation"));
    timings.push(("many arrays", elapsed));

    // A string doubling itself: s = s.concat(s) forever.
    let body = Asm::new()
        .invoke(0x6e, &[1, 1], "Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;")
        .move_result_object(1)
        .goto(-4);
    let (dex, signature) = decoder(body, 2, 1, &[STRING], Vec::new());
    let (result, _, elapsed) = run(&dex, &signature, vec![string("ab")]);
    assert!(matches!(result.unwrap_err(), Stop::Budget("string length" | "allocation")));
    timings.push(("string doubling", elapsed));

    // Unmodelled: an instance field read, a call into I/O.
    let body = Asm::new().raw(&[0x0052, 0]).return_object(0);
    let field = ClassSpec::new("Lcom/example/h/F;", OBJECT).field("x", "I", 0x1);
    let (dex, signature) = decoder(body, 1, 1, &["I"], vec![field]);
    assert!(matches!(run(&dex, &signature, vec![Value::Int(1)]).0, Err(Stop::Unmodelled(_))));
    let body = Asm::new().invoke(STATIC, &[], "Ljava/lang/System;->currentTimeMillis()J").const4(0, 0).return_object(0);
    let (dex, signature) = decoder(body, 1, 1, &["I"], Vec::new());
    match run(&dex, &signature, vec![Value::Int(1)]).0 {
        Err(Stop::Unmodelled(what)) => assert!(what.contains("currentTimeMillis"), "{what}"),
        other => panic!("{other:?}"),
    }
    for (what, elapsed) in &timings {
        eprintln!("{what}: {elapsed:?}");
        assert!(*elapsed < Duration::from_secs(5), "{what}: {elapsed:?}");
    }
}

#[test]
fn many_call_sites_share_emulations_and_stay_bounded() {
    // 5000 call sites of one endless decoder with the same input: one emulation, cached; then the site cap.
    let mut caller = ClassSpec::new("Lcom/example/h/C;", OBJECT);
    let call =
        Asm::new().const4(0, 3).invoke(STATIC, &[0], "Lcom/example/h/D;->run(I)Ljava/lang/String;").return_void();
    for index in 0..5000 {
        caller = caller.method(&format!("c{index}"), "V", &[], 0x9, Some(call.clone().code(1, 0, 1)));
    }
    let (dex, _) = decoder(Asm::new().goto(0), 1, 1, &["I"], vec![caller]);
    let graph = AppGraph::build(&[&dex], GraphLimits::default());
    let started = Instant::now();
    let found = decode_strings(&[&dex], &graph, DecodeLimits::default());
    eprintln!("5000 sites of one endless decoder: {:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(found.emulations, 1);
    assert_eq!(found.stops.get("steps budget"), Some(&1));
    assert!(found.notes.iter().any(|note| note.contains("call sites")), "{:?}", found.notes);
    assert!(found.strings.is_empty());
}

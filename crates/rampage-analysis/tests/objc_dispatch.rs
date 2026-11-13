//! Objective-C send resolution on the owned fixture (tests/fixtures/objc-dispatch/dispatch.m), checked against
//! the implementations each send reaches when the program runs, worked out from the source.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rampage_analysis::functions::{Names, analyze};
use rampage_analysis::objc_dispatch::{Confidence, Dispatch, resolve};
use rampage_loaders::Binary;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn dispatch(name: &str) -> (Binary, Dispatch) {
    let binary = Binary::open(fixture(name)).unwrap();
    let program = analyze(&binary).unwrap();
    let report = rampage_loaders::objc::parse(&binary);
    let dispatch = resolve(&binary, &program, &report, || binary.decoder().ok());
    (binary, dispatch)
}

/// Every send in the fixture, in site order within each (function, selector): the implementations in the binary
/// it reaches at run time. Empty means the implementation is in Foundation (or there is none in the binary).
const TRUTH: &[(&str, &str, &[&str])] = &[
    ("+[Shape unitShape]", "init", &[]),
    ("+[Shape unitShape]", "setScale:", &["-[Shape setScale:]"]),
    ("-[Shape scaledArea]", "area", &["-[Shape area]", "-[Circle area]", "-[Square area]"]),
    ("-[Shape scaledArea]", "scale", &["-[Shape scale]"]),
    ("-[Shape describe]", "kind", &["+[Shape kind]", "+[Circle kind]"]),
    ("-[Shape describe]", "scaledArea", &["-[Shape scaledArea]"]),
    ("-[Shape describe]", "stringWithFormat:", &[]),
    ("-[Circle init]", "init", &[]),
    ("+[Circle kind]", "kind", &["+[Shape kind]"]),
    ("+[Circle kind]", "stringByAppendingString:", &[]),
    ("-[Circle area]", "radius", &["-[Circle radius]"]),
    ("-[Circle area]", "radius", &["-[Circle radius]"]),
    ("-[Circle describe]", "describe", &["-[Shape describe]"]),
    ("-[Circle describe]", "stringByAppendingString:", &[]),
    ("-[Ring area]", "area", &["-[Circle area]"]),
    ("+[Square squareWithSide:]", "init", &[]),
    ("+[Square squareWithSide:]", "setSide:", &["-[Square setSide:]"]),
    ("-[Square area]", "side", &["-[Square side]"]),
    ("-[Square area]", "side", &["-[Square side]"]),
    ("-[Shape(Debug) dump]", "describe", &["-[Shape describe]", "-[Circle describe]"]),
    ("-[Shape(Debug) dump]", "scaledArea", &["-[Shape scaledArea]"]),
    ("-[Label describe]", "text", &["-[Label text]"]),
    ("-[Label describe]", "text", &["-[Label text]"]),
    ("-[Label initials]", "text", &["-[Label text]"]),
    ("-[Label initials]", "substringToIndex:", &[]),
    ("-[NSString(Shout) shout]", "uppercaseString", &[]),
    ("_main", "init", &["-[Circle init]"]),
    ("_main", "squareWithSide:", &["+[Square squareWithSide:]"]),
    ("_main", "unitShape", &["+[Shape unitShape]"]),
    ("_main", "new", &[]),
    ("_main", "dump", &["-[Shape(Debug) dump]"]),
    ("_main", "dump", &["-[Shape(Debug) dump]"]),
    ("_main", "describe", &["-[Shape describe]"]),
    ("_main", "alloc", &[]),
    ("_main", "initials", &["-[Label initials]"]),
    ("_main", "shout", &["-[NSString(Shout) shout]"]),
    ("_main", "initWithFormat:", &[]),
    ("_main", "shout", &["-[NSString(Shout) shout]"]),
    ("_main", "area", &["-[Circle area]"]),
    ("_main", "kind", &["+[Circle kind]"]),
    ("_main", "length", &[]),
    ("_describe_any", "describe", &["-[Circle describe]", "-[Label describe]"]),
];

#[derive(Debug, Default, PartialEq, Eq)]
struct Score {
    sends: usize,
    with_selector: usize,
    /// Sends whose truth is an implementation in the binary.
    in_binary: usize,
    /// ... reported `resolved` to exactly that implementation.
    resolved: usize,
    /// ... reported `ambiguous` with it among the targets.
    ambiguous: usize,
    /// ... whose reported targets include every implementation reached (resolved, ambiguous or candidates).
    covered: usize,
    /// Sends reported `resolved` to the wrong implementation, or `framework` when the binary implements it.
    false_resolutions: usize,
}

/// Scores `name` against [`TRUTH`], using the unstripped twin's symbols to name functions and implementations.
fn score(name: &str, symbols: &str) -> Score {
    let (_, dispatch) = dispatch(name);
    let names = Names::new(&Binary::open(fixture(symbols)).unwrap());
    let mut by_key: BTreeMap<(String, String), Vec<&rampage_analysis::objc_dispatch::Send>> = BTreeMap::new();
    for send in &dispatch.sends {
        let selector = send.selector.clone().unwrap_or_default();
        by_key.entry((names.function_name(send.function), selector)).or_default().push(send);
    }
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut score = Score { sends: dispatch.sends.len(), ..Score::default() };
    score.with_selector = dispatch.sends.iter().filter(|send| send.selector.is_some()).count();
    for &(function, selector, truth) in TRUTH {
        let key = (function.to_owned(), selector.to_owned());
        let index = seen.entry(key.clone()).or_default();
        let send = by_key
            .get(&key)
            .and_then(|sends| sends.get(*index))
            .unwrap_or_else(|| panic!("{name}: no send {index} of {selector} in {function}: {:#?}", dispatch.sends));
        *index += 1;
        let targets: Vec<String> = send.targets.iter().map(|&target| names.function_name(target)).collect();
        let context = format!("{name}: {function} {selector} at {:#x}: {send:?} {targets:?}", send.site);
        if !truth.is_empty() {
            score.in_binary += 1;
            if send.confidence == Confidence::Resolved && targets == truth {
                score.resolved += 1;
            }
            if send.confidence == Confidence::Ambiguous
                && truth.iter().all(|implementation| targets.iter().any(|target| target == implementation))
            {
                score.ambiguous += 1;
            }
            if truth.iter().all(|implementation| targets.iter().any(|target| target == implementation)) {
                score.covered += 1;
            }
        }
        let wrong = match send.confidence {
            Confidence::Resolved => targets != truth,
            Confidence::Framework => !truth.is_empty(),
            _ => false,
        };
        if wrong {
            eprintln!("false resolution: {context}");
            score.false_resolutions += 1;
        }
    }
    assert_eq!(seen.values().sum::<usize>(), dispatch.sends.len(), "{name}: sends beyond the truth table");
    score
}

#[test]
fn every_fixture_send_resolves_with_no_false_resolutions() {
    let arm64 = Score {
        sends: 42,
        with_selector: 42,
        in_binary: 30,
        resolved: 21,
        ambiguous: 5,
        covered: 30,
        false_resolutions: 0,
    };
    // x86-64 keeps `label` and `circle` in stack slots by the time main sends -initials and -area, so those two
    // receivers are unknown there (candidates, truth included).
    let x64 = Score { resolved: 20, ambiguous: 4, ..arm64 };
    for (name, symbols, expected) in [
        ("objc-dispatch-arm64.macho", "objc-dispatch-arm64.macho", &arm64),
        ("objc-dispatch-arm64-stripped.macho", "objc-dispatch-arm64.macho", &arm64),
        ("objc-dispatch-x64.macho", "objc-dispatch-x64.macho", &x64),
        ("objc-dispatch-x64-stripped.macho", "objc-dispatch-x64.macho", &x64),
    ] {
        assert_eq!(&score(name, symbols), expected, "{name}");
    }
}

#[test]
fn stripped_binaries_resolve_exactly_as_their_unstripped_twins() {
    for arch in ["arm64", "x64"] {
        let (_, unstripped) = dispatch(&format!("objc-dispatch-{arch}.macho"));
        let (_, stripped) = dispatch(&format!("objc-dispatch-{arch}-stripped.macho"));
        assert_eq!(stripped.sends, unstripped.sends, "{arch}");
        assert_eq!(stripped.stubs, unstripped.stubs, "{arch}");
    }
}

#[test]
fn arm64_selector_stubs_are_found_without_symbols() {
    let (binary, dispatch) = dispatch("objc-dispatch-arm64-stripped.macho");
    let names = Names::new(&Binary::open(fixture("objc-dispatch-arm64.macho")).unwrap());
    assert_eq!(dispatch.stubs.len(), 21);
    for (address, selector) in &dispatch.stubs {
        assert_eq!(names.function_name(*address), format!("_objc_msgSend${selector}"));
    }
    assert!(binary.symbols.iter().all(|symbol| !symbol.name.starts_with("_objc_msgSend$")));
}

#[test]
fn binaries_without_objective_c_resolve_nothing() {
    for name in ["hello-x64.macho", "hello-arm64.macho", "classes-arm64.macho"] {
        let (_, dispatch) = dispatch(name);
        assert!(dispatch.sends.is_empty() && dispatch.stubs.is_empty(), "{name}");
    }
}

/// Local measurement on any Mach-O: `OBJC_MEASURE=<path>[:x86_64] cargo test ... objc_dispatch::measure --
/// --ignored --nocapture` prints how many sends have a selector and how each was resolved; `OBJC_DUMP=<file>`
/// also writes every send.
#[test]
#[ignore]
fn measure() {
    let spec = std::env::var("OBJC_MEASURE").unwrap();
    let (path, arch) = match spec.rsplit_once(':') {
        Some((path, "x86_64")) => (path.to_owned(), rampage_arch::Arch::X86_64),
        _ => (spec.clone(), rampage_arch::Arch::Aarch64),
    };
    let binary = Binary::open_image(std::path::Path::new(&path), None, Some(arch)).unwrap();
    let started = std::time::Instant::now();
    let program = analyze(&binary).unwrap();
    let analysed = started.elapsed();
    let report = rampage_loaders::objc::parse(&binary);
    let dispatch = resolve(&binary, &program, &report, || binary.decoder().ok());
    let total = dispatch.sends.len();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for send in &dispatch.sends {
        *counts.entry(send.confidence.as_str()).or_default() += 1;
    }
    let with_selector = dispatch.sends.iter().filter(|send| send.selector.is_some()).count();
    let with_class = dispatch.sends.iter().filter(|send| send.receiver.is_some()).count();
    println!(
        "{spec}: {} functions, {} classes, {} stubs, {total} sends, selector {:.1}%, receiver class {:.1}%, \
         {counts:?}, discovery {analysed:?}, dispatch {:?}",
        program.functions.len(),
        report.classes.len(),
        dispatch.stubs.len(),
        100.0 * with_selector as f64 / total.max(1) as f64,
        100.0 * with_class as f64 / total.max(1) as f64,
        started.elapsed() - analysed,
    );
    if let Ok(dump) = std::env::var("OBJC_DUMP") {
        let names = Names::new(&binary);
        let lines: Vec<String> = dispatch
            .sends
            .iter()
            .map(|send| {
                let targets: Vec<String> = send.targets.iter().map(|&target| names.function_name(target)).collect();
                let receiver = send.receiver.as_ref().map(|r| (&r.class, r.class_object, r.exact, r.source));
                format!(
                    "{:#x} {} {} {:?} {receiver:?} {} {targets:?}",
                    send.site,
                    names.function_name(send.function),
                    send.via,
                    send.selector,
                    send.confidence.as_str(),
                )
            })
            .collect();
        std::fs::write(dump, lines.join("\n")).unwrap();
    }
}

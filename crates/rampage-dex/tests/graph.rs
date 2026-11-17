//! The app call graph on the privacy fixture's classes: direct, virtual, by-name, callback and component-start
//! edges; a class hierarchy across DEX files; bounded walks under heavy fan-in.

use std::time::{Duration, Instant};

use rampage_dex::Dex;
use rampage_dex::graph::{AppGraph, EdgeKind, GraphLimits};
use rampage_dex::testkit::{Asm, ClassSpec, INTERFACE, STATIC, VIRTUAL, watch_classes, write_dex};

fn watch(name: &str) -> String {
    format!("Lcom/example/watch/{name};")
}

fn edge(graph: &AppGraph, from: &str, to: &str) -> Option<EdgeKind> {
    let (from, to) = (graph.id(from)?, graph.id(to)?);
    graph.callees[from as usize].iter().find(|(callee, _)| *callee == to).map(|(_, kind)| *kind)
}

#[test]
fn edges_resolve_direct_virtual_by_name_callbacks_and_component_starts() {
    let dex = Dex::parse(write_dex(&watch_classes(), 35)).unwrap();
    let graph = AppGraph::build(&[&dex], GraphLimits::default());
    let on_start = format!("{}->onStartCommand(Landroid/content/Intent;II)I", watch("CaptureService"));
    let on_receive =
        format!("{}->onReceive(Landroid/content/Context;Landroid/content/Intent;)V", watch("BootReceiver"));
    assert_eq!(edge(&graph, &on_receive, &on_start), Some(EdgeKind::Intent));
    let record = format!("{}->record()[B", watch("Recorder"));
    assert_eq!(edge(&graph, &on_start, &record), Some(EdgeKind::Direct));
    let on_click = format!("{}->onClick(Landroid/view/View;)V", watch("TalkActivity"));
    let push = format!("{}->push([B)V", watch("HttpSink"));
    assert_eq!(edge(&graph, &on_click, &push), Some(EdgeKind::ByName));
    assert_eq!(edge(&graph, &on_click, &format!("{}->push([B)V", watch("Sink"))), Some(EdgeKind::Virtual));
    let work = format!("{}->doWork()Landroidx/work/ListenableWorker$Result;", watch("SyncWorker"));
    assert_eq!(edge(&graph, &format!("{}->onCreate()V", watch("App")), &work), Some(EdgeKind::Intent));
    // An API inherited from the framework is named on the framework class the app class extends.
    let find = "Landroid/app/Activity;->findViewById(I)Landroid/view/View;";
    assert!(edge(&graph, &format!("{}->onCreate(Landroid/os/Bundle;)V", watch("TalkActivity")), find).is_some());
    assert_eq!(
        graph.framework_ancestors(&watch("TalkActivity")),
        ["Landroid/app/Activity;", "Landroid/view/View$OnClickListener;"]
    );
    let walk = graph.callers_walk(graph.id(&record).unwrap(), 6, 2000);
    assert!(!walk.cut);
    let chain: Vec<String> =
        walk.chain(graph.id(&on_receive).unwrap()).iter().map(|(id, _)| graph.method(*id).text.clone()).collect();
    assert_eq!(chain, [on_receive.clone(), on_start, record]);
    assert!(graph.indirect.is_empty() && graph.notes.is_empty(), "{:?}", graph.notes);
}

#[test]
fn the_class_hierarchy_spans_dex_files() {
    let object = "Ljava/lang/Object;";
    let base = ClassSpec::new("Lcom/example/a/Base;", "Landroid/accessibilityservice/AccessibilityService;");
    let call = Asm::new().invoke(VIRTUAL, &[0], "Lcom/example/b/Leaf;->tick()V").return_void().code(1, 1, 1);
    let caller = ClassSpec::new("Lcom/example/a/Caller;", object).method("go", "V", &[], 0x1, Some(call));
    let tick = Asm::new().return_void().code(1, 1, 0);
    let mid = ClassSpec::new("Lcom/example/b/Mid;", "Lcom/example/a/Base;").method("tick", "V", &[], 0x1, Some(tick));
    let leaf = ClassSpec::new("Lcom/example/b/Leaf;", "Lcom/example/b/Mid;");
    let first = Dex::parse(write_dex(&[base, caller], 35)).unwrap();
    let second = Dex::parse(write_dex(&[mid, leaf], 35)).unwrap();
    let graph = AppGraph::build(&[&first, &second], GraphLimits::default());
    assert_eq!(
        graph.framework_ancestors("Lcom/example/b/Leaf;"),
        ["Landroid/accessibilityservice/AccessibilityService;"]
    );
    // Leaf.tick() is inherited from Mid, defined in the other file.
    assert_eq!(edge(&graph, "Lcom/example/a/Caller;->go()V", "Lcom/example/b/Mid;->tick()V"), Some(EdgeKind::Virtual));
}

/// `callers` methods that all call one method, and one interface whose call has `implementers` implementations.
fn fan(callers: usize, implementers: usize) -> Vec<ClassSpec> {
    let object = "Ljava/lang/Object;";
    let mut hub = ClassSpec::new("Lcom/example/f/Hub;", object);
    let body = Asm::new()
        .invoke(STATIC, &[], "Lcom/example/f/Hub;->target()V")
        .invoke(INTERFACE, &[0], "Lcom/example/f/Port;->run()V")
        .return_void();
    for index in 0..callers {
        hub = hub.method(&format!("c{index}"), "V", &[], 0x9, Some(body.clone().code(1, 0, 1)));
    }
    hub = hub.method("target", "V", &[], 0x9, Some(Asm::new().return_void().code(0, 0, 0)));
    let mut port = ClassSpec::new("Lcom/example/f/Port;", object).method("run", "V", &[], 0x401, None);
    port.access = 0x601;
    let mut classes = vec![hub, port];
    for index in 0..implementers {
        let mut class = ClassSpec::new(&format!("Lcom/example/f/Impl{index};"), object).method(
            "run",
            "V",
            &[],
            0x1,
            Some(Asm::new().return_void().code(1, 1, 0)),
        );
        class.interfaces = vec!["Lcom/example/f/Port;".to_owned()];
        classes.push(class);
    }
    classes
}

#[test]
fn fan_in_and_fan_out_stay_within_their_bounds() {
    let dex = Dex::parse(write_dex(&fan(20_000, 500), 35)).unwrap();
    let started = Instant::now();
    let graph = AppGraph::build(&[&dex], GraphLimits::default());
    let target = graph.id("Lcom/example/f/Hub;->target()V").unwrap();
    assert_eq!(graph.callers[target as usize].len(), 20_000);
    // One interface call site resolves to at most max_targets implementations by name, and says it was cut.
    let caller = graph.id("Lcom/example/f/Hub;->c0()V").unwrap();
    let by_name = graph.callees[caller as usize].iter().filter(|(_, kind)| *kind == EdgeKind::ByName).count();
    assert!(by_name <= GraphLimits::default().max_targets + 1, "{by_name}");
    assert!(graph.notes.iter().any(|note| note.contains("possible targets")), "{:?}", graph.notes);
    let walk = graph.callers_walk(target, 6, 2000);
    assert!(walk.cut && walk.reached.len() <= 2000);
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    eprintln!("fan-in 20000 x fan-out 500: {:?}", started.elapsed());
    let tight = GraphLimits { max_edges: 1000, ..GraphLimits::default() };
    let graph = AppGraph::build(&[&dex], tight);
    assert_eq!(graph.edges, 1000);
    assert!(graph.notes.iter().any(|note| note.contains("call edges")));
}

#[test]
fn static_calls_through_a_subclass_reach_the_inherited_method() {
    // javac writes `Sub.helper()` for a static helper Base defines as invoke-static Lsub;->helper()V.
    let object = "Ljava/lang/Object;";
    let helper = Asm::new().return_void().code(0, 0, 0);
    let base = ClassSpec::new("Lcom/example/s/Base;", object).method("helper", "V", &[], 0x9, Some(helper));
    let sub = ClassSpec::new("Lcom/example/s/Sub;", "Lcom/example/s/Base;");
    let call = Asm::new().invoke(STATIC, &[], "Lcom/example/s/Sub;->helper()V").return_void().code(1, 1, 0);
    let caller = ClassSpec::new("Lcom/example/s/C;", object).method("go", "V", &[], 0x1, Some(call));
    let dex = Dex::parse(write_dex(&[base, sub, caller], 35)).unwrap();
    let graph = AppGraph::build(&[&dex], GraphLimits::default());
    assert_eq!(edge(&graph, "Lcom/example/s/C;->go()V", "Lcom/example/s/Base;->helper()V"), Some(EdgeKind::Direct));
    let phantom = graph.id("Lcom/example/s/Sub;->helper()V").unwrap();
    assert_eq!(graph.defined_target(phantom), graph.id("Lcom/example/s/Base;->helper()V"));
    assert!(graph.callers[phantom as usize].is_empty());
}

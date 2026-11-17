//! `privacy_surface` on an APK or DEX file: the report native binaries get (sources, sinks, paths, triggers),
//! read from the app's call graph across every DEX file ([`rampage_dex::graph`]) and merged with the native
//! report of each JNI library the APK ships. A Java caller of a `native` method reaches what the bound `Java_`
//! export reaches in its library. Every walk is bounded and says when a bound was hit; evidence that depends on
//! by-name dispatch, reflection or code loaded at run time keeps `no_user_trigger` from being stated.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::{Duration, Instant};

use rampage_dex::apk::NativeLib;
use rampage_dex::graph::{AppGraph, EdgeKind, GraphLimits, Walk, loads_code};
use rampage_dex::manifest::Component;
use serde_json::json;

use crate::Project;
use crate::android::{abi_arch, open};
use crate::endpoints::{Kind, extract};
use crate::workflows::{Confidence, Finding, JniReach, ReportInput, ReportLimits, Section, WorkflowReport, quote};

/// Call levels walked from a source or sink, and methods visited per walk.
const MAX_DEPTH: usize = 6;
const MAX_VISITED: usize = 2000;
/// Levels above both a source and a sink at which a shared caller still counts as a path.
const MAX_SHARED_LEVELS: usize = 4;
/// Source and sink methods paired.
const MAX_SOURCE_METHODS: usize = 200;
const MAX_SINK_METHODS: usize = 400;
/// Time the path search may take before it stops and says so.
const PATH_BUDGET: Duration = Duration::from_secs(5);
/// Endpoints listed per sink method.
const MAX_ENDPOINTS: usize = 4;
/// Native libraries analysed per APK (one ABI per library name).
const MAX_NATIVE_LIBS: usize = 16;
/// ABIs in the order a library is picked from.
const ABI_ORDER: [&str; 4] = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];
const SUGGESTED_METHODS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SinkKind {
    Network,
    Socket,
    File,
}

impl SinkKind {
    fn target(self) -> &'static str {
        match self {
            SinkKind::Network => "the network",
            SinkKind::Socket => "a socket (network or local)",
            SinkKind::File => "a file",
        }
    }

    fn weight(self) -> usize {
        match self {
            SinkKind::Network => 0,
            SinkKind::Socket => 1,
            SinkKind::File => 3,
        }
    }
}

/// Android and Java library calls that send over the network or write a file: `(class, method names, kind)`.
const SINK_APIS: &[(&str, &[&str], SinkKind)] = &[
    ("Ljava/net/URL;", &["openConnection", "openStream"], SinkKind::Network),
    ("Ljava/net/URLConnection;", &["connect", "getOutputStream"], SinkKind::Network),
    ("Ljava/net/HttpURLConnection;", &["connect", "getOutputStream"], SinkKind::Network),
    ("Ljavax/net/ssl/HttpsURLConnection;", &["connect", "getOutputStream"], SinkKind::Network),
    ("Ljava/net/Socket;", &["<init>", "connect", "getOutputStream"], SinkKind::Network),
    ("Ljavax/net/ssl/SSLSocket;", &["getOutputStream", "startHandshake"], SinkKind::Network),
    ("Ljava/net/DatagramSocket;", &["send", "connect"], SinkKind::Network),
    ("Ljava/nio/channels/SocketChannel;", &["open", "connect", "write"], SinkKind::Network),
    ("Ljava/nio/channels/DatagramChannel;", &["send", "write"], SinkKind::Network),
    ("Lokhttp3/OkHttpClient;", &["newCall", "newWebSocket"], SinkKind::Network),
    ("Lokhttp3/Call;", &["execute", "enqueue"], SinkKind::Network),
    ("Lokhttp3/WebSocket;", &["send"], SinkKind::Network),
    ("Lcom/android/volley/RequestQueue;", &["add"], SinkKind::Network),
    ("Lretrofit2/Retrofit;", &["create"], SinkKind::Network),
    ("Lretrofit2/Call;", &["execute", "enqueue"], SinkKind::Network),
    ("Landroid/webkit/WebView;", &["loadUrl", "postUrl"], SinkKind::Network),
    ("Lorg/eclipse/paho/client/mqttv3/MqttClient;", &["connect", "publish"], SinkKind::Network),
    ("Lorg/eclipse/paho/client/mqttv3/MqttAsyncClient;", &["connect", "publish"], SinkKind::Network),
    ("Lorg/eclipse/paho/client/mqttv3/IMqttAsyncClient;", &["connect", "publish"], SinkKind::Network),
    ("Lorg/eclipse/paho/android/service/MqttAndroidClient;", &["connect", "publish"], SinkKind::Network),
    ("Lio/grpc/ManagedChannelBuilder;", &["forAddress", "forTarget"], SinkKind::Network),
    ("Lio/grpc/stub/ClientCalls;", &["blockingUnaryCall", "asyncUnaryCall", "futureUnaryCall"], SinkKind::Network),
    ("Lorg/chromium/net/CronetEngine;", &["newUrlRequestBuilder"], SinkKind::Network),
    ("Lorg/chromium/net/UrlRequest;", &["start"], SinkKind::Network),
    ("Lorg/apache/http/client/HttpClient;", &["execute"], SinkKind::Network),
    ("Lorg/apache/http/impl/client/DefaultHttpClient;", &["execute"], SinkKind::Network),
    ("Landroid/net/LocalSocket;", &["connect", "getOutputStream"], SinkKind::Socket),
    ("Ljava/io/FileOutputStream;", &["<init>"], SinkKind::File),
    ("Ljava/io/FileWriter;", &["<init>"], SinkKind::File),
    ("Ljava/io/RandomAccessFile;", &["<init>"], SinkKind::File),
    ("Ljava/nio/file/Files;", &["write", "newOutputStream"], SinkKind::File),
    ("Landroid/content/ContentResolver;", &["insert", "openOutputStream"], SinkKind::File),
    ("Landroid/content/Context;", &["openFileOutput"], SinkKind::File),
    ("Landroid/content/ContextWrapper;", &["openFileOutput"], SinkKind::File),
    ("Landroid/app/Activity;", &["openFileOutput"], SinkKind::File),
    ("Landroid/app/Service;", &["openFileOutput"], SinkKind::File),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Marker {
    Timer,
    Receive,
    UserInput,
}

/// Calls that mark a method on a chain: `(class, method names; a name ending in `*` is a prefix, marker)`.
const MARKER_APIS: &[(&str, &[&str], Marker)] = &[
    ("Landroid/app/AlarmManager;", &["set*"], Marker::Timer),
    ("Landroid/app/job/JobScheduler;", &["schedule", "enqueue"], Marker::Timer),
    ("Landroidx/work/WorkManager;", &["enqueue*"], Marker::Timer),
    (
        "Landroid/os/Handler;",
        &["postDelayed", "postAtTime", "sendMessageDelayed", "sendEmptyMessageDelayed"],
        Marker::Timer,
    ),
    ("Ljava/util/Timer;", &["schedule", "scheduleAtFixedRate"], Marker::Timer),
    ("Ljava/util/concurrent/ScheduledExecutorService;", &["schedule*"], Marker::Timer),
    ("Ljava/util/concurrent/ScheduledThreadPoolExecutor;", &["schedule*"], Marker::Timer),
    ("Ljava/net/ServerSocket;", &["accept"], Marker::Receive),
    ("Ljava/net/Socket;", &["getInputStream"], Marker::Receive),
    ("Ljava/net/DatagramSocket;", &["receive"], Marker::Receive),
    ("Ljava/nio/channels/SocketChannel;", &["read"], Marker::Receive),
    ("Lorg/eclipse/paho/client/mqttv3/MqttClient;", &["subscribe", "setCallback"], Marker::Receive),
    ("Lorg/eclipse/paho/client/mqttv3/MqttAsyncClient;", &["subscribe", "setCallback"], Marker::Receive),
    (
        "Landroid/view/View;",
        &["setOnClickListener", "setOnTouchListener", "setOnLongClickListener", "setOnKeyListener"],
        Marker::UserInput,
    ),
    ("Landroid/widget/CompoundButton;", &["setOnCheckedChangeListener"], Marker::UserInput),
];

fn api_matches(table_class: &str, names: &[&str], class: &str, name: &str) -> bool {
    table_class == class
        && names.iter().any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => *pattern == name,
        })
}

/// What starts a method, read from its class's framework supertypes, its name and the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// A receiver of a boot broadcast.
    Boot(String),
    /// Code the platform runs when the app's process starts (the Application class, a content provider).
    AppStart(&'static str),
    Broadcast {
        receiver: String,
        exported: bool,
        actions: Vec<String>,
    },
    Service {
        service: String,
        exported: bool,
    },
    Job(&'static str),
    Push(&'static str),
    Ui(&'static str),
    Accessibility,
}

const ACTIVITIES: [&str; 7] = [
    "Landroid/app/Activity;",
    "Landroidx/appcompat/app/AppCompatActivity;",
    "Landroidx/fragment/app/FragmentActivity;",
    "Landroidx/activity/ComponentActivity;",
    "Landroidx/core/app/ComponentActivity;",
    "Landroid/app/Fragment;",
    "Landroidx/fragment/app/Fragment;",
];
const SERVICES: [&str; 5] = [
    "Landroid/app/Service;",
    "Landroid/app/IntentService;",
    "Landroidx/core/app/JobIntentService;",
    "Landroidx/lifecycle/LifecycleService;",
    "Landroid/service/notification/NotificationListenerService;",
];
const PUSH_SERVICES: [&str; 2] =
    ["Lcom/google/firebase/messaging/FirebaseMessagingService;", "Lcom/google/firebase/iid/FirebaseInstanceIdService;"];
const WORKERS: [&str; 5] = [
    "Landroidx/work/Worker;",
    "Landroidx/work/ListenableWorker;",
    "Landroidx/work/CoroutineWorker;",
    "Landroidx/work/RxWorker;",
    "Landroid/app/job/JobService;",
];
const UI_CALLBACKS: [&str; 16] = [
    "onClick",
    "onLongClick",
    "onTouch",
    "onTouchEvent",
    "onKey",
    "onKeyDown",
    "onKeyUp",
    "onCheckedChanged",
    "onItemClick",
    "onItemSelected",
    "onEditorAction",
    "onOptionsItemSelected",
    "onMenuItemClick",
    "onProgressChanged",
    "onStopTrackingTouch",
    "onNavigationItemSelected",
];

/// The descriptor's Java name, for messages.
fn java(descriptor: &str) -> String {
    rampage_dex::dex::java_name(descriptor)
}

/// One capture source in one method.
struct SourceHit {
    medium: &'static str,
    what: String,
    /// Whether the evidence shows capture in particular.
    specific: bool,
    evidence: Vec<String>,
}

struct SinkHit {
    kind: SinkKind,
    what: String,
    evidence: Vec<String>,
}

struct Survey<'a> {
    graph: AppGraph,
    dex_paths: Vec<String>,
    sources: BTreeMap<u32, Vec<SourceHit>>,
    sinks: BTreeMap<u32, Vec<SinkHit>>,
    markers: BTreeMap<u32, BTreeMap<Marker, String>>,
    /// Strings each method loads or decodes, with how.
    named: BTreeMap<u32, Vec<(String, String)>>,
    /// Component class descriptor to its manifest entry.
    components: HashMap<String, &'a Component>,
    loads_code: Option<(u32, &'static str)>,
}

/// One scored capture-to-sink pair.
struct PathMatch {
    score: usize,
    confidence: Confidence,
    source: u32,
    sink: u32,
    kind: SinkKind,
    relation: Relation,
}

#[derive(Debug, Clone, Copy)]
enum Relation {
    Same,
    SourceCalls(usize),
    SinkCalls(usize),
    Shared { ancestor: u32, levels: usize },
}

impl Survey<'_> {
    fn name(&self, id: u32) -> String {
        self.graph.method(id).text.clone()
    }

    fn origin(&self, id: u32) -> String {
        let method = self.graph.method(id);
        format!("origin: dex {}", self.dex_paths.get(method.dex).map_or("classes.dex", String::as_str))
    }

    /// Callers of the external methods matching a table, with the method text, as `(caller, api)`.
    fn api_callers(&self, matches: impl Fn(&str, &str) -> bool) -> Vec<(u32, u32)> {
        let mut found = Vec::new();
        for (id, method) in self.graph.methods.iter().enumerate() {
            if method.defined || !matches(&method.class, &method.name) {
                continue;
            }
            for &(caller, _) in self.graph.callers_of(id as u32) {
                found.push((caller, id as u32));
            }
        }
        found
    }

    fn scan(&mut self) {
        let captures: Vec<(u32, u32)> =
            self.api_callers(|class, name| rampage_dex::scan::capture_api(&format!("{class}->{name}(")).is_some());
        for (caller, api) in captures {
            let text = self.graph.method(api).text.clone();
            let Some((medium, permissions)) = rampage_dex::scan::capture_api(&text) else { continue };
            let mut evidence = vec![format!("invokes {text}")];
            if !permissions.is_empty() {
                evidence.push(format!("guarded by {}", permissions.join(" or ")));
            }
            self.sources.entry(caller).or_default().push(SourceHit {
                medium,
                what: format!("invokes {}", short_api(&text)),
                specific: true,
                evidence,
            });
        }
        for &(class, names, kind) in SINK_APIS {
            for (caller, api) in self.api_callers(|c, n| api_matches(class, names, c, n)) {
                let text = self.graph.method(api).text.clone();
                self.sinks.entry(caller).or_default().push(SinkHit {
                    kind,
                    what: short_api(&text),
                    evidence: vec![format!("invokes {text}")],
                });
            }
        }
        for &(class, names, marker) in MARKER_APIS {
            for (caller, api) in self.api_callers(|c, n| api_matches(class, names, c, n)) {
                let text = short_api(&self.graph.method(api).text);
                self.markers.entry(caller).or_default().entry(marker).or_insert(format!("calls {text}"));
            }
        }
        for (&id, strings) in &self.graph.strings {
            self.named.entry(id).or_default().extend(strings.iter().map(|text| (text.clone(), String::new())));
        }
        self.loads_code = self.graph.indirect.iter().find(|(_, what)| loads_code(what)).map(|(&id, &what)| (id, what));
    }

    /// Adds what the native libraries' JNI exports reach as sources and sinks of the `native` methods bound to
    /// them.
    fn link_jni(&mut self, bound: &[(u32, String, String)], reach: &BTreeMap<(String, String), JniReach>) {
        for (method, library, symbol) in bound {
            let Some(found) = reach.get(&(library.clone(), symbol.clone())) else { continue };
            let via = format!("native method bound to `{}` in {library}", found.function);
            for (function, what, medium, depth, specific) in found.sources.iter().take(8) {
                let mut evidence = vec![via.clone(), format!("`{function}` {what} ({})", below(*depth))];
                if !specific {
                    evidence.push("ambiguous: the native evidence does not show direction".to_owned());
                }
                self.sources.entry(*method).or_default().push(SourceHit {
                    medium,
                    what: format!("reaches native capture in {library}: {what}"),
                    specific: *specific,
                    evidence,
                });
            }
            for (function, what, target, depth) in found.sinks.iter().take(8) {
                let kind = match *target {
                    "the network" => SinkKind::Network,
                    "a file" => SinkKind::File,
                    _ => SinkKind::Socket,
                };
                self.sinks.entry(*method).or_default().push(SinkHit {
                    kind,
                    what: format!("native {what} in {library}"),
                    evidence: vec![via.clone(), format!("`{function}` {what} ({})", below(*depth))],
                });
            }
        }
    }

    /// What starts `id` by itself (the platform calls it), if anything.
    fn entry(&mut self, id: u32) -> Option<Entry> {
        let (class, name) = {
            let method = self.graph.method(id);
            (method.class.clone(), method.name.clone())
        };
        if !self.graph.classes.contains_key(&class) {
            return None;
        }
        let ancestors = self.graph.framework_ancestors(&class);
        let has = |list: &[&str]| ancestors.iter().any(|ancestor| list.contains(&ancestor.as_str()));
        let component = self.components.get(&class).copied();
        if has(&["Landroid/content/BroadcastReceiver;"]) && name == "onReceive" {
            return Some(match component {
                Some(component) if component.start_at_boot => Entry::Boot(component.name.clone()),
                Some(component) => Entry::Broadcast {
                    receiver: component.name.clone(),
                    exported: component.exported,
                    actions: component.intent_filters.iter().flat_map(|filter| filter.actions.clone()).collect(),
                },
                None => Entry::Broadcast { receiver: java(&class), exported: false, actions: Vec::new() },
            });
        }
        if has(&["Landroid/app/Application;"]) && matches!(name.as_str(), "onCreate" | "attachBaseContext") {
            return Some(Entry::AppStart("the Application class (runs when the app's process starts)"));
        }
        if has(&["Landroid/content/ContentProvider;"]) && name == "onCreate" {
            return Some(Entry::AppStart("a content provider (created when the app's process starts)"));
        }
        if has(&PUSH_SERVICES) && name == "onMessageReceived" {
            return Some(Entry::Push("a push message (FirebaseMessagingService.onMessageReceived)"));
        }
        if has(&[
            "Lorg/eclipse/paho/client/mqttv3/MqttCallback;",
            "Lorg/eclipse/paho/client/mqttv3/MqttCallbackExtended;",
        ]) && name == "messageArrived"
        {
            return Some(Entry::Push("an MQTT message (MqttCallback.messageArrived)"));
        }
        if has(&["Lokhttp3/WebSocketListener;"]) && name == "onMessage" {
            return Some(Entry::Push("a WebSocket message (WebSocketListener.onMessage)"));
        }
        if has(&WORKERS) && matches!(name.as_str(), "doWork" | "startWork" | "onStartJob" | "createWork") {
            return Some(Entry::Job("a scheduled job (WorkManager or JobScheduler)"));
        }
        if has(&["Landroid/accessibilityservice/AccessibilityService;"])
            && matches!(name.as_str(), "onAccessibilityEvent" | "onServiceConnected" | "onKeyEvent")
        {
            return Some(Entry::Accessibility);
        }
        if has(&SERVICES) && rampage_dex::graph::ENTRY_NAMES.contains(&name.as_str()) {
            return Some(Entry::Service {
                service: component.map_or_else(|| java(&class), |component| component.name.clone()),
                exported: component.is_some_and(|component| component.exported),
            });
        }
        if UI_CALLBACKS.contains(&name.as_str()) {
            return Some(Entry::Ui("a UI event callback"));
        }
        if has(&ACTIVITIES) && name.starts_with("on") {
            return Some(Entry::Ui("an activity or fragment shown on screen"));
        }
        None
    }

    /// The endpoints a sink method, or a method calling it directly, loads or decodes, as evidence lines.
    fn endpoints(&self, sink: u32) -> Vec<String> {
        let mut methods = vec![sink];
        methods.extend(
            self.graph.callers[sink as usize]
                .iter()
                .filter(|(_, edge)| matches!(edge, EdgeKind::Direct | EdgeKind::Virtual))
                .map(|(caller, _)| *caller),
        );
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        for method in methods {
            for (text, how) in self.named.get(&method).into_iter().flatten() {
                for candidate in extract(text).found {
                    if lines.len() >= MAX_ENDPOINTS {
                        return lines;
                    }
                    if !matches!(candidate.kind, Kind::Url | Kind::Host | Kind::Ip | Kind::Local)
                        || !seen.insert(candidate.value.clone())
                    {
                        continue;
                    }
                    let local = if candidate.kind == Kind::Local {
                        format!(" (local: {})", candidate.reason.unwrap_or("not a public peer"))
                    } else {
                        String::new()
                    };
                    let by =
                        if method == sink { String::new() } else { format!(" by its caller `{}`", self.name(method)) };
                    let how = if how.is_empty() { "loaded".to_owned() } else { how.clone() };
                    lines.push(format!("names endpoint {}{local}, {how}{by}", quote(&candidate.value)));
                }
            }
        }
        lines
    }

    fn specific(&self, id: u32) -> bool {
        self.sources.get(&id).is_some_and(|hits| hits.iter().any(|hit| hit.specific))
    }

    fn mediums(&self, id: u32) -> String {
        let mediums: BTreeSet<&str> = self.sources[&id].iter().map(|hit| hit.medium).collect();
        mediums.into_iter().collect::<Vec<_>>().join("/")
    }

    fn render(&self, chain: &[(u32, Option<EdgeKind>)]) -> Vec<String> {
        chain
            .iter()
            .map(|&(id, edge)| match edge {
                Some(edge @ (EdgeKind::ByName | EdgeKind::Callback | EdgeKind::Intent)) => {
                    format!("{} ({})", self.name(id), edge.label())
                }
                _ => self.name(id),
            })
            .collect()
    }

    fn paths(&self, cones: &BTreeMap<u32, Walk>) -> (Vec<PathMatch>, bool, bool) {
        let deadline = Instant::now() + PATH_BUDGET;
        let mut cut = self.sources.len() > MAX_SOURCE_METHODS || self.sinks.len() > MAX_SINK_METHODS;
        let mut timed_out = false;
        let mut found = Vec::new();
        for &source in self.sources.keys().take(MAX_SOURCE_METHODS) {
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            let source_cone = &cones[&source];
            let near: Vec<(u32, usize)> = source_cone
                .reached
                .iter()
                .filter(|&(_, &(up, _))| up <= MAX_SHARED_LEVELS)
                .map(|(&id, &(up, _))| (id, up))
                .collect();
            for &sink in self.sinks.keys().take(MAX_SINK_METHODS) {
                let sink_cone = &cones[&sink];
                cut |= source_cone.cut || sink_cone.cut;
                let kind = self.sinks[&sink].iter().map(|hit| hit.kind).min().unwrap_or(SinkKind::File);
                let (relation, by_name) = if source == sink {
                    (Relation::Same, false)
                } else if let Some(depth) = sink_cone.depth(source) {
                    (Relation::SourceCalls(depth), sink_cone.chain_has(source, EdgeKind::ByName))
                } else if let Some(depth) = source_cone.depth(sink) {
                    (Relation::SinkCalls(depth), source_cone.chain_has(sink, EdgeKind::ByName))
                } else {
                    let shared = near
                        .iter()
                        .filter_map(|&(id, up)| sink_cone.depth(id).map(|down| (up + down, id)))
                        .filter(|&(levels, _)| levels <= MAX_SHARED_LEVELS)
                        .min();
                    let Some((levels, ancestor)) = shared else { continue };
                    let by_name = source_cone.chain_has(ancestor, EdgeKind::ByName)
                        || sink_cone.chain_has(ancestor, EdgeKind::ByName);
                    (Relation::Shared { ancestor, levels }, by_name)
                };
                let rank = match relation {
                    Relation::Same => 0,
                    Relation::SourceCalls(depth) | Relation::SinkCalls(depth) => depth,
                    Relation::Shared { levels, .. } => levels + 1,
                };
                let mut confidence = match rank {
                    0 | 1 => Confidence::High,
                    2 | 3 => Confidence::Medium,
                    _ => Confidence::Low,
                };
                let specific = self.specific(source);
                for lowered in [kind != SinkKind::Network, !specific, by_name] {
                    if lowered {
                        confidence = lower(confidence);
                    }
                }
                let score = rank * 2 + kind.weight() + usize::from(!specific) + usize::from(by_name) * 2;
                found.push(PathMatch { score, confidence, source, sink, kind, relation });
            }
        }
        found.sort_by(|a, b| a.score.cmp(&b.score).then(b.confidence.cmp(&a.confidence)));
        (found, cut, timed_out)
    }

    fn path_finding(&self, cones: &BTreeMap<u32, Walk>, found: &PathMatch) -> Finding {
        let (source, sink) = (found.source, found.sink);
        let (relation, chain, by_name) = match found.relation {
            Relation::Same => ("in the same method".to_owned(), vec![self.name(source)], false),
            Relation::SourceCalls(depth) => {
                let how = if depth == 1 {
                    "calls the sink directly".to_owned()
                } else {
                    format!("reaches the sink {depth} calls down")
                };
                let chain = cones[&sink].chain(source);
                let by_name = chain.iter().any(|(_, edge)| *edge == Some(EdgeKind::ByName));
                (format!("the capturing method {how}"), self.render(&chain), by_name)
            }
            Relation::SinkCalls(depth) => {
                let how = if depth == 1 {
                    "calls the capture directly".to_owned()
                } else {
                    format!("reaches the capture {depth} calls down")
                };
                let chain = cones[&source].chain(sink);
                let by_name = chain.iter().any(|(_, edge)| *edge == Some(EdgeKind::ByName));
                (format!("the sending method {how}"), self.render(&chain), by_name)
            }
            Relation::Shared { ancestor, levels } => {
                let mut chain = self.render(&cones[&source].chain(ancestor));
                chain.push(format!("and {}", self.render(&cones[&sink].chain(ancestor)).join(" -> ")));
                let by_name = cones[&source].chain_has(ancestor, EdgeKind::ByName)
                    || cones[&sink].chain_has(ancestor, EdgeKind::ByName);
                (format!("both are reached from `{}` ({levels} calls in all)", self.name(ancestor)), chain, by_name)
            }
        };
        let captures: BTreeSet<&str> = self.sources[&source].iter().map(|hit| hit.what.as_str()).collect();
        let sinks: BTreeSet<&str> = self.sinks[&sink].iter().map(|hit| hit.what.as_str()).collect();
        let mut evidence = vec![
            self.origin(source),
            format!("chain: {}", chain.join(" -> ")),
            format!("capture: {}", captures.into_iter().collect::<Vec<_>>().join("; ")),
            format!("sink: {}", sinks.into_iter().collect::<Vec<_>>().join(", ")),
        ];
        if by_name {
            evidence.push(
                "a by_name edge (a virtual or interface call resolved by name) is on the chain: ranked lower"
                    .to_owned(),
            );
        }
        if !self.specific(source) {
            evidence.push("the capture evidence does not show direction: ranked lower".to_owned());
        }
        if found.kind != SinkKind::File {
            evidence.extend(self.endpoints(sink));
        }
        Finding::new(
            "dex_code",
            found.confidence,
            format!(
                "{} capture in `{}` and a send to {} in `{}`: {relation}",
                self.mediums(source),
                self.name(source),
                found.kind.target(),
                self.name(sink)
            ),
        )
        .evidence(evidence)
    }

    /// What reaches each capture method, and how many are reached from boot or app start with no user-facing
    /// trigger found; whether a walk was cut.
    fn triggers(&mut self, cones: &BTreeMap<u32, Walk>) -> (Vec<Finding>, usize, bool) {
        let mut findings = Vec::new();
        let mut unprompted = 0;
        let mut cut_any = false;
        let sources: Vec<u32> = self.sources.keys().copied().take(MAX_SOURCE_METHODS).collect();
        for source in sources {
            let cone = &cones[&source];
            cut_any |= cone.cut;
            let label = self.mediums(source);
            let name = self.name(source);
            let mut by_depth: Vec<(usize, u32)> = cone.reached.iter().map(|(&id, &(depth, _))| (depth, id)).collect();
            by_depth.sort_unstable();
            let mut seen: BTreeSet<String> = BTreeSet::new();
            let mut start: Option<(u32, String)> = None;
            let mut user_input = false;
            let mut incomplete: Option<String> = None;
            let mut by_name = false;
            for &(_, id) in &by_depth {
                let chain = cone.chain(id);
                by_name |= chain.iter().any(|(_, edge)| *edge == Some(EdgeKind::ByName));
                if incomplete.is_none()
                    && let Some(what) = self.graph.indirect.get(&id)
                {
                    incomplete = Some(format!("`{}` uses {what}", self.name(id)));
                }
                let rendered = self.render(&chain).join(" -> ");
                let entry = self.entry(id);
                let has_callers = !self.graph.callers[id as usize].is_empty();
                if entry.is_none() && !has_callers && incomplete.is_none() {
                    incomplete = Some(format!(
                        "`{}` has no callers in the app's code: the platform, reflection or code not read may call it",
                        self.name(id)
                    ));
                }
                let found = match &entry {
                    Some(Entry::Boot(receiver)) => {
                        start.get_or_insert((id, format!("start at boot (BOOT_COMPLETED receiver {receiver})")));
                        None
                    }
                    Some(Entry::AppStart(what)) => {
                        start.get_or_insert((id, format!("app start: {what}")));
                        None
                    }
                    Some(Entry::Ui(what)) => {
                        user_input = true;
                        Some((
                            "user input",
                            format!("{label} capture in `{name}` follows user input"),
                            Confidence::Medium,
                            format!("`{}` is {what}", self.name(id)),
                        ))
                    }
                    Some(Entry::Push(what)) => Some((
                        "network command",
                        format!("{label} capture in `{name}` is reached from {what}"),
                        Confidence::Medium,
                        format!("`{}` handles {what}", self.name(id)),
                    )),
                    Some(Entry::Job(what)) => Some((
                        "timer",
                        format!("{label} capture in `{name}` runs from {what}"),
                        Confidence::Medium,
                        format!("`{}` is {what}", self.name(id)),
                    )),
                    Some(Entry::Accessibility) => Some((
                        "accessibility event",
                        format!("{label} capture in `{name}` is reached from an accessibility service callback"),
                        Confidence::Medium,
                        format!("`{}` runs on accessibility events once the service is enabled", self.name(id)),
                    )),
                    Some(Entry::Broadcast { receiver, exported, actions }) => {
                        let actions = if actions.is_empty() {
                            "no intent filter in the manifest".to_owned()
                        } else {
                            actions.join(", ")
                        };
                        let who = if *exported { "an exported receiver other apps can send to" } else { "a receiver" };
                        Some((
                            "broadcast",
                            format!("{label} capture in `{name}` is reached from a broadcast to {who}: {receiver}"),
                            if *exported { Confidence::Medium } else { Confidence::Low },
                            format!("actions: {actions}"),
                        ))
                    }
                    Some(Entry::Service { service, exported }) if !has_callers || *exported => {
                        let who = if *exported {
                            "an exported service other apps can start"
                        } else {
                            "a service started by the platform or code not read"
                        };
                        Some((
                            "service start",
                            format!("{label} capture in `{name}` is reached from {who}: {service}"),
                            Confidence::Low,
                            format!("`{}` is a service entry point", self.name(id)),
                        ))
                    }
                    _ => None,
                };
                if let Some((kind, observation, confidence, detail)) = found
                    && seen.insert(kind.to_owned())
                {
                    findings.push(Finding::new("dex_code", confidence, observation).evidence([
                        self.origin(source),
                        format!("trigger: {kind}"),
                        detail,
                        format!("chain: {rendered}"),
                    ]));
                }
                let markers: Vec<(Marker, String)> =
                    self.markers.get(&id).into_iter().flatten().map(|(&marker, api)| (marker, api.clone())).collect();
                for (marker, api) in markers {
                    let (kind, observation, confidence) = match marker {
                        Marker::UserInput => {
                            user_input = true;
                            (
                                "user input",
                                format!("{label} capture in `{name}` may follow user input"),
                                Confidence::Low,
                            )
                        }
                        Marker::Timer => (
                            "timer",
                            format!(
                                "{label} capture in `{name}` is reached from a method that schedules work or a timer"
                            ),
                            Confidence::Low,
                        ),
                        Marker::Receive => (
                            "network command",
                            format!(
                                "{label} capture in `{name}` is reached from a method that receives from the network"
                            ),
                            Confidence::Low,
                        ),
                    };
                    if !seen.insert(kind.to_owned()) {
                        continue;
                    }
                    findings.push(Finding::new("dex_code", confidence, observation).evidence([
                        self.origin(source),
                        format!("trigger: {kind}"),
                        format!("`{}` {api}", self.name(id)),
                        format!("chain: {rendered}"),
                    ]));
                }
            }
            let Some((root, how)) = start else {
                if !cone.cut && seen.is_empty() {
                    findings.push(
                        Finding::new(
                            "dex_code",
                            Confidence::Low,
                            format!("{label} capture in `{name}`: no trigger found"),
                        )
                        .evidence([
                            self.origin(source),
                            format!(
                                "no boot receiver, Application, component entry point or UI callback is among the {} \
                                     methods within {MAX_DEPTH} call levels above it; it may be reached through \
                                     reflection, a callback the platform makes, or code not read",
                                cone.reached.len()
                            ),
                        ]),
                    );
                }
                continue;
            };
            let rendered = self.render(&cone.chain(root)).join(" -> ");
            let capture_medium =
                self.sources[&source].iter().any(|hit| matches!(hit.medium, "microphone" | "camera" | "screen"));
            let withheld = if user_input || !capture_medium {
                None
            } else if cone.cut {
                Some("the walk up its callers hit its bound".to_owned())
            } else if by_name {
                Some(
                    "a caller is linked by name (a virtual or interface call), which is possible, not shown".to_owned(),
                )
            } else if let Some(reason) = &incomplete {
                Some(reason.clone())
            } else if let Some((id, what)) = self.loads_code {
                Some(format!("the app loads code at run time (`{}` uses {what})", self.name(id)))
            } else if !self.specific(source) {
                Some("the capture evidence does not show direction".to_owned())
            } else {
                None
            };
            let mut evidence = vec![self.origin(source), format!("trigger: {how}"), format!("chain: {rendered}")];
            if let Some(reason) = &withheld {
                evidence.push(format!("no_user_trigger not stated: {reason}"));
            }
            findings.push(
                Finding::new(
                    "dex_code",
                    Confidence::Medium,
                    format!("{label} capture in `{name}` is reached from {how}"),
                )
                .evidence(evidence),
            );
            if !user_input && capture_medium && withheld.is_none() {
                unprompted += 1;
                findings.push(
                    Finding::new(
                        "dex_code",
                        Confidence::Medium,
                        format!(
                            "no_user_trigger: {label} capture in `{name}` is reached from {how} with no UI callback, \
                             activity or input listener found among its callers within {MAX_DEPTH} levels"
                        ),
                    )
                    .evidence([
                        self.origin(source),
                        format!("chain: {rendered}"),
                        format!(
                            "{} methods within {MAX_DEPTH} call levels above it; none is a UI callback or an activity, \
                             none registers an input listener, none is linked by name or uses reflection, and each \
                             without callers is a known entry point",
                            cone.reached.len()
                        ),
                    ]),
                );
            }
        }
        (findings, unprompted, cut_any)
    }
}

fn lower(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::Observed | Confidence::High => Confidence::Medium,
        Confidence::Medium | Confidence::Low => Confidence::Low,
    }
}

/// Where in a library a JNI export's reach was found.
fn below(depth: usize) -> String {
    match depth {
        0 => "in the export itself".to_owned(),
        1 => "one call below the export".to_owned(),
        depth => format!("{depth} calls below the export"),
    }
}

/// `Lpkg/Class;->name(...)` as `pkg.Class.name`.
fn short_api(text: &str) -> String {
    let (class, rest) = text.split_once("->").unwrap_or((text, ""));
    let name = rest.split('(').next().unwrap_or(rest);
    format!("{}.{name}", java(class))
}

/// The native libraries to analyse: one ABI per library name, in [`ABI_ORDER`], at most [`MAX_NATIVE_LIBS`].
fn pick_libraries(libs: &[NativeLib]) -> (Vec<usize>, usize) {
    let mut by_name: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (index, lib) in libs.iter().enumerate() {
        let name = lib.path.rsplit('/').next().unwrap_or(&lib.path);
        let rank = ABI_ORDER.iter().position(|abi| *abi == lib.abi).unwrap_or(ABI_ORDER.len());
        let slot = by_name.entry(name).or_insert((rank, index));
        if rank < slot.0 {
            *slot = (rank, index);
        }
    }
    let picked: Vec<usize> = by_name.values().map(|&(_, index)| index).collect();
    let total = picked.len();
    (picked.into_iter().take(MAX_NATIVE_LIBS).collect(), total)
}

/// Prefixes a native finding with its library, as an origin.
fn from_library(mut finding: Finding, library: &str) -> Finding {
    finding.observation = format!("{library}: {}", finding.observation);
    let mut evidence = vec![format!("origin: {library}")];
    evidence.append(&mut finding.evidence);
    finding.evidence = evidence;
    finding
}

/// The privacy_surface report on the APK or DEX file at `path`.
pub(crate) fn report(path: &Path, limits: ReportLimits) -> Result<WorkflowReport, String> {
    let mut opened = open(path, true)?;
    let mut libs = opened.apk.as_mut().map(|apk| std::mem::take(&mut apk.native_libs)).unwrap_or_default();
    let sha256 = std::fs::read(path).ok().map(|bytes| rampage_arch::hex::bytes(&sha2_digest(&bytes)));
    let mut report = WorkflowReport::for_input(
        "privacy_surface",
        ReportInput { kind: opened.kind, path: path.display().to_string(), sha256, files: None, next_cursor: None },
    );
    let dexes: Vec<&rampage_dex::Dex> = opened.parsed().map(|(_, dex)| dex).collect();
    let dex_paths: Vec<String> = opened.parsed().map(|(path, _)| path.to_owned()).collect();
    for (dex_path, _, _) in opened.dexes.iter().filter(|(_, dex, _)| dex.is_err()) {
        report.limitation(format!("{dex_path} did not parse and was not read."));
    }
    let graph = AppGraph::build(&dexes, GraphLimits::default());
    let manifest = opened.manifest();
    let components: HashMap<String, &Component> = manifest
        .map(|manifest| {
            manifest
                .components
                .iter()
                .map(|component| (rampage_dex::dex::descriptor_of(&component.name), component))
                .collect()
        })
        .unwrap_or_default();
    let mut survey = Survey {
        graph,
        dex_paths,
        sources: BTreeMap::new(),
        sinks: BTreeMap::new(),
        markers: BTreeMap::new(),
        named: BTreeMap::new(),
        components,
        loads_code: None,
    };
    survey.scan();

    // Native libraries: each one's own report, and what its JNI exports reach.
    let (picked, libraries_total) = pick_libraries(&libs);
    let mut bound: Vec<(u32, String, String)> = Vec::new();
    let mut native_reports: Vec<(String, WorkflowReport)> = Vec::new();
    let mut reach: BTreeMap<(String, String), JniReach> = BTreeMap::new();
    {
        for index in picked {
            let lib = &mut libs[index];
            let library = lib.path.clone();
            let exports = crate::android::jni_exports(lib).java;
            let mut wanted = Vec::new();
            for (id, method) in survey.graph.methods.iter().enumerate() {
                if !method.defined || !method.is_native() {
                    continue;
                }
                let Some(dex) = dexes.get(method.dex) else { continue };
                let Ok(reference) = dex.method(method.method_idx) else { continue };
                let (short, long) =
                    rampage_dex::jni::symbols(&reference.class, &reference.name, &reference.proto.parameters);
                if let Some(symbol) = [long, short].into_iter().find(|symbol| exports.contains(symbol)) {
                    bound.push((id as u32, library.clone(), symbol.clone()));
                    wanted.push(symbol);
                }
            }
            let (Some(bytes), Some(arch)) = (lib.bytes.take(), abi_arch(&lib.abi)) else {
                report.limitation(format!("{library} was not analysed (size limit or unknown ABI)."));
                continue;
            };
            let project = match rampage_loaders::Binary::from_owned_native_bytes(bytes, arch) {
                Ok(binary) => Project::new(binary),
                Err(error) => {
                    report.limitation(format!("{library} did not load ({error}) and was not analysed."));
                    continue;
                }
            };
            match project.privacy_surface_with(limits, &wanted) {
                Ok((native, found)) => {
                    for (symbol, entry) in found {
                        reach.insert((library.clone(), symbol), entry);
                    }
                    native_reports.push((library, native));
                }
                Err(error) => report.limitation(format!("{library} could not be analysed: {error}.")),
            }
        }
    }
    if libraries_total > MAX_NATIVE_LIBS {
        report.limitation(format!(
            "Only {MAX_NATIVE_LIBS} of the APK's {libraries_total} native libraries were analysed; open the others \
             with privacy_surface after fs_extract."
        ));
    }
    survey.link_jni(&bound, &reach);

    let mut cones: BTreeMap<u32, Walk> = BTreeMap::new();
    for &id in survey.sources.keys().take(MAX_SOURCE_METHODS).chain(survey.sinks.keys().take(MAX_SINK_METHODS)) {
        cones.entry(id).or_insert_with(|| survey.graph.callers_walk(id, MAX_DEPTH, MAX_VISITED));
    }

    let mut found: Vec<Finding> = Vec::new();
    for (&id, hits) in &survey.sources {
        for hit in hits {
            let mut evidence =
                vec![survey.origin(id), format!("evidence: {}", if hit.specific { "invoke" } else { "name" })];
            evidence.extend(hit.evidence.iter().cloned());
            let confidence = if hit.specific { Confidence::High } else { Confidence::Medium };
            found.push(
                Finding::new("dex_code", confidence, format!("`{}` {} ({})", survey.name(id), hit.what, hit.medium))
                    .evidence(evidence),
            );
        }
    }
    let mut sources = Section::new("Capture sources", limits);
    let mut sinks = Section::new("Send and write sinks", limits);
    let mut paths = Section::new("Capture-to-send paths", limits);
    let mut triggers = Section::new("Capture triggers", limits);
    let mut excluded = Section::new("Excluded: not capture", limits);
    let mut unreferenced = Section::new("Capture strings not referenced from code", limits);

    found.sort_by_key(|finding| std::cmp::Reverse(finding.confidence));
    let dex_sources = found.len();
    let mut native_findings: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for (library, native) in &native_reports {
        for section in &native.sections {
            native_findings
                .entry(section.title.clone())
                .or_default()
                .extend(section.findings.iter().cloned().map(|finding| from_library(finding, library)));
        }
    }
    let mut take = |title: &str| native_findings.remove(title).unwrap_or_default();
    sources.extend(found.into_iter().chain(take("Capture sources")));

    let mut found: Vec<Finding> = Vec::new();
    for (&id, hits) in &survey.sinks {
        let endpoints = survey.endpoints(id);
        for hit in hits {
            let mut evidence = vec![survey.origin(id)];
            evidence.extend(hit.evidence.iter().cloned());
            if hit.kind != SinkKind::File {
                evidence.extend(endpoints.iter().cloned());
            }
            let name = survey.name(id);
            let observation = match hit.kind {
                SinkKind::Network => format!("`{name}` can send over the network: {}", hit.what),
                SinkKind::Socket => format!("`{name}` can send through a socket (network or local): {}", hit.what),
                SinkKind::File => format!("`{name}` can write a file: {}", hit.what),
            };
            let confidence = match hit.kind {
                SinkKind::Network => Confidence::High,
                SinkKind::Socket => Confidence::Medium,
                SinkKind::File => Confidence::Low,
            };
            found.push(Finding::new("dex_code", confidence, observation).evidence(evidence));
        }
    }
    found.sort_by_key(|finding| std::cmp::Reverse(finding.confidence));
    sinks.extend(found.into_iter().chain(take("Send and write sinks")));

    let (matches, cut, timed_out) = survey.paths(&cones);
    let mut ranked: Vec<(u32, u32)> = Vec::new();
    let path_findings: Vec<Finding> = matches
        .iter()
        .take(limits.per_section)
        .map(|found| {
            ranked.push((found.source, found.sink));
            survey.path_finding(&cones, found)
        })
        .collect();
    let native_paths = take("Capture-to-send paths");
    paths.extend(path_findings.into_iter().chain(native_paths.iter().cloned()));
    paths.total = matches.len() + native_paths.len();
    paths.truncated = paths.total > paths.findings.len();
    if cut {
        report.limitation(format!(
            "The DEX path search was bounded ({MAX_SOURCE_METHODS} source and {MAX_SINK_METHODS} sink methods, \
             {MAX_DEPTH} call levels, {MAX_VISITED} methods per walk) and hit a bound; more distant paths are not \
             listed."
        ));
    }
    if timed_out {
        report.limitation(format!(
            "The DEX path search stopped after {} seconds; pairs it did not reach are not listed.",
            PATH_BUDGET.as_secs()
        ));
    }
    let (mut found, unprompted, trigger_cut) = survey.triggers(&cones);
    found.sort_by_key(|finding| {
        (!finding.observation.starts_with("no_user_trigger:"), std::cmp::Reverse(finding.confidence))
    });
    triggers.extend(found.into_iter().chain(take("Capture triggers")));
    if trigger_cut {
        report.limitation(format!(
            "The trigger search walks at most {MAX_DEPTH} call levels and {MAX_VISITED} methods up from each capture \
             and hit that bound for some; their triggers may be incomplete and they are not said to lack a \
             user-facing trigger."
        ));
    }
    excluded.extend(take("Excluded: not capture"));
    unreferenced.extend(take("Capture strings not referenced from code"));

    let mediums: BTreeSet<&str> = survey.sources.values().flatten().map(|hit| hit.medium).collect();
    let senders = survey.sinks.values().filter(|hits| hits.iter().any(|hit| hit.kind != SinkKind::File)).count();
    let writers = survey.sinks.len() - senders;
    report.summary.push(if survey.sources.is_empty() {
        "No microphone, camera, screen, location or identifier API is invoked from the DEX code.".to_owned()
    } else {
        format!(
            "DEX: {dex_sources} capture sources in {} methods ({}); {senders} methods can send over the network or a \
             socket and {writers} more can write files; {} capture-to-send paths; {unprompted} captures are reached \
             from boot or app start with no user-facing trigger found among their callers.",
            survey.sources.len(),
            mediums.into_iter().collect::<Vec<_>>().join(", "),
            matches.len(),
        )
    });
    for (library, native) in &native_reports {
        if let Some(line) = native.summary.first() {
            report.summary.push(format!("{library}: {line}"));
        }
    }
    report.summary.push(
        "This is evidence of what the code can do and how it is reached, not of intent or that it runs.".to_owned(),
    );

    for &(source, sink) in ranked.iter().take(SUGGESTED_METHODS) {
        report.step(
            "dex_code",
            json!({ "method": survey.name(source) }),
            format!("`{}` captures on a path to a sink; read what it records and passes on.", survey.name(source)),
        );
        if sink != source {
            report.step(
                "dex_code",
                json!({ "method": survey.name(sink) }),
                format!("`{}` sends or writes; read what it sends and where.", survey.name(sink)),
            );
        }
    }
    if !survey.sinks.is_empty() {
        report.step(
            "endpoint_inventory",
            json!({}),
            "List every endpoint the app names, with the methods loading each.",
        );
    }
    report.step("dex_metadata", json!({}), "Read the manifest, permissions, components and JNI links.");

    report.sections.extend([sources, paths, triggers, sinks, excluded, unreferenced]);
    for note in survey.graph.notes.clone() {
        report.limitation(format!("DEX graph bound: {note}."));
    }
    report.limitation(
        "DEX calls are followed through direct and static invokes, virtual and interface invokes resolved through the \
         app's class hierarchy (marked `by_name` when resolved by name to an overriding method, which is possible, \
         not shown), app classes with a framework supertype that a method instantiates (callbacks), and components a \
         method names with const-class beside a call that starts them. Reflection, method handles, code loaded at run \
         time and framework code are not followed; such uses keep no_user_trigger from being stated.",
    );
    report.limitation(
        "A Java caller of a native method reaches what the bound Java_ export reaches through direct calls in its \
         library; natives registered with RegisterNatives are not linked.",
    );
    let mut native_limits: BTreeSet<String> = BTreeSet::new();
    for (_, native) in &native_reports {
        native_limits.extend(native.limitations.iter().cloned());
    }
    for text in native_limits {
        report.limitation(format!("Native libraries: {text}"));
    }
    Ok(report)
}

fn sha2_digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

/// `privacy_surface` on a path no loader opens as one binary: an APK, AAB, JAR or DEX file, or a directory (an
/// extracted firmware tree, paged by cursor). `None` when `path` is another kind of file, which opens as a binary
/// as usual. `input` holds the tool's other arguments.
pub fn privacy_surface_input(path: &Path, input: &serde_json::Value) -> Option<Result<serde_json::Value, String>> {
    let metadata = std::fs::metadata(path).ok()?;
    let fitted = |report: WorkflowReport| {
        let mut report = report;
        report.fit(crate::tools::MAX_RESULT_CHARS);
        serde_json::to_value(report).map_err(|error| error.to_string())
    };
    if metadata.is_dir() {
        return Some(crate::privacy_tree::report(path, input).and_then(fitted));
    }
    if !metadata.is_file() || crate::android::sniff(path).is_none() {
        return None;
    }
    if input.get("cursor").is_some_and(|cursor| !cursor.is_null()) {
        return Some(Err("cursor pages a directory; an APK or DEX file is read whole".to_owned()));
    }
    let limits = match input.get("max_per_section") {
        None | Some(serde_json::Value::Null) => ReportLimits::default(),
        Some(value) => match value.as_u64() {
            Some(count) => ReportLimits::new(Some(count as usize)),
            None => return Some(Err("invalid arguments: max_per_section must be a non-negative integer".to_owned())),
        },
    };
    Some(report(path, limits).and_then(fitted))
}

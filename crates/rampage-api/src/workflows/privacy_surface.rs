//! `privacy_surface`: what a binary can capture (microphone, camera, screen, input devices) and where it can send it
//! (network, files), the call paths between capture and send ranked by evidence, and what starts each capture
//! (program start, a timer, a network command, user input). It reports evidence of capability and reachability,
//! never intent, and never that anything runs.
//!
//! Sources and sinks are found by the APIs a function calls (imports or linked functions, by name), by constant
//! arguments at the call site where they are cheap to read (a capture-direction flag, an ioctl request code, a file
//! mode), and by device-path and framework-class strings a function references. Paths and triggers come from a
//! bounded walk of the call graph, where taking a function's address (a callback, a thread start, a signal handler)
//! counts as an edge.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use rampage_analysis::discover::XrefKind;
use rampage_arch::{Arch, Flow};
use serde_json::{Value, json};

use super::registry::{Workflow, WorkflowOptions, report_options, report_schema};
use super::{Confidence, Finding, ReportLimits, Section, WorkflowReport, match_api, quote};
use crate::endpoints::{Kind, extract};
use crate::tools::Group;
use crate::{ApiError, DisassemblyLine, Project};

/// What a capture source records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Medium {
    Microphone,
    Camera,
    Screen,
    Input,
}

impl Medium {
    const ALL: [Medium; 4] = [Medium::Microphone, Medium::Camera, Medium::Screen, Medium::Input];

    fn label(self) -> &'static str {
        match self {
            Medium::Microphone => "microphone",
            Medium::Camera => "camera",
            Medium::Screen => "screen",
            Medium::Input => "input devices",
        }
    }
}

/// How directly the evidence shows capture, weakest first: a referenced string, an API's name, or the API's name
/// plus a constant argument at the call site that selects capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    String,
    Name,
    Argument,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::String => "string",
            Level::Name => "name",
            Level::Argument => "argument",
        }
    }

    fn confidence(self) -> Confidence {
        match self {
            Level::String => Confidence::Low,
            Level::Name => Confidence::Medium,
            Level::Argument => Confidence::High,
        }
    }
}

/// What a constant argument at a call site says about a source API.
#[derive(Debug, Clone, Copy)]
enum Check {
    /// The name alone shows capture (a read from a capture stream).
    Name,
    /// Argument `index` selects the direction: `capture` means capture, `other` the opposite direction.
    Equals { index: usize, argument: &'static str, capture: (u64, &'static str), other: (u64, &'static str) },
    /// Argument `index` is a flag word; `bit` set means capture.
    Flag { index: usize, argument: &'static str, bit: u64, flag: &'static str },
    /// Argument `index` (a channel count or a parameter pointer) is non-zero for capture.
    NonZero { index: usize, argument: &'static str },
    /// An ioctl: argument `index` is the request code, and only a known capture request makes it a source.
    Ioctl { index: usize },
}

#[derive(Debug, Clone, Copy)]
struct SourceApi {
    medium: Medium,
    what: &'static str,
    check: Check,
}

const fn name(medium: Medium, what: &'static str) -> SourceApi {
    SourceApi { medium, what, check: Check::Name }
}

const SND_PCM_OPEN: SourceApi = SourceApi {
    medium: Medium::Microphone,
    what: "opens an ALSA PCM stream",
    check: Check::Equals {
        index: 2,
        argument: "stream",
        capture: (1, "SND_PCM_STREAM_CAPTURE"),
        other: (0, "SND_PCM_STREAM_PLAYBACK"),
    },
};
const IOCTL: SourceApi = SourceApi { medium: Medium::Camera, what: "ioctl", check: Check::Ioctl { index: 1 } };

/// Capture APIs (patterns, see `api_matches`).
const SOURCE_APIS: &[(&str, SourceApi)] = &[
    ("snd_pcm_open", SND_PCM_OPEN),
    ("snd_pcm_readi", name(Medium::Microphone, "reads frames from an ALSA PCM")),
    ("snd_pcm_readn", name(Medium::Microphone, "reads frames from an ALSA PCM")),
    ("snd_pcm_mmap_readi", name(Medium::Microphone, "reads frames from an ALSA PCM")),
    ("snd_pcm_mmap_readn", name(Medium::Microphone, "reads frames from an ALSA PCM")),
    (
        "pcm_open",
        SourceApi {
            medium: Medium::Microphone,
            what: "opens a tinyalsa PCM",
            check: Check::Flag { index: 2, argument: "flags", bit: 0x1000_0000, flag: "PCM_IN" },
        },
    ),
    ("pcm_read", name(Medium::Microphone, "reads from a tinyalsa PCM")),
    ("pcm_readi", name(Medium::Microphone, "reads from a tinyalsa PCM")),
    ("pcm_mmap_read", name(Medium::Microphone, "reads from a tinyalsa PCM")),
    (
        "pa_simple_new",
        SourceApi {
            medium: Medium::Microphone,
            what: "opens a PulseAudio simple stream",
            check: Check::Equals {
                index: 2,
                argument: "direction",
                capture: (2, "PA_STREAM_RECORD"),
                other: (1, "PA_STREAM_PLAYBACK"),
            },
        },
    ),
    ("pa_simple_read", name(Medium::Microphone, "reads from a PulseAudio record stream")),
    ("pa_stream_connect_record", name(Medium::Microphone, "connects a PulseAudio record stream")),
    (
        "pa_opendefaultstream",
        SourceApi {
            medium: Medium::Microphone,
            what: "opens a PortAudio stream",
            check: Check::NonZero { index: 1, argument: "input channel count" },
        },
    ),
    (
        "pa_openstream",
        SourceApi {
            medium: Medium::Microphone,
            what: "opens a PortAudio stream",
            check: Check::NonZero { index: 1, argument: "input parameters" },
        },
    ),
    ("pa_readstream", name(Medium::Microphone, "reads from a PortAudio input stream")),
    (
        "aaudiostreambuilder_setdirection",
        SourceApi {
            medium: Medium::Microphone,
            what: "sets an AAudio stream's direction",
            check: Check::Equals {
                index: 1,
                argument: "direction",
                capture: (1, "AAUDIO_DIRECTION_INPUT"),
                other: (0, "AAUDIO_DIRECTION_OUTPUT"),
            },
        },
    ),
    ("sl_iid_record", name(Medium::Microphone, "uses the OpenSL ES record interface")),
    ("waveinopen", name(Medium::Microphone, "opens a waveform-audio input device")),
    ("ioctl", IOCTL),
    ("v4l2_ioctl", IOCTL),
    ("v4l2_read", name(Medium::Camera, "reads frames through libv4l2")),
    ("acameramanager_opencamera", name(Medium::Camera, "opens a camera (NDK camera2)")),
    ("acameradevice_createcapturesession", name(Medium::Camera, "creates a camera capture session (NDK camera2)")),
    ("acameracapturesession_setrepeatingrequest", name(Medium::Camera, "starts repeating camera capture")),
    ("acameracapturesession_capture", name(Medium::Camera, "captures a camera frame (NDK camera2)")),
    ("drmmodegetfb", name(Medium::Screen, "reads the displayed DRM framebuffer's handle")),
    ("drmmodegetfb2", name(Medium::Screen, "reads the displayed DRM framebuffer's handle")),
    ("xgetimage", name(Medium::Screen, "reads screen pixels (X11)")),
    ("xshmgetimage", name(Medium::Screen, "reads screen pixels (X11 shared memory)")),
    ("libevdev_grab", name(Medium::Input, "grabs an input device exclusively (libevdev)")),
    ("libevdev_next_event", name(Medium::Input, "reads input events (libevdev)")),
    ("libinput_get_event", name(Medium::Input, "reads input events (libinput)")),
];

/// Fragments of C++ (Itanium-mangled) framework names, matched case-sensitively anywhere in an import or symbol.
const MANGLED_SOURCES: &[(&str, SourceApi)] = &[
    ("7android11AudioRecord", name(Medium::Microphone, "uses the Android native AudioRecord")),
    ("7android13MediaRecorder", name(Medium::Microphone, "uses the Android native MediaRecorder (audio or video)")),
    ("7android6Camera", name(Medium::Camera, "uses the Android native Camera")),
    ("7android16ScreenshotClient", name(Medium::Screen, "uses the Android ScreenshotClient")),
    ("13captureDisplay", name(Medium::Screen, "captures a display (SurfaceFlinger)")),
    ("13ScreenCapture", name(Medium::Screen, "uses the Android ScreenCapture")),
];

/// Lowercase fragments of device paths and framework class names in strings (`.` read as `/`).
const SOURCE_STRINGS: &[(&str, Medium, &str)] = &[
    ("/dev/snd/pcmc", Medium::Microphone, "ALSA PCM capture device node"),
    ("/proc/asound", Medium::Microphone, "ALSA sound-card listing (either direction)"),
    ("/dev/video", Medium::Camera, "V4L2 video device node"),
    ("/dev/graphics/fb", Medium::Screen, "framebuffer device node"),
    ("/dev/fb", Medium::Screen, "framebuffer device node"),
    ("/dev/dri/", Medium::Screen, "DRM display device node"),
    ("/dev/input/", Medium::Input, "input event device node"),
    ("android/media/audiorecord", Medium::Microphone, "Android AudioRecord class"),
    ("android/media/mediarecorder", Medium::Microphone, "Android MediaRecorder class (audio or video)"),
    ("android/hardware/camera", Medium::Camera, "Android camera class"),
    ("android/media/projection/mediaprojection", Medium::Screen, "Android MediaProjection (screen capture) class"),
];

/// ioctl request codes, matched by type and number with any size and direction encoding (which differ between
/// 32- and 64-bit ABIs and on MIPS and PowerPC).
const IOCTL_REQUESTS: &[(u8, u8, Medium, &str)] = &[
    (b'V', 0, Medium::Camera, "VIDIOC_QUERYCAP"),
    (b'V', 5, Medium::Camera, "VIDIOC_S_FMT"),
    (b'V', 8, Medium::Camera, "VIDIOC_REQBUFS"),
    (b'V', 9, Medium::Camera, "VIDIOC_QUERYBUF"),
    (b'V', 15, Medium::Camera, "VIDIOC_QBUF"),
    (b'V', 17, Medium::Camera, "VIDIOC_DQBUF"),
    (b'V', 18, Medium::Camera, "VIDIOC_STREAMON"),
    (b'E', 0x06, Medium::Input, "EVIOCGNAME"),
    (b'E', 0x90, Medium::Input, "EVIOCGRAB"),
    (b'd', 0xad, Medium::Screen, "DRM_IOCTL_MODE_GETFB"),
    (b'd', 0xce, Medium::Screen, "DRM_IOCTL_MODE_GETFB2"),
];

/// The capture request an ioctl code names. Framebuffer requests predate the size/direction encoding.
fn ioctl_request(value: u64) -> Option<(Medium, &'static str)> {
    match value {
        0x4600 => return Some((Medium::Screen, "FBIOGET_VSCREENINFO")),
        0x4602 => return Some((Medium::Screen, "FBIOGET_FSCREENINFO")),
        _ => {}
    }
    // Encoded requests carry a size or direction above bit 16; plain 'V' codes below it are console requests.
    if value > u64::from(u32::MAX) || value >> 16 == 0 {
        return None;
    }
    let (kind, number) = ((value >> 8) as u8, value as u8);
    if kind == b'E' && (0x20..0x40).contains(&number) {
        return Some((Medium::Input, "EVIOCGBIT"));
    }
    IOCTL_REQUESTS
        .iter()
        .find(|(k, n, ..)| *k == kind && *n == number)
        .map(|&(_, _, medium, request)| (medium, request))
}

/// Where data can leave: the network, or a file (weaker, since a file is sent only if something uploads it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SinkKind {
    Network,
    File,
}

#[derive(Debug, Clone, Copy)]
enum SinkCheck {
    Name,
    /// `fopen`: argument `index` is the mode string; a read-only mode is no sink.
    Mode {
        index: usize,
    },
    /// `open`/`openat`: argument `path` is the path (a device or pseudo-file path is no sink) and `flags` the flags
    /// (read-only is no sink).
    Flags {
        path: usize,
        flags: usize,
    },
}

#[derive(Debug, Clone, Copy)]
struct SinkApi {
    kind: SinkKind,
    what: &'static str,
    check: SinkCheck,
}

const fn network(what: &'static str) -> SinkApi {
    SinkApi { kind: SinkKind::Network, what, check: SinkCheck::Name }
}

/// Send and write APIs (patterns, see `api_matches`). The network ones are the sending part of `network_surface`'s
/// table plus MQTT and WebSocket clients.
const SINK_APIS: &[(&str, SinkApi)] = &[
    ("send", network("socket send")),
    ("sendto", network("socket send")),
    ("sendmsg", network("socket send")),
    ("sendmmsg", network("socket send")),
    ("connect", network("socket connect")),
    ("wsasend", network("socket send")),
    ("wsasendto", network("socket send")),
    ("ssl_write", network("TLS write")),
    ("curl_easy_perform", network("HTTP client (libcurl)")),
    ("curl_multi_perform", network("HTTP client (libcurl)")),
    ("curl_easy_send", network("HTTP client (libcurl)")),
    ("internetwritefile", network("HTTP/FTP client")),
    ("httpsendrequest", network("HTTP/FTP client")),
    ("httpsendrequestex", network("HTTP/FTP client")),
    ("winhttpsendrequest", network("HTTP/FTP client")),
    ("winhttpwritedata", network("HTTP/FTP client")),
    ("mosquitto_publish", network("MQTT publish")),
    ("mosquitto_connect", network("MQTT connect")),
    ("mqttclient_publish", network("MQTT publish")),
    ("mqttclient_publishmessage", network("MQTT publish")),
    ("mqttasync_send", network("MQTT publish")),
    ("mqttasync_sendmessage", network("MQTT publish")),
    ("lws_write", network("WebSocket write")),
    ("nopoll_conn_send_binary", network("WebSocket write")),
    ("nopoll_conn_send_text", network("WebSocket write")),
    ("fopen", SinkApi { kind: SinkKind::File, what: "file open", check: SinkCheck::Mode { index: 1 } }),
    ("fopen64", SinkApi { kind: SinkKind::File, what: "file open", check: SinkCheck::Mode { index: 1 } }),
    ("open", SinkApi { kind: SinkKind::File, what: "file open", check: SinkCheck::Flags { path: 0, flags: 1 } }),
    ("open64", SinkApi { kind: SinkKind::File, what: "file open", check: SinkCheck::Flags { path: 0, flags: 1 } }),
    ("openat", SinkApi { kind: SinkKind::File, what: "file open", check: SinkCheck::Flags { path: 1, flags: 2 } }),
    ("creat", SinkApi { kind: SinkKind::File, what: "file create", check: SinkCheck::Name }),
];

/// Writes, named beside a file sink in the same function but not sinks on their own: most write to streams that
/// are already open, such as a log or stdout.
const WRITE_APIS: [&str; 4] = ["fwrite", "write", "writev", "fputs"];
/// Paths that name devices or kernel interfaces: opening one for writing is not storing data.
const DEVICE_PREFIXES: [&str; 3] = ["/dev/", "/proc/", "/sys/"];

/// What a function on a call chain reaching a capture says about what starts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Marker {
    Timer,
    Sleep,
    Receive,
    UserInput,
}

const TRIGGER_APIS: &[(&str, Marker)] = &[
    ("timer_create", Marker::Timer),
    ("timer_settime", Marker::Timer),
    ("setitimer", Marker::Timer),
    ("alarm", Marker::Timer),
    ("timerfd_create", Marker::Timer),
    ("timerfd_settime", Marker::Timer),
    ("g_timeout_add*", Marker::Timer),
    ("uv_timer_start", Marker::Timer),
    ("settimer", Marker::Timer),
    ("createtimerqueuetimer", Marker::Timer),
    ("sleep", Marker::Sleep),
    ("usleep", Marker::Sleep),
    ("nanosleep", Marker::Sleep),
    ("clock_nanosleep", Marker::Sleep),
    ("recv", Marker::Receive),
    ("recvfrom", Marker::Receive),
    ("recvmsg", Marker::Receive),
    ("accept", Marker::Receive),
    ("accept4", Marker::Receive),
    ("ssl_read", Marker::Receive),
    ("wsarecv", Marker::Receive),
    ("wsarecvfrom", Marker::Receive),
    ("mosquitto_message_callback_set", Marker::Receive),
    ("mqttclient_setcallbacks", Marker::Receive),
    ("mqttasync_setcallbacks", Marker::Receive),
    ("mqttclient_receive", Marker::Receive),
    ("libevdev_next_event", Marker::UserInput),
    ("libinput_get_event", Marker::UserInput),
    ("libinput_dispatch", Marker::UserInput),
    ("xnextevent", Marker::UserInput),
    ("sdl_pollevent", Marker::UserInput),
    ("sdl_waitevent", Marker::UserInput),
    ("gtk_main", Marker::UserInput),
    ("getmessage", Marker::UserInput),
];

/// Call-graph levels walked from a source or sink, and functions visited per walk.
const MAX_DEPTH: usize = 6;
const MAX_VISITED: usize = 2000;
/// Levels above both a source and a sink at which a shared caller still counts as a path.
const MAX_SHARED_LEVELS: usize = 4;
/// Source and sink functions paired, and pairs compared.
const MAX_SOURCE_FUNCTIONS: usize = 200;
const MAX_SINK_FUNCTIONS: usize = 400;
/// Instructions before a call read for its constant arguments.
const ARGUMENT_WINDOW: usize = 12;
/// Endpoints listed per sink function.
const MAX_ENDPOINTS: usize = 4;
const SUGGESTED_FUNCTIONS: usize = 3;

/// Whether `name` is a capture API (an ioctl is one only with a capture request, so it does not count here).
pub(crate) fn capture_api(name: &str) -> bool {
    match_api(SOURCE_APIS, name).is_some_and(|source| !matches!(source.check, Check::Ioctl { .. }))
        || MANGLED_SOURCES.iter().any(|(fragment, _)| name.contains(fragment))
}

pub struct PrivacySurface;

impl Workflow for PrivacySurface {
    fn name(&self) -> &'static str {
        "privacy_surface"
    }

    fn summary(&self) -> &'static str {
        "What a binary can capture (mic, camera, screen, input), where it can send it, and what starts capture"
    }

    fn description(&self) -> &'static str {
        "Map capture and send as evidence: microphone, camera, screen and input-device sources (ALSA/tinyalsa/\
         PulseAudio, V4L2 and framebuffer ioctls, device paths, Android audio/camera classes; a capture-direction \
         flag or ioctl code at the call raises evidence from `name` to `argument`), network and file sinks with the \
         endpoints they name, call paths between them ranked by evidence, and what reaches each capture (program \
         start, timer, network command, user input). Evidence, not intent."
    }

    fn group(&self) -> Group {
        Group::Carve
    }

    fn input_schema(&self) -> Value {
        report_schema()
    }

    fn options(&self, input: Value) -> Result<WorkflowOptions, String> {
        report_options(input)
    }

    fn run(&self, project: &Project, options: &WorkflowOptions) -> Result<WorkflowReport, ApiError> {
        project.privacy_surface(options.limits)
    }
}

/// The value a register holds before a call, as far as the instructions just before it show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Constant(u64),
    Address(u64),
}

/// What one call site's arguments say about a source or sink API.
enum Outcome {
    Confirmed(String),
    Excluded(String),
    Unknown,
}

/// An endpoint a function names: string address, value, and why it is local (when it is).
type Named = (u64, String, Option<&'static str>);

/// A capture-to-send path and its (source, sink) functions.
type RankedPath = (Finding, (u64, u64));

/// One capture source in one function.
struct SourceHit {
    medium: Medium,
    what: String,
    level: Level,
    evidence: Vec<String>,
    address: u64,
}

/// One sink API in one function.
struct SinkHit {
    kind: SinkKind,
    what: String,
    level: Level,
    evidence: Vec<String>,
    address: u64,
}

/// How a function reaches the next one toward the walk's start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Edge {
    Call,
    /// Takes the function's address: a callback, thread start or handler it registers.
    Callback,
}

/// Every function's callers, by direct call (or tail jump) and by taking its address in code.
struct Graph {
    callers: BTreeMap<u64, BTreeSet<(u64, Edge)>>,
    /// Functions with a backward jump (a loop).
    loops: BTreeSet<u64>,
}

/// The functions a backward walk reached, each with its distance and the next function toward the start.
struct Cone {
    reached: BTreeMap<u64, (usize, Option<(u64, Edge)>)>,
    /// Whether the depth or function cap stopped the walk.
    cut: bool,
}

impl Graph {
    /// The callers of `start`, breadth first, up to `MAX_DEPTH` levels and `MAX_VISITED` functions.
    fn cone(&self, start: u64) -> Cone {
        let mut reached = BTreeMap::from([(start, (0, None))]);
        let mut queue = VecDeque::from([start]);
        let mut cut = false;
        while let Some(function) = queue.pop_front() {
            let depth = reached[&function].0;
            let Some(callers) = self.callers.get(&function) else { continue };
            if depth == MAX_DEPTH {
                cut |= callers.iter().any(|(caller, _)| !reached.contains_key(caller));
                continue;
            }
            for &(caller, edge) in callers {
                if reached.contains_key(&caller) {
                    continue;
                }
                if reached.len() >= MAX_VISITED {
                    cut = true;
                    break;
                }
                reached.insert(caller, (depth + 1, Some((function, edge))));
                queue.push_back(caller);
            }
        }
        Cone { reached, cut }
    }
}

impl Cone {
    /// The chain from `from` down to the walk's start, as (function, edge to the next).
    fn chain(&self, from: u64) -> Vec<(u64, Option<Edge>)> {
        let mut chain = Vec::new();
        let mut at = from;
        while let Some(&(_, next)) = self.reached.get(&at) {
            chain.push((at, next.map(|(_, edge)| edge)));
            match next {
                Some((function, _)) => at = function,
                None => break,
            }
        }
        chain
    }

    fn depth(&self, function: u64) -> Option<usize> {
        self.reached.get(&function).map(|&(depth, _)| depth)
    }
}

/// Why a function starts work on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    Entry,
    Main,
    Constructor,
    LibraryLoad,
    Export,
}

impl Root {
    fn label(self) -> &'static str {
        match self {
            Root::Entry => "the program entry point",
            Root::Main => "main",
            Root::Constructor => "a load-time constructor (.init_array)",
            Root::LibraryLoad => "library load (JNI_OnLoad)",
            Root::Export => "an exported function (called by whatever loads the library)",
        }
    }

    /// Whether it runs when the program starts, with no other trigger.
    fn at_start(self) -> bool {
        !matches!(self, Root::Export)
    }
}

/// The run's state: the analysis-derived graph and per-function facts.
struct Survey<'p> {
    project: &'p Project,
    arch: Arch,
    listings: HashMap<u64, Option<Vec<Vec<DisassemblyLine>>>>,
    sources: BTreeMap<u64, Vec<SourceHit>>,
    excluded: Vec<Finding>,
    sinks: BTreeMap<u64, Vec<SinkHit>>,
    writes: BTreeMap<u64, BTreeSet<String>>,
    markers: BTreeMap<u64, BTreeMap<Marker, String>>,
    strings: BTreeMap<u64, String>,
    /// Calls read for constant arguments, and those where the instructions before the call did not settle it.
    calls_read: usize,
}

impl Project {
    /// What the binary can capture and send, the paths between, and what starts each capture.
    pub fn privacy_surface(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("privacy_surface", self);
        let analysis = match self.analysis() {
            Ok(analysis) => Some(analysis),
            Err(error) => {
                report.limitation(format!(
                    "Code references are unavailable ({error}); only capture strings are listed, without the \
                     functions using them, paths or triggers."
                ));
                None
            }
        };
        let mut survey = Survey {
            project: self,
            arch: self.binary.arch,
            listings: HashMap::new(),
            sources: BTreeMap::new(),
            excluded: Vec::new(),
            sinks: BTreeMap::new(),
            writes: BTreeMap::new(),
            markers: BTreeMap::new(),
            strings: self.scanned_strings().iter().map(|found| (found.address, found.text.clone())).collect(),
            calls_read: 0,
        };
        let mut unreferenced = Section::new("Capture strings not referenced from code", limits);
        survey.scan_strings(&mut unreferenced);
        if analysis.is_some() {
            survey.scan_calls();
        }
        let graph = analysis.map(|analysis| graph(&analysis.program, |address| analysis.function_containing(address)));
        let roots = self.roots();

        let mut sources = Section::new("Capture sources", limits);
        for (&function, hits) in &survey.sources {
            for hit in hits {
                sources.push(
                    Finding::new(
                        source_tool(hit.level),
                        hit.level.confidence(),
                        format!("`{}` {} ({})", self.function_name(function), hit.what, hit.medium.label()),
                    )
                    .at(hit.address)
                    .evidence(
                        std::iter::once(format!("evidence: {}", hit.level.as_str()))
                            .chain(std::iter::once(format!("in function at {function:#x}")))
                            .chain(hit.evidence.iter().cloned()),
                    ),
                );
            }
        }
        sources.findings.sort_by_key(|finding| std::cmp::Reverse(finding.confidence));

        let mut sinks = Section::new("Send and write sinks", limits);
        let named = if survey.sinks.is_empty() { BTreeMap::new() } else { survey.endpoint_strings() };
        for (&function, hits) in &survey.sinks {
            let endpoints = graph.as_ref().map(|graph| survey.endpoints(graph, &named, function)).unwrap_or_default();
            for hit in hits {
                let mut evidence = vec![format!("evidence: {}", hit.level.as_str())];
                evidence.extend(hit.evidence.iter().cloned());
                if hit.kind == SinkKind::File
                    && let Some(writes) = survey.writes.get(&function)
                {
                    evidence.push(format!("also calls {}", ticked(writes)));
                }
                if hit.kind == SinkKind::Network {
                    evidence.extend(endpoints.iter().cloned());
                }
                let observation = match hit.kind {
                    SinkKind::Network => {
                        format!("`{}` can send over the network: {}", self.function_name(function), hit.what)
                    }
                    SinkKind::File => format!("`{}` can write a file: {}", self.function_name(function), hit.what),
                };
                let confidence = match (hit.kind, hit.level) {
                    (SinkKind::Network, _) => Confidence::High,
                    (SinkKind::File, Level::Argument) => Confidence::Medium,
                    (SinkKind::File, _) => Confidence::Low,
                };
                sinks.push(Finding::new("list_imports", confidence, observation).at(hit.address).evidence(evidence));
            }
        }

        let mut paths = Section::new("Capture-to-send paths", limits);
        let mut triggers = Section::new("Capture triggers", limits);
        let mut unprompted = 0;
        let mut ranked_paths: Vec<(u64, u64)> = Vec::new();
        if let Some(graph) = &graph {
            let (found, cut) = survey.paths(graph, &roots);
            for (finding, pair) in found {
                paths.push(finding);
                ranked_paths.push(pair);
            }
            if cut {
                report.limitation(format!(
                    "The path search was bounded ({MAX_SOURCE_FUNCTIONS} source and {MAX_SINK_FUNCTIONS} sink \
                     functions, {MAX_DEPTH} call levels, {MAX_VISITED} functions per walk) and hit a bound; more \
                     distant paths are not listed."
                ));
            }
            let (found, quiet, cut) = survey.triggers(graph, &roots);
            triggers.extend(found);
            unprompted = quiet;
            if cut {
                report.limitation(format!(
                    "The trigger search walks at most {MAX_DEPTH} call levels and {MAX_VISITED} functions up from \
                     each capture and hit that bound for some; their triggers may be incomplete and they are not \
                     said to lack a user-facing trigger."
                ));
            }
        }
        let mut excluded = Section::new("Excluded: not capture", limits);
        excluded.extend(std::mem::take(&mut survey.excluded));

        let counts: Vec<String> = Medium::ALL
            .iter()
            .filter_map(|medium| {
                let count = survey.sources.values().flatten().filter(|hit| hit.medium == *medium).count();
                (count > 0).then(|| format!("{} {count}", medium.label()))
            })
            .collect();
        let network_sinks =
            survey.sinks.values().filter(|hits| hits.iter().any(|hit| hit.kind == SinkKind::Network)).count();
        let file_sinks = survey.sinks.len() - network_sinks;
        report.summary.push(if survey.sources.is_empty() && unreferenced.total == 0 {
            "No microphone, camera, screen or input-device capture was observed.".to_owned()
        } else {
            format!(
                "{} capture sources in {} functions ({}); {} functions can send over the network and {} more can \
                 write files; {} capture-to-send paths; {} captures are reached from program start with no \
                 user-facing trigger found on the way.",
                sources.total,
                survey.sources.len(),
                if counts.is_empty() { "strings only".to_owned() } else { counts.join(", ") },
                network_sinks,
                file_sinks,
                paths.total,
                unprompted
            )
        });
        report.summary.push(
            "This is evidence of what the code can do and how it is reached, not of intent or that it runs.".to_owned(),
        );

        for &(source, sink) in ranked_paths.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{source:#x}") }),
                format!(
                    "`{}` captures on a path to a sink; read what it records and passes on.",
                    self.function_name(source)
                ),
            );
            if sink != source {
                report.step(
                    "decompile",
                    json!({ "at": format!("{sink:#x}") }),
                    format!("`{}` sends or writes; read what it sends and where.", self.function_name(sink)),
                );
            }
        }
        if ranked_paths.is_empty()
            && let Some(&function) = survey.sources.keys().next()
        {
            report.step(
                "decompile",
                json!({ "at": format!("{function:#x}") }),
                format!("`{}` uses a capture API; read what it records.", self.function_name(function)),
            );
        }
        if !survey.sinks.is_empty() {
            report.step(
                "endpoint_inventory",
                json!({}),
                "List every endpoint the binary names, with the networking functions referencing each.",
            );
        }

        report.sections.extend([sources, paths, triggers, sinks, excluded, unreferenced]);
        report.limitation(
            "Sources and sinks are found by API name, by a few constant arguments read from the instructions just \
             before a call in the same block, and by device-path and class-name strings. Arguments built in another \
             block, passed through variables or helpers, raw system calls, APIs resolved at run time and Java/DEX \
             code are not read; a capture reached only that way is missed.",
        );
        report.limitation(
            "Paths and triggers follow direct calls and functions whose address code takes (callbacks, thread starts, \
             signal handlers); virtual calls and other indirect calls are not followed. A path shows that capture and \
             send code are connected by calls, not that captured data is sent; a shared caller reached only through \
             main or the entry point is not counted as a path.",
        );
        report.limitation(
            "A trigger names a function on a call chain reaching the capture: one that calls a timer API or sleeps in \
             a loop, receives from the network, or reads user input. \"No user-facing trigger found\" means none of \
             these input or UI calls was seen on any chain within the bounds, not that none exists.",
        );
        report.limitation(
            "V4L2 is also used for video output, decoders and HDMI input, and framebuffer queries for drawing; a \
             listed source shows the capability, not what is recorded.",
        );
        if survey.calls_read > 0 && !matches!(survey.arch, Arch::X86_64 | Arch::Aarch64 | Arch::Arm) {
            report.limitation(format!(
                "Constant arguments are read only on x86-64, AArch64 and 32-bit ARM; on {:?} every source is listed \
                 at `name` level and ioctl request codes are not read.",
                survey.arch
            ));
        }
        Ok(report)
    }

    /// Functions that start work on their own: the entry point, main, .init_array constructors, JNI_OnLoad and
    /// exports.
    fn roots(&self) -> BTreeMap<u64, Root> {
        let binary = &self.binary;
        let mut roots = BTreeMap::new();
        for export in &binary.exports {
            roots.insert(export.address, Root::Export);
        }
        for symbol in &binary.symbols {
            if matches!(symbol.name.as_str(), "main" | "_main" | "JNI_OnLoad") {
                let root = if symbol.name == "JNI_OnLoad" { Root::LibraryLoad } else { Root::Main };
                roots.insert(symbol.address, root);
            }
        }
        if let Some(entry) = binary.entry {
            roots.insert(entry, Root::Entry);
        }
        let width = usize::from(binary.arch.pointer_size().unwrap_or(8));
        for section in
            binary.sections.iter().filter(|section| section.name == ".init_array" || section.name == ".ctors")
        {
            let Some(bytes) = binary.read(section.address, section.size) else { continue };
            for chunk in bytes.chunks_exact(width) {
                let mut value = 0u64;
                for (index, &byte) in chunk.iter().enumerate() {
                    let shift = if binary.big_endian { (width - 1 - index) * 8 } else { index * 8 };
                    value |= u64::from(byte) << shift;
                }
                if value != 0 && value != u64::MAX && binary.is_code(value) {
                    roots.entry(value).or_insert(Root::Constructor);
                }
            }
        }
        roots
    }
}

/// The tool that produced a source's evidence.
fn source_tool(level: Level) -> &'static str {
    match level {
        Level::String => "list_strings",
        Level::Name => "list_imports",
        Level::Argument => "disassemble",
    }
}

fn ticked(names: &BTreeSet<String>) -> String {
    names.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ")
}

/// The call graph of `program`: callers by call, tail jump, and code taking a function's address.
fn graph(program: &rampage_analysis::discover::Program, containing: impl Fn(u64) -> Option<u64>) -> Graph {
    let mut callers: BTreeMap<u64, BTreeSet<(u64, Edge)>> = BTreeMap::new();
    let mut loops = BTreeSet::new();
    for xref in &program.xrefs {
        let Some(from) = containing(xref.from) else { continue };
        if xref.kind == XrefKind::Jump && xref.to <= xref.from && containing(xref.to) == Some(from) {
            loops.insert(from);
            continue;
        }
        if from == xref.to || program.function_at(xref.to).is_none() {
            continue;
        }
        let edge = if xref.kind == XrefKind::Data { Edge::Callback } else { Edge::Call };
        callers.entry(xref.to).or_default().insert((from, edge));
    }
    Graph { callers, loops }
}

impl Survey<'_> {
    fn name(&self, function: u64) -> String {
        self.project.function_name(function)
    }

    /// Capture strings: those referenced from code credit the referencing functions; the rest are listed apart.
    fn scan_strings(&mut self, unreferenced: &mut Section) {
        let analysis = self.project.analysis().ok();
        for found in self.project.scanned_strings() {
            let lower = found.text.to_ascii_lowercase().replace('.', "/");
            let Some(&(pattern, medium, what)) = SOURCE_STRINGS.iter().find(|(pattern, ..)| lower.contains(pattern))
            else {
                continue;
            };
            if pattern == "/dev/snd/pcmc" && !lower.trim_end().ends_with('c') {
                self.excluded.push(
                    Finding::new(
                        "list_strings",
                        Confidence::Medium,
                        format!("ALSA PCM playback device node {}", quote(&found.text)),
                    )
                    .at(found.address)
                    .evidence(["a PCM device node ending in `p` is a playback device"]),
                );
                continue;
            }
            let mut functions = BTreeSet::new();
            if let Some(analysis) = analysis {
                for xref in analysis.program.xrefs_to(found.address) {
                    if let Some(function) = analysis.function_containing(xref.from) {
                        functions.insert((function, xref.from));
                    }
                }
            }
            if functions.is_empty() {
                unreferenced.push(
                    Finding::new(
                        "list_strings",
                        Confidence::Low,
                        format!("{what} ({}): {}", medium.label(), quote(&found.text)),
                    )
                    .at(found.address)
                    .evidence([
                        format!("string at {:#x}", found.address),
                        "no reference from discovered code".to_owned(),
                    ]),
                );
                continue;
            }
            for (function, from) in functions {
                self.add_source(
                    function,
                    medium,
                    format!("references the {what} {}", quote(&found.text)),
                    Level::String,
                    from,
                    format!("string at {:#x} referenced at {from:#x}", found.address),
                );
            }
        }
    }

    fn add_source(&mut self, function: u64, medium: Medium, what: String, level: Level, at: u64, evidence: String) {
        let hits = self.sources.entry(function).or_default();
        if let Some(hit) = hits.iter_mut().find(|hit| hit.what == what) {
            hit.level = hit.level.max(level);
            hit.evidence.push(evidence);
        } else {
            hits.push(SourceHit { medium, what, level, evidence: vec![evidence], address: at });
        }
    }

    fn add_sink(&mut self, function: u64, kind: SinkKind, what: String, level: Level, at: u64, evidence: String) {
        let hits = self.sinks.entry(function).or_default();
        if let Some(hit) = hits.iter_mut().find(|hit| hit.what == what) {
            hit.level = hit.level.max(level);
            hit.evidence.push(evidence);
        } else {
            hits.push(SinkHit { kind, what, level, evidence: vec![evidence], address: at });
        }
    }

    /// Every call to a source, sink, write or trigger API, read for its constant arguments where they matter.
    fn scan_calls(&mut self) {
        let project = self.project;
        let Ok(analysis) = project.analysis() else { return };
        let mut apis: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for import in &project.binary.imports {
            let targets = apis.entry(import.name.clone()).or_default();
            targets.extend(
                project.binary.import_slots.iter().filter(|slot| slot.name == import.name).map(|slot| slot.address),
            );
            targets.extend(project.resolve(&import.name).ok());
        }
        for symbol in &project.binary.symbols {
            if symbol.kind == rampage_loaders::SymbolKind::Function && project.binary.is_code(symbol.address) {
                apis.entry(symbol.name.clone()).or_default().push(symbol.address);
            }
        }
        for (api, mut targets) in apis {
            let source = match_api(SOURCE_APIS, &api).or_else(|| {
                MANGLED_SOURCES.iter().find(|(fragment, _)| api.contains(fragment)).map(|&(_, source)| source)
            });
            let sink = match_api(SINK_APIS, &api);
            let marker = match_api(TRIGGER_APIS, &api);
            let write = WRITE_APIS.iter().any(|pattern| super::api_matches(pattern, &api));
            if source.is_none() && sink.is_none() && marker.is_none() && !write {
                continue;
            }
            targets.sort_unstable();
            targets.dedup();
            let mut sites: BTreeSet<(u64, u64, bool)> = BTreeSet::new();
            for &target in &targets {
                for xref in analysis.program.xrefs_to(target) {
                    let Some(function) = analysis.function_containing(xref.from) else { continue };
                    if targets.binary_search(&function).is_ok() {
                        continue;
                    }
                    sites.insert((function, xref.from, xref.kind != XrefKind::Data));
                }
            }
            for (function, site, call) in sites {
                if let Some(source) = source {
                    self.source_call(function, site, call, &api, source);
                }
                if let Some(sink) = sink {
                    self.sink_call(function, site, call, &api, sink);
                }
                if let Some(marker) = marker {
                    self.markers.entry(function).or_default().entry(marker).or_insert_with(|| format!("calls `{api}`"));
                }
                if write {
                    self.writes.entry(function).or_default().insert(api.clone());
                }
            }
        }
        // Reading input devices is user input for the captures it leads to.
        let input: Vec<u64> = self
            .sources
            .iter()
            .filter(|(_, hits)| hits.iter().any(|hit| hit.medium == Medium::Input))
            .map(|(&function, _)| function)
            .collect();
        for function in input {
            self.markers
                .entry(function)
                .or_default()
                .entry(Marker::UserInput)
                .or_insert_with(|| "reads an input device".to_owned());
        }
    }

    fn source_call(&mut self, function: u64, site: u64, call: bool, api: &str, source: SourceApi) {
        let at = format!("call to `{api}` at {site:#x}");
        if let Check::Ioctl { index } = source.check {
            // An ioctl is a source only for a known capture request.
            let request = match self.argument(function, site, index).filter(|_| call) {
                Some(Held::Constant(value)) => ioctl_request(value).map(|request| (value, request)),
                _ => None,
            };
            if let Some((value, (medium, request))) = request {
                let what = format!("issues the {request} ioctl");
                self.add_source(function, medium, what, Level::Argument, site, format!("{at}: request {value:#x}"));
            }
            return;
        }
        let outcome = if call { self.source_outcome(function, site, source) } else { Outcome::Unknown };
        match (outcome, source.check) {
            (Outcome::Confirmed(detail), _) => {
                let what = format!("{} for capture", source.what);
                self.add_source(function, source.medium, what, Level::Argument, site, format!("{at}: {detail}"));
            }
            (Outcome::Excluded(detail), _) => {
                let observation = format!("`{}` {}, not for capture", self.name(function), source.what);
                self.excluded.push(
                    Finding::new("disassemble", Confidence::High, observation)
                        .at(site)
                        .evidence([format!("{at}: {detail}")]),
                );
            }
            (Outcome::Unknown, Check::Name) => {
                self.add_source(function, source.medium, source.what.to_owned(), Level::Name, site, at);
            }
            (Outcome::Unknown, _) => {
                self.add_source(
                    function,
                    source.medium,
                    format!("{} (direction not read)", source.what),
                    Level::Name,
                    site,
                    format!("{at}: the argument that selects capture was not set by a constant just before the call"),
                );
            }
        }
    }

    fn source_outcome(&mut self, function: u64, site: u64, source: SourceApi) -> Outcome {
        let constant = |value: Option<Held>| match value {
            Some(Held::Constant(value)) => Some(value),
            _ => None,
        };
        match source.check {
            Check::Name => Outcome::Unknown,
            Check::Equals { index, argument, capture, other } => match constant(self.argument(function, site, index)) {
                Some(value) if value == capture.0 => {
                    Outcome::Confirmed(format!("{argument} = {value} ({})", capture.1))
                }
                Some(value) if value == other.0 => Outcome::Excluded(format!("{argument} = {value} ({})", other.1)),
                _ => Outcome::Unknown,
            },
            Check::Flag { index, argument, bit, flag } => match constant(self.argument(function, site, index)) {
                Some(value) if value & bit != 0 => Outcome::Confirmed(format!("{argument} = {value:#x} (sets {flag})")),
                Some(value) => Outcome::Excluded(format!("{argument} = {value:#x} (without {flag})")),
                None => Outcome::Unknown,
            },
            Check::NonZero { index, argument } => match self.argument(function, site, index) {
                Some(Held::Constant(0)) => Outcome::Excluded(format!("{argument} = 0 (no input)")),
                Some(Held::Constant(value)) => Outcome::Confirmed(format!("{argument} = {value}")),
                Some(Held::Address(address)) => Outcome::Confirmed(format!("{argument} = {address:#x}")),
                None => Outcome::Unknown,
            },
            Check::Ioctl { .. } => Outcome::Unknown,
        }
    }

    fn sink_call(&mut self, function: u64, site: u64, call: bool, api: &str, sink: SinkApi) {
        let at = format!("call to `{api}` at {site:#x}");
        let string = |survey: &mut Self, index: usize| match survey.argument(function, site, index) {
            Some(Held::Address(address)) => survey.string_at(address),
            _ => None,
        };
        match (sink.check, call) {
            (SinkCheck::Name, _) | (_, false) => {
                self.add_sink(function, sink.kind, format!("`{api}` ({})", sink.what), Level::Name, site, at);
            }
            (SinkCheck::Mode { index }, true) => match string(self, index) {
                Some(mode) if mode.starts_with('r') && !mode.contains('+') => {}
                Some(mode) => {
                    let path = string(self, 0).map(|path| format!(" {}", quote(&path))).unwrap_or_default();
                    self.add_sink(
                        function,
                        sink.kind,
                        format!("`{api}`{path} for writing"),
                        Level::Argument,
                        site,
                        format!("{at}: mode {}", quote(&mode)),
                    );
                }
                None => self.add_sink(function, sink.kind, format!("`{api}` (mode not read)"), Level::Name, site, at),
            },
            (SinkCheck::Flags { path, flags }, true) => {
                let path = string(self, path);
                if path.as_deref().is_some_and(|path| DEVICE_PREFIXES.iter().any(|prefix| path.starts_with(prefix))) {
                    return;
                }
                match self.argument(function, site, flags) {
                    Some(Held::Constant(value)) if value & 3 == 0 => {}
                    Some(Held::Constant(value)) => {
                        let named = path.map(|path| format!(" {}", quote(&path))).unwrap_or_default();
                        self.add_sink(
                            function,
                            sink.kind,
                            format!("`{api}`{named} for writing"),
                            Level::Argument,
                            site,
                            format!("{at}: flags {value:#x}"),
                        );
                    }
                    _ => self.add_sink(function, sink.kind, format!("`{api}` (flags not read)"), Level::Name, site, at),
                }
            }
        }
    }

    /// The NUL-terminated text at `address`, when it is one of the scanned strings or short readable bytes.
    fn string_at(&self, address: u64) -> Option<String> {
        if let Some(text) = self.strings.get(&address) {
            return Some(text.clone());
        }
        let bytes = self.project.binary.read(address, 16).or_else(|| self.project.binary.read(address, 4))?;
        let end = bytes.iter().position(|&byte| byte == 0)?;
        let text = std::str::from_utf8(&bytes[..end]).ok()?;
        (!text.is_empty() && text.chars().all(|c| c.is_ascii_graphic())).then(|| text.to_owned())
    }

    /// The constant or address argument `index` holds at the call at `site`, read from the instructions before the
    /// call in its block.
    fn argument(&mut self, function: u64, site: u64, index: usize) -> Option<Held> {
        let register = argument_registers(self.arch)?.get(index).copied()?;
        self.calls_read += 1;
        let project = self.project;
        let blocks = self
            .listings
            .entry(function)
            .or_insert_with(|| project.function_listing_for_frame(function).ok().map(|listing| listing.blocks))
            .as_ref()?;
        let block = blocks.iter().find(|block| block.iter().any(|line| line.address == site))?;
        let position = block.iter().position(|line| line.address == site)?;
        let start = position.saturating_sub(ARGUMENT_WINDOW);
        let mut value: Option<Held> = None;
        for line in &block[start..position] {
            let Some((mnemonic, operands)) = split(&line.text) else { continue };
            if matches!(line.flow, Flow::Call(_) | Flow::IndirectCall) {
                value = None;
                continue;
            }
            let Some(destination) = operands.first() else { continue };
            if register_index(self.arch, destination) != Some(register) || !writes_first_operand(&mnemonic) {
                continue;
            }
            value = written_value(self.project, &mnemonic, &operands, line, value);
        }
        value
    }

    /// The endpoints each function references in strings: (string address, endpoint value, local reason).
    fn endpoint_strings(&self) -> BTreeMap<u64, Vec<Named>> {
        let mut found: BTreeMap<u64, Vec<Named>> = BTreeMap::new();
        let Ok(analysis) = self.project.analysis() else { return found };
        for (&address, text) in &self.strings {
            let users: BTreeSet<u64> = analysis
                .program
                .xrefs_to(address)
                .iter()
                .filter_map(|xref| analysis.function_containing(xref.from))
                .collect();
            if users.is_empty() {
                continue;
            }
            for candidate in extract(text).found {
                if !matches!(candidate.kind, Kind::Url | Kind::Host | Kind::Ip | Kind::Local) {
                    continue;
                }
                let local = (candidate.kind == Kind::Local).then_some(candidate.reason.unwrap_or("not a public peer"));
                for &user in &users {
                    found.entry(user).or_default().push((address, candidate.value.clone(), local));
                }
            }
        }
        found
    }

    /// The endpoints a sink function, or a function calling it directly, references, as evidence lines.
    fn endpoints(&self, graph: &Graph, named: &BTreeMap<u64, Vec<Named>>, function: u64) -> Vec<String> {
        let mut functions = vec![function];
        if let Some(callers) = graph.callers.get(&function) {
            functions.extend(callers.iter().filter(|(_, edge)| *edge == Edge::Call).map(|(caller, _)| *caller));
        }
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        for user in functions {
            for (address, value, local) in named.get(&user).into_iter().flatten() {
                if lines.len() >= MAX_ENDPOINTS || !seen.insert(value.as_str()) {
                    continue;
                }
                let local = local.map(|reason| format!(" (local: {reason})")).unwrap_or_default();
                let by = if user == function { String::new() } else { format!(" by its caller `{}`", self.name(user)) };
                lines.push(format!("names endpoint {}{local}, string at {address:#x} referenced{by}", quote(value)));
            }
        }
        lines
    }

    /// The writable globals each of `functions` references.
    fn globals(&self, functions: &BTreeSet<u64>) -> BTreeMap<u64, BTreeSet<u64>> {
        let mut globals: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let Ok(analysis) = self.project.analysis() else { return globals };
        let binary = &self.project.binary;
        for xref in analysis.program.xrefs.iter().filter(|xref| xref.kind == XrefKind::Data) {
            if !binary.segment_containing(xref.to).is_some_and(|segment| segment.perms.write) {
                continue;
            }
            if let Some(function) =
                analysis.function_containing(xref.from).filter(|function| functions.contains(function))
            {
                globals.entry(function).or_default().insert(xref.to);
            }
        }
        globals
    }

    /// Capture-to-send paths, best first, each with its (source, sink) functions; and whether a bound was hit.
    fn paths(&self, graph: &Graph, roots: &BTreeMap<u64, Root>) -> (Vec<RankedPath>, bool) {
        let mut cut = self.sources.len() > MAX_SOURCE_FUNCTIONS || self.sinks.len() > MAX_SINK_FUNCTIONS;
        let sources: Vec<u64> = self
            .sources
            .iter()
            .filter(|(_, hits)| hits.iter().any(|hit| hit.medium != Medium::Input))
            .map(|(&function, _)| function)
            .take(MAX_SOURCE_FUNCTIONS)
            .collect();
        let sinks: Vec<u64> = self.sinks.keys().copied().take(MAX_SINK_FUNCTIONS).collect();
        let globals = self.globals(&sources.iter().chain(&sinks).copied().collect());
        let mut cones: BTreeMap<u64, Cone> = BTreeMap::new();
        for &function in sources.iter().chain(&sinks) {
            cones.entry(function).or_insert_with(|| graph.cone(function));
        }
        let mut found: Vec<(usize, Finding, (u64, u64))> = Vec::new();
        for &source in &sources {
            let source_cone = &cones[&source];
            let source_level = self.sources[&source].iter().map(|hit| hit.level).max().unwrap_or(Level::String);
            let mediums: BTreeSet<&str> = self.sources[&source].iter().map(|hit| hit.medium.label()).collect();
            for &sink in &sinks {
                let sink_cone = &cones[&sink];
                cut |= source_cone.cut || sink_cone.cut;
                let kind = self.sinks[&sink].iter().map(|hit| hit.kind).min().unwrap_or(SinkKind::File);
                let (rank, relation, chain) = if source == sink {
                    (0, "in the same function".to_owned(), vec![self.name(source)])
                } else if let Some(depth) = sink_cone.depth(source) {
                    let chain = self.render(&sink_cone.chain(source));
                    let how = if depth == 1 {
                        "calls the sink directly".to_owned()
                    } else {
                        format!("reaches the sink {depth} calls down")
                    };
                    (depth, format!("the capturing function {how}"), chain)
                } else if let Some(depth) = source_cone.depth(sink) {
                    let chain = self.render(&source_cone.chain(sink));
                    let how = if depth == 1 {
                        "calls the capture directly".to_owned()
                    } else {
                        format!("reaches the capture {depth} calls down")
                    };
                    (depth, format!("the sending function {how}"), chain)
                } else {
                    let shared = source_cone
                        .reached
                        .iter()
                        .filter(|(function, _)| {
                            !roots.get(function).is_some_and(|root| matches!(root, Root::Entry | Root::Main))
                        })
                        .filter_map(|(&function, &(up, _))| sink_cone.depth(function).map(|down| (up + down, function)))
                        .filter(|&(levels, _)| levels <= MAX_SHARED_LEVELS)
                        .min();
                    let Some((levels, ancestor)) = shared else { continue };
                    let mut chain = self.render(&source_cone.chain(ancestor));
                    let to_sink = self.render(&sink_cone.chain(ancestor));
                    chain.push(format!("and {}", to_sink.join(" -> ")));
                    (
                        levels + 1,
                        format!("both are reached from `{}` ({levels} calls in all)", self.name(ancestor)),
                        chain,
                    )
                };
                let mut confidence = match rank {
                    0 | 1 => Confidence::High,
                    2 | 3 => Confidence::Medium,
                    _ => Confidence::Low,
                };
                if kind == SinkKind::File {
                    confidence = lower(confidence);
                }
                if source_level == Level::String {
                    confidence = lower(confidence);
                }
                let sink_what: Vec<&str> = self.sinks[&sink].iter().map(|hit| hit.what.as_str()).collect();
                let target = match kind {
                    SinkKind::Network => "the network",
                    SinkKind::File => "a file",
                };
                let mut evidence = vec![
                    format!("chain: {}", chain.join(" -> ")),
                    format!("capture: {} (evidence: {})", self.whats(source), source_level.as_str()),
                    format!("sink: {}", sink_what.join(", ")),
                ];
                if let Some(global) = self.shared_global(&globals, source, sink) {
                    evidence.push(global);
                }
                // A direct call to a network send outranks a file write in the same function.
                let score =
                    rank * 2 + usize::from(kind == SinkKind::File) * 3 + usize::from(source_level == Level::String);
                found.push((
                    score,
                    Finding::new(
                        "xrefs",
                        confidence,
                        format!(
                            "{} capture in `{}` and a send to {target} in `{}`: {relation}",
                            mediums.iter().copied().collect::<Vec<_>>().join("/"),
                            self.name(source),
                            self.name(sink)
                        ),
                    )
                    .at(source)
                    .evidence(evidence),
                    (source, sink),
                ));
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.confidence.cmp(&a.1.confidence)));
        (found.into_iter().map(|(_, finding, pair)| (finding, pair)).collect(), cut)
    }

    /// A writable global that both functions reference, if any (a shared buffer is a cheap hint of a data link).
    fn shared_global(&self, globals: &BTreeMap<u64, BTreeSet<u64>>, source: u64, sink: u64) -> Option<String> {
        if source == sink {
            return None;
        }
        let shared = globals.get(&source)?.intersection(globals.get(&sink)?).next().copied()?;
        let name = self
            .project
            .binary
            .symbols
            .iter()
            .find(|symbol| symbol.address == shared)
            .map(|symbol| format!(" (`{}`)", symbol.name))
            .unwrap_or_default();
        Some(format!("both reference the writable global at {shared:#x}{name}"))
    }

    fn whats(&self, function: u64) -> String {
        let whats: BTreeSet<&str> = self.sources[&function].iter().map(|hit| hit.what.as_str()).collect();
        whats.into_iter().collect::<Vec<_>>().join("; ")
    }

    /// A chain as function names, a callback edge marked as such.
    fn render(&self, chain: &[(u64, Option<Edge>)]) -> Vec<String> {
        chain
            .iter()
            .map(|&(function, edge)| match edge {
                Some(Edge::Callback) => format!("{} (registers callback)", self.name(function)),
                _ => self.name(function),
            })
            .collect()
    }

    /// What reaches each capture, and how many captures are reached from program start with no user-facing trigger
    /// found; and whether a walk was cut.
    fn triggers(&self, graph: &Graph, roots: &BTreeMap<u64, Root>) -> (Vec<Finding>, usize, bool) {
        let mut findings = Vec::new();
        let mut unprompted = 0;
        let mut cut_any = false;
        for (&source, hits) in self.sources.iter().take(MAX_SOURCE_FUNCTIONS) {
            let mediums: BTreeSet<Medium> = hits.iter().map(|hit| hit.medium).collect();
            let label = mediums.iter().map(|medium| medium.label()).collect::<Vec<_>>().join("/");
            let cone = graph.cone(source);
            cut_any |= cone.cut;
            let mut by_depth: Vec<(usize, u64)> =
                cone.reached.iter().map(|(&function, &(depth, _))| (depth, function)).collect();
            by_depth.sort_unstable();
            let mut start: Option<(u64, Root)> = None;
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut user_input = false;
            let name = self.name(source);
            for &(_, function) in &by_depth {
                let chain = cone.chain(function);
                let edge = chain.first().and_then(|(_, edge)| *edge);
                let rendered = self.render(&chain).join(" -> ");
                if let Some(&root) = roots.get(&function)
                    && start.is_none_or(|(_, found)| !found.at_start() && root.at_start())
                {
                    start = Some((function, root));
                }
                let Some(markers) = self.markers.get(&function) else { continue };
                for (&marker, api) in markers {
                    // An input reader is not its own user trigger.
                    if marker == Marker::UserInput && function == source && mediums.contains(&Medium::Input) {
                        continue;
                    }
                    let (kind, observation, confidence) = match marker {
                        Marker::UserInput => {
                            user_input = true;
                            (
                                "user input",
                                format!("{label} capture in `{name}` follows user input"),
                                Confidence::Medium,
                            )
                        }
                        Marker::Timer if edge == Some(Edge::Callback) => (
                            "timer",
                            format!("{label} capture in `{name}` runs from a callback registered beside a timer"),
                            Confidence::Medium,
                        ),
                        Marker::Timer => (
                            "timer",
                            format!("{label} capture in `{name}` is reached from a function that sets a timer"),
                            Confidence::Low,
                        ),
                        Marker::Sleep if graph.loops.contains(&function) => (
                            "periodic loop",
                            format!("{label} capture in `{name}` is reached from a loop that sleeps"),
                            Confidence::Low,
                        ),
                        Marker::Sleep => continue,
                        Marker::Receive => (
                            "network command",
                            format!(
                                "{label} capture in `{name}` is reached from a function that receives from the network"
                            ),
                            if edge == Some(Edge::Callback) || chain.len() <= 3 {
                                Confidence::Medium
                            } else {
                                Confidence::Low
                            },
                        ),
                    };
                    if !seen.insert(kind) {
                        continue;
                    }
                    findings.push(Finding::new("xrefs", confidence, observation).at(source).evidence([
                        format!("trigger: {kind}"),
                        format!("`{}` {api}", self.name(function)),
                        format!("chain: {rendered}"),
                    ]));
                }
            }
            if let Some((function, root)) = start {
                let rendered = self.render(&cone.chain(function)).join(" -> ");
                let kind = if root.at_start() { "program start" } else { "export" };
                findings.push(
                    Finding::new(
                        "xrefs",
                        Confidence::Medium,
                        format!("{label} capture in `{name}` is reached from {}", root.label()),
                    )
                    .at(source)
                    .evidence([format!("trigger: {kind}"), format!("chain: {rendered}")]),
                );
                let capture = mediums.iter().any(|medium| *medium != Medium::Input);
                if root.at_start() && capture && !user_input && !cone.cut {
                    unprompted += 1;
                    findings.push(
                        Finding::new(
                            "xrefs",
                            Confidence::Medium,
                            format!(
                                "no_user_trigger: {label} capture in `{name}` is reached from {} with no input-event \
                                 or UI handling found on any call chain to it",
                                root.label()
                            ),
                        )
                        .at(source)
                        .evidence([
                            format!("chain: {rendered}"),
                            format!(
                                "{} functions within {MAX_DEPTH} call levels above it; none reads an input device or runs a UI event loop",
                                cone.reached.len()
                            ),
                        ]),
                    );
                }
            } else if !cone.cut {
                findings.push(
                    Finding::new("xrefs", Confidence::Low, format!("{label} capture in `{name}`: no trigger found"))
                        .at(source)
                        .evidence([format!(
                            "no entry point, main, constructor or export is among the {} functions within {MAX_DEPTH} \
                             call levels above it; it may be reached through an indirect call",
                            cone.reached.len()
                        )]),
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

/// The registers that carry the first arguments of a call, in order, under the ELF ABIs modelled here.
fn argument_registers(arch: Arch) -> Option<&'static [usize]> {
    match arch {
        Arch::X86_64 => Some(&[0, 1, 2, 3, 4, 5]),
        Arch::Aarch64 => Some(&[0, 1, 2, 3, 4, 5, 6, 7]),
        Arch::Arm => Some(&[0, 1, 2, 3]),
        _ => None,
    }
}

/// The argument position a register name carries, if it is an argument register.
fn register_index(arch: Arch, register: &str) -> Option<usize> {
    match arch {
        Arch::X86_64 => [
            ["rdi", "edi", "di", "dil"],
            ["rsi", "esi", "si", "sil"],
            ["rdx", "edx", "dx", "dl"],
            ["rcx", "ecx", "cx", "cl"],
            ["r8", "r8d", "r8w", "r8b"],
            ["r9", "r9d", "r9w", "r9b"],
        ]
        .iter()
        .position(|names| names.contains(&register)),
        Arch::Aarch64 => {
            let number = register.strip_prefix('x').or_else(|| register.strip_prefix('w'))?;
            number.parse::<usize>().ok().filter(|&number| number < 8)
        }
        Arch::Arm => register.strip_prefix('r')?.parse::<usize>().ok().filter(|&number| number < 4),
        _ => None,
    }
}

/// The lowercase mnemonic and operands of an instruction's text.
fn split(text: &str) -> Option<(String, Vec<String>)> {
    let text = text.trim().to_ascii_lowercase();
    let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap_or((&text, ""));
    let operands =
        rest.split(',').map(|operand| operand.trim().to_owned()).filter(|operand| !operand.is_empty()).collect();
    Some((mnemonic.to_owned(), operands))
}

/// Whether the instruction writes its first operand (stores, compares and pushes do not).
fn writes_first_operand(mnemonic: &str) -> bool {
    !(mnemonic.starts_with("st")
        || mnemonic.starts_with("cmp")
        || mnemonic.starts_with("cmn")
        || mnemonic.starts_with("tst")
        || mnemonic.starts_with("test")
        || mnemonic.starts_with("push")
        || mnemonic.starts_with("cb")
        || mnemonic.starts_with("tb")
        || mnemonic.starts_with("b.")
        || mnemonic == "teq")
}

/// The value an instruction writing an argument register leaves in it, given the value before (`movk`/`movt`
/// merge into it); `None` when it is not a constant or address.
fn written_value(
    project: &Project,
    mnemonic: &str,
    operands: &[String],
    line: &DisassemblyLine,
    before: Option<Held>,
) -> Option<Held> {
    let source = operands.get(1).map(String::as_str);
    match mnemonic {
        "xor" | "eor" | "sub" if operands.len() == 2 && source == operands.first().map(String::as_str) => {
            Some(Held::Constant(0))
        }
        "mov" | "movz" | "movabs" | "movw" => {
            if matches!(source, Some("wzr" | "xzr")) {
                return Some(Held::Constant(0));
            }
            if let Some(address) = line.data_ref.filter(|_| !line.accesses) {
                return Some(Held::Address(address));
            }
            if line.accesses {
                return None;
            }
            let value = number(source?)?;
            Some(Held::Constant(value << shift(operands)))
        }
        "orr" if operands.len() == 3 && matches!(operands[1].as_str(), "wzr" | "xzr") => {
            number(&operands[2]).map(Held::Constant)
        }
        "movk" => {
            let Some(Held::Constant(previous)) = before else { return None };
            let amount = shift(operands);
            let value = number(source?)?;
            Some(Held::Constant((previous & !(0xffff << amount)) | (value << amount)))
        }
        "movt" => {
            let Some(Held::Constant(previous)) = before else { return None };
            let value = number(source?)?;
            Some(Held::Constant((previous & 0xffff) | (value << 16)))
        }
        "lea" | "adr" | "add" | "adrp" => match line.data_ref {
            Some(address) if !line.accesses && mnemonic != "adrp" => Some(Held::Address(address)),
            _ => None,
        },
        "ldr" => {
            let address = line.data_ref.filter(|_| line.accesses)?;
            let width = if operands.first().is_some_and(|register| register.starts_with('x')) { 8 } else { 4 };
            project.binary.read_constant(address, width).map(Held::Constant)
        }
        _ => None,
    }
}

/// The `lsl #n` shift of an AArch64 move-wide operand list, or 0.
fn shift(operands: &[String]) -> u32 {
    operands
        .iter()
        .find_map(|operand| operand.strip_prefix("lsl"))
        .and_then(|amount| number(amount.trim()))
        .map_or(0, |amount| amount as u32)
}

/// An immediate as written: `#0x10`, `#16`, `0x10`, `10h` or `16`.
fn number(text: &str) -> Option<u64> {
    let text = text.trim().trim_start_matches('#');
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let value = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = text.strip_suffix('h') {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        text.parse::<u64>().ok()?
    };
    Some(if negative { value.wrapping_neg() } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_requests_match_any_abi_size() {
        // VIDIOC_DQBUF with a 64-bit (88-byte) and a 32-bit (68-byte) struct v4l2_buffer, and MIPS's direction bits.
        for code in [0xc058_5611, 0xc044_5611, 0xc058_5611 & !0xc000_0000 | 0xc000_0000] {
            assert_eq!(ioctl_request(code), Some((Medium::Camera, "VIDIOC_DQBUF")), "{code:#x}");
        }
        assert_eq!(ioctl_request(0x4004_5612), Some((Medium::Camera, "VIDIOC_STREAMON")));
        assert_eq!(ioctl_request(0x4004_4590), Some((Medium::Input, "EVIOCGRAB")));
        assert_eq!(ioctl_request(0x4600), Some((Medium::Screen, "FBIOGET_VSCREENINFO")));
        // A console request (VT_OPENQRY, 0x5600) is a plain 'V' code, not V4L2.
        assert_eq!(ioctl_request(0x5600), None);
        assert_eq!(ioctl_request(0x5401), None);
    }

    #[test]
    fn source_and_sink_names_match_decorated_imports() {
        assert!(matches!(
            match_api(SOURCE_APIS, "snd_pcm_open@plt"),
            Some(SourceApi { medium: Medium::Microphone, .. })
        ));
        assert!(match_api(SOURCE_APIS, "Pa_OpenDefaultStream").is_some());
        assert!(match_api(SOURCE_APIS, "snd_pcm_writei").is_none());
        assert!(match_api(SOURCE_APIS, "pcm_write").is_none());
        assert_eq!(match_api(SINK_APIS, "curl_easy_perform").map(|sink| sink.kind), Some(SinkKind::Network));
        assert_eq!(match_api(SINK_APIS, "fopen64").map(|sink| sink.kind), Some(SinkKind::File));
        assert!(match_api(SINK_APIS, "recv").is_none());
        assert_eq!(match_api(TRIGGER_APIS, "g_timeout_add_seconds"), Some(Marker::Timer));
        let mangled = "_ZN7android11AudioRecord5startENS_11AudioSystem12sync_event_tE";
        assert!(MANGLED_SOURCES.iter().any(|(fragment, _)| mangled.contains(fragment)));
        assert!(!MANGLED_SOURCES.iter().any(|(fragment, _)| "_ZN7android16CameraParametersC1Ev".contains(fragment)));
    }

    #[test]
    fn immediates_parse_in_every_spelling() {
        assert_eq!(number("#0x5612"), Some(0x5612));
        assert_eq!(number("#22034"), Some(22034));
        assert_eq!(number("40044590h"), Some(0x4004_4590));
        assert_eq!(number("1"), Some(1));
        assert_eq!(number("rdx"), None);
        assert_eq!(shift(&["w1".into(), "#0x4004".into(), "lsl #16".into()]), 16);
    }

    #[test]
    fn argument_registers_by_abi() {
        assert_eq!(register_index(Arch::X86_64, "edx"), Some(2));
        assert_eq!(register_index(Arch::X86_64, "r8d"), Some(4));
        assert_eq!(register_index(Arch::X86_64, "rbx"), None);
        assert_eq!(register_index(Arch::Aarch64, "w2"), Some(2));
        assert_eq!(register_index(Arch::Aarch64, "x19"), None);
        assert_eq!(register_index(Arch::Arm, "r3"), Some(3));
        assert!(!writes_first_operand("str"));
        assert!(!writes_first_operand("cmp"));
        assert!(writes_first_operand("mov"));
    }
}

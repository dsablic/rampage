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
use std::time::{Duration, Instant};

use rampage_analysis::discover::{Program, XrefKind};
use rampage_arch::{Arch, Flow};
use serde_json::{Value, json};

use super::registry::{Workflow, WorkflowOptions};
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
    /// For `Check::Name`: whether the name alone shows capture (a capture-only API), rather than an API also used
    /// without capturing. With an argument check, the argument decides.
    specific: bool,
}

const fn name(medium: Medium, what: &'static str) -> SourceApi {
    SourceApi { medium, what, check: Check::Name, specific: true }
}

/// An API also used without capturing (a compositor reads the displayed framebuffer too).
const fn vague(medium: Medium, what: &'static str) -> SourceApi {
    SourceApi { medium, what, check: Check::Name, specific: false }
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
    specific: true,
};
const IOCTL: SourceApi =
    SourceApi { medium: Medium::Camera, what: "ioctl", check: Check::Ioctl { index: 1 }, specific: false };

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
            specific: true,
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
            specific: true,
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
            specific: true,
        },
    ),
    (
        "pa_openstream",
        SourceApi {
            medium: Medium::Microphone,
            what: "opens a PortAudio stream",
            check: Check::NonZero { index: 1, argument: "input parameters" },
            specific: true,
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
            specific: true,
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
    ("drmmodegetfb", vague(Medium::Screen, "reads the displayed DRM framebuffer's handle")),
    ("drmmodegetfb2", vague(Medium::Screen, "reads the displayed DRM framebuffer's handle")),
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

/// Lowercase fragments of device paths and framework class names in strings (`.` read as `/`). A string shows a
/// capability, never the direction of use, so no string drives `no_user_trigger`. ALSA PCM nodes are told apart by
/// their last letter (see `pcm_node`).
const SOURCE_STRINGS: &[(&str, Medium, &str)] = &[
    ("/dev/snd/pcmc", Medium::Microphone, "ALSA PCM device node"),
    ("/proc/asound", Medium::Microphone, "ALSA sound-card listing (either direction)"),
    ("/dev/video", Medium::Camera, "V4L2 video device node (capture, output or codec)"),
    ("/dev/graphics/fb", Medium::Screen, "framebuffer device node (drawing or reading)"),
    ("/dev/fb", Medium::Screen, "framebuffer device node (drawing or reading)"),
    ("/dev/dri/", Medium::Screen, "DRM device node (display or rendering)"),
    ("/dev/input/", Medium::Input, "input event device node"),
    ("android/media/audiorecord", Medium::Microphone, "Android AudioRecord class"),
    ("android/media/mediarecorder", Medium::Microphone, "Android MediaRecorder class (audio or video)"),
    ("android/hardware/camera", Medium::Camera, "Android camera class"),
    ("android/media/projection/mediaprojection", Medium::Screen, "Android MediaProjection (screen capture) class"),
];

/// What an ALSA PCM node string says: `Some(true)` capture (`...c`), `Some(false)` playback (`...p`), `None`
/// either (no direction letter, or one a format fills in, as in `pcmC%uD%u%c`).
fn pcm_node(lower: &str) -> Option<bool> {
    let text = lower.trim_end();
    let mut tail = text.chars().rev();
    let last = tail.next()?;
    if tail.next() == Some('%') {
        return None;
    }
    match last {
        'c' => Some(true),
        'p' => Some(false),
        _ => None,
    }
}

/// ioctl request codes, matched by type and number with any size and direction encoding (which differ between
/// 32- and 64-bit ABIs and on MIPS and PowerPC), each with a note when the request is not specific to capture.
const IOCTL_REQUESTS: &[(u8, u8, Medium, &str, Option<&str>)] = &[
    (b'V', 0, Medium::Camera, "VIDIOC_QUERYCAP", Some("a capability query; output and codec devices answer it too")),
    (b'V', 5, Medium::Camera, "VIDIOC_S_FMT", Some("format setup; also for video output and codec devices")),
    (b'V', 8, Medium::Camera, "VIDIOC_REQBUFS", Some("buffer setup; also for video output and codec devices")),
    (b'V', 9, Medium::Camera, "VIDIOC_QUERYBUF", Some("buffer setup; also for video output and codec devices")),
    (b'V', 15, Medium::Camera, "VIDIOC_QBUF", Some("buffer queueing; also for video output and codec devices")),
    (b'V', 17, Medium::Camera, "VIDIOC_DQBUF", None),
    (b'V', 18, Medium::Camera, "VIDIOC_STREAMON", None),
    (b'E', 0x06, Medium::Input, "EVIOCGNAME", Some("a device name query")),
    (b'E', 0x90, Medium::Input, "EVIOCGRAB", None),
    (b'd', 0xad, Medium::Screen, "DRM_IOCTL_MODE_GETFB", Some("compositors also read the displayed framebuffer")),
    (b'd', 0xce, Medium::Screen, "DRM_IOCTL_MODE_GETFB2", Some("compositors also read the displayed framebuffer")),
];

/// A known request: its medium, name, and a note when it is not specific to capture.
type Request = (Medium, &'static str, Option<&'static str>);

/// The capture request an ioctl code names. Framebuffer requests predate the size/direction encoding. A code
/// sign-extended into a 64-bit register is read by its low 32 bits.
fn ioctl_request(value: u64) -> Option<Request> {
    let value = value & 0xffff_ffff;
    const GEOMETRY: Option<&str> = Some("framebuffer geometry; drawing code issues it too");
    match value {
        0x4600 => return Some((Medium::Screen, "FBIOGET_VSCREENINFO", GEOMETRY)),
        0x4602 => return Some((Medium::Screen, "FBIOGET_FSCREENINFO", GEOMETRY)),
        _ => {}
    }
    // Encoded requests carry a size or direction above bit 16; plain 'V' codes below it are console requests.
    if value >> 16 == 0 {
        return None;
    }
    let (kind, number) = ((value >> 8) as u8, value as u8);
    if kind == b'E' && (0x20..0x40).contains(&number) {
        return Some((Medium::Input, "EVIOCGBIT", Some("an event-type query")));
    }
    IOCTL_REQUESTS
        .iter()
        .find(|(k, n, ..)| *k == kind && *n == number)
        .map(|&(_, _, medium, request, note)| (medium, request, note))
}

/// Where data can leave: the network; a socket that may be network or local IPC; or a file (weaker, since a file is
/// sent only if something uploads it).
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

    /// Rank penalty in path ordering: a direct network send outranks a file write in the same function.
    fn weight(self) -> usize {
        match self {
            SinkKind::Network => 0,
            SinkKind::Socket => 1,
            SinkKind::File => 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SinkCheck {
    Name,
    /// `fopen`: argument `index` is the mode string (a read-only mode is no sink) and argument 0 the path (a
    /// device or pseudo-file path is no sink).
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

const fn socket(what: &'static str) -> SinkApi {
    SinkApi { kind: SinkKind::Socket, what, check: SinkCheck::Name }
}

/// Send and write APIs (patterns, see `api_matches`). The network ones are the sending part of `network_surface`'s
/// table plus MQTT and WebSocket clients; bare socket calls serve local IPC as well (see `socket_domains`).
const SINK_APIS: &[(&str, SinkApi)] = &[
    ("send", socket("socket send")),
    ("sendto", socket("socket send")),
    ("sendmsg", socket("socket send")),
    ("sendmmsg", socket("socket send")),
    ("connect", socket("socket connect")),
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
/// Linux socket domains: local IPC, and the two internet families.
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

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
/// Source and sink functions paired.
const MAX_SOURCE_FUNCTIONS: usize = 200;
const MAX_SINK_FUNCTIONS: usize = 400;
/// Time the path search may take before it stops and says so.
const PATH_BUDGET: Duration = Duration::from_secs(5);
/// Bytes of non-code segments scanned for pointers to functions (tables of handlers and operations).
const MAX_POINTER_SCAN: usize = 64 << 20;
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

/// Device paths and class names a quick byte search looks for before a tree's program is analysed.
const CAPTURE_MARKS: [&[u8]; 11] = [
    b"/dev/snd",
    b"/proc/asound",
    b"/dev/video",
    b"/dev/fb",
    b"/dev/graphics/fb",
    b"/dev/dri/",
    b"/dev/input/",
    b"AudioRecord",
    b"MediaRecorder",
    b"android/hardware/Camera",
    b"MediaProjection",
];

/// Whether a program may capture, read cheaply before analysis: it imports a capture API, or its bytes name a
/// capture device or Android capture class. A program for which this is false has no source the report could
/// list except through raw system calls.
pub(crate) fn may_capture(binary: &rampage_loaders::Binary, bytes: &[u8]) -> bool {
    binary.imports.iter().any(|import| capture_api(&import.name))
        || CAPTURE_MARKS.iter().any(|mark| memchr::memmem::find(bytes, mark).is_some())
}

pub struct PrivacySurface;

// The arguments of privacy_surface. Not a doc comment: the schema would carry it.
#[derive(serde::Deserialize, schemars::JsonSchema)]
struct PrivacyArgs {
    /// Findings kept per report section (default 25, at most 200); each section says when it was cut, and large
    /// reports are cut further to fit one tool result.
    max_per_section: Option<usize>,
    /// Directory: the input.next_cursor of the previous page.
    cursor: Option<String>,
    /// Directory: programs and APKs analysed per page (default 10, at most 50).
    max_files: Option<usize>,
    /// Directory: time budget per page in ms (default 30000, at most 300000); one file is always analysed.
    timeout_ms: Option<u64>,
}

/// What one JNI export reaches in its library through direct calls.
#[derive(Debug, Clone, Default)]
pub(crate) struct JniReach {
    pub(crate) function: String,
    pub(crate) address: u64,
    /// `(function, what, sink target, calls down)`.
    pub(crate) sinks: Vec<(String, String, &'static str, usize)>,
    /// `(function, what, medium, calls down, whether the evidence shows direction)`.
    pub(crate) sources: Vec<(String, String, &'static str, usize, bool)>,
    /// Whether the walk hit its bound.
    pub(crate) cut: bool,
}

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
         start, timer, network command, user input). Evidence, not intent. path may also be an APK/DEX (capture and \
         network APIs invoked from DEX, a call graph with by_name virtual edges, triggers from the manifest and \
         framework callbacks: boot, push, jobs, UI; native libraries merged, Java callers of native methods linked \
         to what the JNI export reaches) or a directory (an extracted tree: programs that may capture, with init \
         .rc/systemd/init.d boot starts; paged by cursor)."
    }

    fn group(&self) -> Group {
        Group::Carve
    }

    fn input_schema(&self) -> Value {
        crate::tools::schema::<PrivacyArgs>()
    }

    fn options(&self, input: Value) -> Result<WorkflowOptions, String> {
        let args: PrivacyArgs = crate::tools::arguments(input)?;
        let _ = (args.cursor, args.max_files, args.timeout_ms);
        Ok(WorkflowOptions { limits: ReportLimits::new(args.max_per_section), ..WorkflowOptions::default() })
    }

    fn run(&self, project: &Project, options: &WorkflowOptions) -> Result<WorkflowReport, ApiError> {
        project.privacy_surface(options.limits)
    }
}

/// The value a register holds before a call, as far as the instructions just before it show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Constant(u64),
    /// A constant that is also an address in the image (a string, or a number that happens to look like one).
    Address(u64),
}

impl Held {
    /// The number held, whether or not it looks like an address.
    fn number(self) -> u64 {
        match self {
            Held::Constant(value) | Held::Address(value) => value,
        }
    }
}

/// One instruction as the argument reader sees it.
struct Instruction<'a> {
    text: &'a str,
    data_ref: Option<u64>,
    accesses: bool,
    call: bool,
}

/// What one call site's arguments say about a source or sink API.
enum Outcome {
    Confirmed(String),
    Excluded(String),
    Unknown,
}

/// An endpoint a function names: string address, value, and why it is local (when it is).
type Named = (u64, String, Option<&'static str>);

/// One capture source in one function.
struct SourceHit {
    medium: Medium,
    what: String,
    level: Level,
    /// Whether the evidence shows capture in particular, not a device or API also used the other way.
    specific: bool,
    evidence: Vec<String>,
    address: u64,
}

impl SourceHit {
    fn confidence(&self) -> Confidence {
        if self.specific { self.level.confidence() } else { lower(self.level.confidence()) }
    }
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
#[derive(Default)]
struct Graph {
    callers: BTreeMap<u64, BTreeSet<(u64, Edge)>>,
    /// Direct calls only, caller to callees.
    callees: BTreeMap<u64, BTreeSet<u64>>,
    /// Functions with a backward jump (a loop).
    loops: BTreeSet<u64>,
    /// Functions whose address is stored outside code (a table of handlers or operations, a vtable): their callers
    /// through it are not known.
    data_referenced: BTreeSet<u64>,
    /// Whether the scan for such pointers stopped at `MAX_POINTER_SCAN`.
    pointer_scan_cut: bool,
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

    fn add(&mut self, caller: u64, callee: u64, edge: Edge) {
        self.callers.entry(callee).or_default().insert((caller, edge));
        if edge == Edge::Call {
            self.callees.entry(caller).or_default().insert(callee);
        }
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

/// How a capture function relates to a sink function.
#[derive(Debug, Clone, Copy)]
enum Relation {
    Same,
    /// The capturing function reaches the sink this many calls down.
    SourceCalls(usize),
    /// The sending function reaches the capture this many calls down.
    SinkCalls(usize),
    /// Both are reached from `ancestor`, `levels` calls in all.
    Shared {
        ancestor: u64,
        levels: usize,
    },
}

/// A scored capture-to-sink pair, turned into a finding only if it ranks within the section.
struct PathMatch {
    score: usize,
    confidence: Confidence,
    source: u64,
    sink: u64,
    kind: SinkKind,
    relation: Relation,
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
    /// The constant domain of each `socket` call, per function (`None` when not read).
    socket_domains: BTreeMap<u64, Vec<Option<u64>>>,
    strings: BTreeMap<u64, String>,
    /// Calls whose arguments mattered but could not be read on this architecture.
    unread_calls: usize,
}

impl Project {
    /// What the binary can capture and send, the paths between, and what starts each capture.
    pub fn privacy_surface(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        self.privacy_surface_with(limits, &[]).map(|(report, _)| report)
    }

    /// [`Project::privacy_surface`], plus what each of the exported functions named in `exports` (JNI symbols)
    /// reaches through direct calls: the sinks and sources of the report in it or below it.
    pub(crate) fn privacy_surface_with(
        &self,
        limits: ReportLimits,
        exports: &[String],
    ) -> Result<(WorkflowReport, BTreeMap<String, JniReach>), ApiError> {
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
            socket_domains: BTreeMap::new(),
            strings: self.scanned_strings().iter().map(|found| (found.address, found.text.clone())).collect(),
            unread_calls: 0,
        };
        let mut unreferenced = Section::new("Capture strings not referenced from code", limits);
        survey.scan_strings(&mut unreferenced);
        if analysis.is_some() {
            survey.scan_calls();
            survey.classify_sockets();
        }
        let graph =
            analysis.map(|analysis| graph(self, &analysis.program, |address| analysis.function_containing(address)));
        let roots = self.roots();
        let reach = graph.as_ref().map(|graph| survey.reach(graph, exports)).unwrap_or_default();

        let mut found: Vec<Finding> = Vec::new();
        for (&function, hits) in &survey.sources {
            for hit in hits {
                let mut evidence = vec![format!("evidence: {}", hit.level.as_str())];
                if !hit.specific {
                    evidence.push(
                        "ambiguous: this API, request or device is also used without capturing (the other \
                         direction, display or decoding)"
                            .to_owned(),
                    );
                }
                evidence.push(format!("in function at {function:#x}"));
                evidence.extend(hit.evidence.iter().cloned());
                found.push(
                    Finding::new(
                        source_tool(hit.level),
                        hit.confidence(),
                        format!("`{}` {} ({})", self.function_name(function), hit.what, hit.medium.label()),
                    )
                    .at(hit.address)
                    .evidence(evidence),
                );
            }
        }
        // Sorted before the section keeps its first findings, so the strongest are the ones kept.
        found.sort_by_key(|finding| std::cmp::Reverse(finding.confidence));
        let mut sources = Section::new("Capture sources", limits);
        sources.extend(found);

        let mut found: Vec<Finding> = Vec::new();
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
                if hit.kind != SinkKind::File {
                    evidence.extend(endpoints.iter().cloned());
                }
                let name = self.function_name(function);
                let observation = match hit.kind {
                    SinkKind::Network => format!("`{name}` can send over the network: {}", hit.what),
                    SinkKind::Socket => format!("`{name}` can send through a socket (network or local): {}", hit.what),
                    SinkKind::File => format!("`{name}` can write a file: {}", hit.what),
                };
                let confidence = match (hit.kind, hit.level) {
                    (SinkKind::Network, _) => Confidence::High,
                    (SinkKind::Socket, _) | (SinkKind::File, Level::Argument) => Confidence::Medium,
                    (SinkKind::File, _) => Confidence::Low,
                };
                found.push(Finding::new("list_imports", confidence, observation).at(hit.address).evidence(evidence));
            }
        }
        found.sort_by_key(|finding| std::cmp::Reverse(finding.confidence));
        let mut sinks = Section::new("Send and write sinks", limits);
        sinks.extend(found);

        let mut paths = Section::new("Capture-to-send paths", limits);
        let mut triggers = Section::new("Capture triggers", limits);
        let mut unprompted = 0;
        let mut ranked_paths: Vec<(u64, u64)> = Vec::new();
        if let Some(graph) = &graph {
            let cones = survey.cones(graph);
            let (matches, cut, timed_out) = survey.paths(&cones, &roots);
            paths.total = matches.len();
            for found in matches.iter().take(limits.per_section) {
                paths.findings.push(survey.path_finding(&cones, found));
                ranked_paths.push((found.source, found.sink));
            }
            paths.truncated = paths.total > paths.findings.len();
            if cut {
                report.limitation(format!(
                    "The path search was bounded ({MAX_SOURCE_FUNCTIONS} source and {MAX_SINK_FUNCTIONS} sink \
                     functions, {MAX_DEPTH} call levels, {MAX_VISITED} functions per walk) and hit a bound; more \
                     distant paths are not listed."
                ));
            }
            if timed_out {
                report.limitation(format!(
                    "The path search stopped after {} seconds; pairs it did not reach are not listed.",
                    PATH_BUDGET.as_secs()
                ));
            }
            let (mut found, quiet, cut) = survey.triggers(graph, &cones, &roots);
            // no_user_trigger findings first, so a cut section keeps them.
            found.sort_by_key(|finding| {
                (!finding.observation.starts_with("no_user_trigger:"), std::cmp::Reverse(finding.confidence))
            });
            triggers.extend(found);
            unprompted = quiet;
            if cut {
                report.limitation(format!(
                    "The trigger search walks at most {MAX_DEPTH} call levels and {MAX_VISITED} functions up from \
                     each capture and hit that bound for some; their triggers may be incomplete and they are not \
                     said to lack a user-facing trigger."
                ));
            }
            if graph.pointer_scan_cut {
                report.limitation(format!(
                    "Only the first {} MiB of data were scanned for pointers to functions, so no capture is said to \
                     lack a user-facing trigger.",
                    MAX_POINTER_SCAN >> 20
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
        let senders = survey.sinks.values().filter(|hits| hits.iter().any(|hit| hit.kind != SinkKind::File)).count();
        let writers = survey.sinks.len() - senders;
        report.summary.push(if survey.sources.is_empty() && unreferenced.total == 0 {
            "No microphone, camera, screen or input-device capture was observed.".to_owned()
        } else {
            format!(
                "{} capture sources in {} functions ({}); {} functions can send over the network or a socket and {} \
                 more can write files; {} capture-to-send paths; {} captures are reached from program start with no \
                 user-facing trigger found among their callers.",
                sources.total,
                survey.sources.len(),
                if counts.is_empty() { "strings only".to_owned() } else { counts.join(", ") },
                senders,
                writers,
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
             a loop, receives from the network, or reads user input. no_user_trigger is stated only for \
             direction-specific capture evidence, when no caller within the bounds (or a function such a caller \
             calls directly) reads input or runs a UI loop, and none of them is referenced from data; it means none \
             was found, not that none exists.",
        );
        report.limitation(
            "V4L2 is also used for video output, decoders and HDMI input, framebuffer and DRM queries for drawing, \
             and device nodes and sound-card listings in either direction: such sources are marked ambiguous, rank \
             lower, and never support no_user_trigger.",
        );
        if survey.unread_calls > 0 {
            report.limitation(format!(
                "Constant arguments are read only on x86-64, AArch64 and 32-bit ARM. On {:?} sources are listed at \
                 `name` level without their direction, and ioctl-based sources (V4L2, framebuffer, DRM, evdev) are \
                 missing entirely.",
                survey.arch
            ));
        }
        Ok((report, reach))
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
                let value = read_word(chunk, binary.big_endian);
                if value != 0 && value != u64::MAX && binary.is_code(value) {
                    roots.entry(value).or_insert(Root::Constructor);
                }
            }
        }
        roots
    }
}

/// A pointer-sized word.
fn read_word(chunk: &[u8], big_endian: bool) -> u64 {
    let width = chunk.len();
    let mut value = 0u64;
    for (index, &byte) in chunk.iter().enumerate() {
        let shift = if big_endian { (width - 1 - index) * 8 } else { index * 8 };
        value |= u64::from(byte) << shift;
    }
    value
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

/// The call graph of `program`: callers by call, tail jump, and code taking a function's address; and the
/// functions whose address is stored outside code (references from data, and pointer-sized words in non-code
/// segments).
fn graph(project: &Project, program: &Program, containing: impl Fn(u64) -> Option<u64>) -> Graph {
    let mut graph = Graph::default();
    for xref in &program.xrefs {
        let Some(from) = containing(xref.from) else {
            if program.function_at(xref.to).is_some() {
                graph.data_referenced.insert(xref.to);
            }
            continue;
        };
        if xref.kind == XrefKind::Jump && xref.to <= xref.from && containing(xref.to) == Some(from) {
            graph.loops.insert(from);
            continue;
        }
        if from == xref.to || program.function_at(xref.to).is_none() {
            continue;
        }
        let edge = if xref.kind == XrefKind::Data { Edge::Callback } else { Edge::Call };
        graph.add(from, xref.to, edge);
    }
    let binary = &project.binary;
    let width = usize::from(binary.arch.pointer_size().unwrap_or(8));
    let thumb = binary.arch == Arch::Arm;
    let mut budget = MAX_POINTER_SCAN;
    for segment in &binary.segments {
        if segment.perms.execute || !segment.perms.read || segment.file_size == 0 {
            continue;
        }
        let length = segment.file_size.min(segment.size);
        let Some(bytes) = binary.read(segment.address, length) else { continue };
        if bytes.len() > budget {
            graph.pointer_scan_cut = true;
            break;
        }
        budget -= bytes.len();
        let skip = (width - (segment.address as usize % width)) % width;
        for chunk in bytes.get(skip..).unwrap_or_default().chunks_exact(width) {
            let value = read_word(chunk, binary.big_endian);
            let target = if thumb { value & !1 } else { value };
            if target != 0 && program.function_at(target).is_some() {
                graph.data_referenced.insert(target);
            }
        }
    }
    graph
}

impl Survey<'_> {
    fn name(&self, function: u64) -> String {
        self.project.function_name(function)
    }

    /// The sinks and sources each export in `exports` reaches through direct calls, within the walk's bounds.
    fn reach(&self, graph: &Graph, exports: &[String]) -> BTreeMap<String, JniReach> {
        let mut found = BTreeMap::new();
        let by_name: HashMap<&str, &rampage_loaders::Export> =
            self.project.binary.exports.iter().map(|export| (export.name.as_str(), export)).collect();
        for name in exports {
            let Some(export) = by_name.get(name.as_str()) else { continue };
            let mut reached = BTreeMap::from([(export.address, 0usize)]);
            let mut queue = VecDeque::from([export.address]);
            let mut entry = JniReach::default();
            while let Some(function) = queue.pop_front() {
                let depth = reached[&function];
                for hit in self.sinks.get(&function).into_iter().flatten() {
                    entry.sinks.push((self.name(function), hit.what.clone(), hit.kind.target(), depth));
                }
                for hit in self.sources.get(&function).into_iter().flatten().filter(|hit| hit.medium != Medium::Input) {
                    let specific = hit.specific && hit.level >= Level::Name;
                    entry.sources.push((self.name(function), hit.what.clone(), hit.medium.label(), depth, specific));
                }
                if depth == MAX_DEPTH {
                    continue;
                }
                for &callee in graph.callees.get(&function).into_iter().flatten() {
                    if reached.len() >= MAX_VISITED {
                        entry.cut = true;
                        break;
                    }
                    if let std::collections::btree_map::Entry::Vacant(slot) = reached.entry(callee) {
                        slot.insert(depth + 1);
                        queue.push_back(callee);
                    }
                }
            }
            entry.function = self.name(export.address);
            entry.address = export.address;
            found.insert(name.clone(), entry);
        }
        found
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
            let mut what = what.to_owned();
            if pattern == "/dev/snd/pcmc" {
                match pcm_node(&lower) {
                    Some(true) => what = "ALSA PCM capture device node".to_owned(),
                    Some(false) => {
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
                    None => what = "ALSA PCM device node (either direction)".to_owned(),
                }
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
                    (Level::String, false),
                    from,
                    format!("string at {:#x} referenced at {from:#x}", found.address),
                );
            }
        }
    }

    fn add_source(
        &mut self,
        function: u64,
        medium: Medium,
        what: String,
        (level, specific): (Level, bool),
        at: u64,
        evidence: String,
    ) {
        let hits = self.sources.entry(function).or_default();
        if let Some(hit) = hits.iter_mut().find(|hit| hit.what == what) {
            hit.level = hit.level.max(level);
            hit.specific |= specific;
            hit.evidence.push(evidence);
        } else {
            hits.push(SourceHit { medium, what, level, specific, evidence: vec![evidence], address: at });
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

    /// Every call to a source, sink, write, trigger or `socket` API, read for its constant arguments where they
    /// matter.
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
            let socket = super::api_matches("socket", &api);
            if source.is_none() && sink.is_none() && marker.is_none() && !write && !socket {
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
                if socket {
                    let domain = if call { self.argument(function, site, 0).map(Held::number) } else { None };
                    self.socket_domains.entry(function).or_default().push(domain);
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

    /// Socket sends in a function whose `socket` calls all name a constant domain: local-only (AF_UNIX) ones are
    /// dropped, and an internet domain makes them network sends.
    fn classify_sockets(&mut self) {
        for (function, domains) in &self.socket_domains {
            let Some(hits) = self.sinks.get_mut(function) else { continue };
            if domains.iter().all(|domain| *domain == Some(AF_UNIX)) {
                hits.retain(|hit| hit.kind != SinkKind::Socket);
            } else if domains.iter().any(|domain| matches!(domain, Some(AF_INET | AF_INET6))) {
                for hit in hits.iter_mut().filter(|hit| hit.kind == SinkKind::Socket) {
                    hit.kind = SinkKind::Network;
                    hit.evidence.push("the same function opens an internet socket (AF_INET or AF_INET6)".to_owned());
                }
            }
        }
        self.sinks.retain(|_, hits| !hits.is_empty());
    }

    fn source_call(&mut self, function: u64, site: u64, call: bool, api: &str, source: SourceApi) {
        let at = format!("call to `{api}` at {site:#x}");
        if let Check::Ioctl { index } = source.check {
            // An ioctl is a source only for a known capture request.
            let request = if call { self.argument(function, site, index).map(Held::number) } else { None };
            let request = request.and_then(|value| ioctl_request(value).map(|request| (value & 0xffff_ffff, request)));
            if let Some((value, (medium, name, note))) = request {
                let what = match note {
                    Some(note) => format!("issues the {name} ioctl ({note})"),
                    None => format!("issues the {name} ioctl"),
                };
                let evidence = format!("{at}: request {value:#x}");
                self.add_source(function, medium, what, (Level::Argument, note.is_none()), site, evidence);
            }
            return;
        }
        let outcome = if call { self.source_outcome(function, site, source) } else { Outcome::Unknown };
        match (outcome, source.check) {
            (Outcome::Confirmed(detail), _) => {
                let what = format!("{} for capture", source.what);
                self.add_source(
                    function,
                    source.medium,
                    what,
                    (Level::Argument, true),
                    site,
                    format!("{at}: {detail}"),
                );
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
                let what = source.what.to_owned();
                self.add_source(function, source.medium, what, (Level::Name, source.specific), site, at);
            }
            (Outcome::Unknown, _) => {
                self.add_source(
                    function,
                    source.medium,
                    format!("{} (direction not read)", source.what),
                    (Level::Name, false),
                    site,
                    format!("{at}: the argument that selects capture was not set by a constant just before the call"),
                );
            }
        }
    }

    fn source_outcome(&mut self, function: u64, site: u64, source: SourceApi) -> Outcome {
        match source.check {
            Check::Name | Check::Ioctl { .. } => Outcome::Unknown,
            // A flag word can equal an address in the image (PCM_IN is 0x10000000): read it as a number.
            Check::Equals { index, argument, capture, other } => {
                match self.argument(function, site, index).map(Held::number) {
                    Some(value) if value == capture.0 => {
                        Outcome::Confirmed(format!("{argument} = {value} ({})", capture.1))
                    }
                    Some(value) if value == other.0 => Outcome::Excluded(format!("{argument} = {value} ({})", other.1)),
                    _ => Outcome::Unknown,
                }
            }
            Check::Flag { index, argument, bit, flag } => {
                match self.argument(function, site, index).map(Held::number) {
                    Some(value) if value & bit != 0 => {
                        Outcome::Confirmed(format!("{argument} = {value:#x} (sets {flag})"))
                    }
                    Some(value) => Outcome::Excluded(format!("{argument} = {value:#x} (without {flag})")),
                    None => Outcome::Unknown,
                }
            }
            Check::NonZero { index, argument } => match self.argument(function, site, index).map(Held::number) {
                Some(0) => Outcome::Excluded(format!("{argument} = 0 (no input)")),
                Some(value) => Outcome::Confirmed(format!("{argument} = {value:#x}")),
                None => Outcome::Unknown,
            },
        }
    }

    fn sink_call(&mut self, function: u64, site: u64, call: bool, api: &str, sink: SinkApi) {
        let at = format!("call to `{api}` at {site:#x}");
        let string = |survey: &mut Self, index: usize| match survey.argument(function, site, index) {
            Some(Held::Address(address)) => survey.string_at(address),
            _ => None,
        };
        let device = |path: &Option<String>| {
            path.as_deref().is_some_and(|path| DEVICE_PREFIXES.iter().any(|prefix| path.starts_with(prefix)))
        };
        match (sink.check, call) {
            (SinkCheck::Name, _) | (_, false) => {
                self.add_sink(function, sink.kind, format!("`{api}` ({})", sink.what), Level::Name, site, at);
            }
            (SinkCheck::Mode { index }, true) => {
                let path = string(self, 0);
                if device(&path) {
                    return;
                }
                match string(self, index) {
                    Some(mode) if mode.starts_with('r') && !mode.contains('+') => {}
                    Some(mode) => {
                        let path = path.map(|path| format!(" {}", quote(&path))).unwrap_or_default();
                        self.add_sink(
                            function,
                            sink.kind,
                            format!("`{api}`{path} for writing"),
                            Level::Argument,
                            site,
                            format!("{at}: mode {}", quote(&mode)),
                        );
                    }
                    None => {
                        self.add_sink(function, sink.kind, format!("`{api}` (mode not read)"), Level::Name, site, at)
                    }
                }
            }
            (SinkCheck::Flags { path, flags }, true) => {
                let path = string(self, path);
                if device(&path) {
                    return;
                }
                match self.argument(function, site, flags).map(Held::number) {
                    Some(value) if value & 3 == 0 => {}
                    Some(value) => {
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
                    None => {
                        self.add_sink(function, sink.kind, format!("`{api}` (flags not read)"), Level::Name, site, at)
                    }
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
        let Some(register) = argument_registers(self.arch).and_then(|registers| registers.get(index).copied()) else {
            self.unread_calls += 1;
            return None;
        };
        let project = self.project;
        let blocks = self
            .listings
            .entry(function)
            .or_insert_with(|| project.function_listing_for_frame(function).ok().map(|listing| listing.blocks))
            .as_ref()?;
        let block = blocks.iter().find(|block| block.iter().any(|line| line.address == site))?;
        let position = block.iter().position(|line| line.address == site)?;
        let start = position.saturating_sub(ARGUMENT_WINDOW);
        let lines: Vec<Instruction> = block[start..position]
            .iter()
            .map(|line| Instruction {
                text: &line.text,
                data_ref: line.data_ref,
                accesses: line.accesses,
                call: matches!(line.flow, Flow::Call(_) | Flow::IndirectCall),
            })
            .collect();
        let binary = &project.binary;
        track(self.arch, register, &lines, &|address, width| binary.read_constant(address, width))
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

    /// The source functions paths and triggers consider (capped), and the sink functions paths consider.
    fn source_functions(&self) -> Vec<u64> {
        self.sources.keys().copied().take(MAX_SOURCE_FUNCTIONS).collect()
    }

    fn sink_functions(&self) -> Vec<u64> {
        self.sinks.keys().copied().take(MAX_SINK_FUNCTIONS).collect()
    }

    /// One backward walk per source and sink function, shared by paths and triggers.
    fn cones(&self, graph: &Graph) -> BTreeMap<u64, Cone> {
        let mut cones = BTreeMap::new();
        for function in self.source_functions().into_iter().chain(self.sink_functions()) {
            cones.entry(function).or_insert_with(|| graph.cone(function));
        }
        cones
    }

    /// Whether `function` holds capture evidence that shows direction (an argument that selects capture, or a
    /// capture-only API), for a medium other than input.
    fn specific_capture(&self, function: u64) -> bool {
        self.sources.get(&function).is_some_and(|hits| {
            hits.iter().any(|hit| hit.specific && hit.level >= Level::Name && hit.medium != Medium::Input)
        })
    }

    /// Capture-to-send pairs, best first; whether a bound was hit; and whether the time budget ran out.
    fn paths(&self, cones: &BTreeMap<u64, Cone>, roots: &BTreeMap<u64, Root>) -> (Vec<PathMatch>, bool, bool) {
        let deadline = Instant::now() + PATH_BUDGET;
        let mut cut = self.sources.len() > MAX_SOURCE_FUNCTIONS || self.sinks.len() > MAX_SINK_FUNCTIONS;
        let mut timed_out = false;
        let sources: Vec<u64> = self
            .source_functions()
            .into_iter()
            .filter(|function| self.sources[function].iter().any(|hit| hit.medium != Medium::Input))
            .collect();
        let sinks = self.sink_functions();
        let mut found: Vec<PathMatch> = Vec::new();
        for &source in &sources {
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            let source_cone = &cones[&source];
            let specific = self.specific_capture(source);
            // Shared callers within reach, other than main and the entry point (which everything shares).
            let near: Vec<(u64, usize)> = source_cone
                .reached
                .iter()
                .filter(|&(_, &(up, _))| up <= MAX_SHARED_LEVELS)
                .filter(|(function, _)| {
                    !roots.get(function).is_some_and(|root| matches!(root, Root::Entry | Root::Main))
                })
                .map(|(&function, &(up, _))| (function, up))
                .collect();
            for &sink in &sinks {
                let sink_cone = &cones[&sink];
                cut |= source_cone.cut || sink_cone.cut;
                let kind = self.sinks[&sink].iter().map(|hit| hit.kind).min().unwrap_or(SinkKind::File);
                let relation = if source == sink {
                    Relation::Same
                } else if let Some(depth) = sink_cone.depth(source) {
                    Relation::SourceCalls(depth)
                } else if let Some(depth) = source_cone.depth(sink) {
                    Relation::SinkCalls(depth)
                } else {
                    let shared = near
                        .iter()
                        .filter_map(|&(function, up)| sink_cone.depth(function).map(|down| (up + down, function)))
                        .filter(|&(levels, _)| levels <= MAX_SHARED_LEVELS)
                        .min();
                    let Some((levels, ancestor)) = shared else { continue };
                    Relation::Shared { ancestor, levels }
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
                if kind != SinkKind::Network {
                    confidence = lower(confidence);
                }
                if !specific {
                    confidence = lower(confidence);
                }
                let score = rank * 2 + kind.weight() + usize::from(!specific);
                found.push(PathMatch { score, confidence, source, sink, kind, relation });
            }
        }
        found.sort_by(|a, b| a.score.cmp(&b.score).then(b.confidence.cmp(&a.confidence)));
        (found, cut, timed_out)
    }

    /// The finding for one capture-to-sink pair.
    fn path_finding(&self, cones: &BTreeMap<u64, Cone>, found: &PathMatch) -> Finding {
        let (source, sink) = (found.source, found.sink);
        let (relation, chain) = match found.relation {
            Relation::Same => ("in the same function".to_owned(), vec![self.name(source)]),
            Relation::SourceCalls(depth) => {
                let how = if depth == 1 {
                    "calls the sink directly".to_owned()
                } else {
                    format!("reaches the sink {depth} calls down")
                };
                (format!("the capturing function {how}"), self.render(&cones[&sink].chain(source)))
            }
            Relation::SinkCalls(depth) => {
                let how = if depth == 1 {
                    "calls the capture directly".to_owned()
                } else {
                    format!("reaches the capture {depth} calls down")
                };
                (format!("the sending function {how}"), self.render(&cones[&source].chain(sink)))
            }
            Relation::Shared { ancestor, levels } => {
                let mut chain = self.render(&cones[&source].chain(ancestor));
                chain.push(format!("and {}", self.render(&cones[&sink].chain(ancestor)).join(" -> ")));
                (format!("both are reached from `{}` ({levels} calls in all)", self.name(ancestor)), chain)
            }
        };
        let level = self.sources[&source].iter().map(|hit| hit.level).max().unwrap_or(Level::String);
        let mediums: BTreeSet<&str> = self.sources[&source].iter().map(|hit| hit.medium.label()).collect();
        let sink_what: Vec<&str> = self.sinks[&sink].iter().map(|hit| hit.what.as_str()).collect();
        let mut evidence = vec![
            format!("chain: {}", chain.join(" -> ")),
            format!("capture: {} (evidence: {})", self.whats(source), level.as_str()),
            format!("sink: {}", sink_what.join(", ")),
        ];
        if !self.specific_capture(source) {
            evidence.push("the capture evidence does not show direction: ranked lower".to_owned());
        }
        let functions: BTreeSet<u64> = [source, sink].into();
        if let Some(global) = self.shared_global(&self.globals(&functions), source, sink) {
            evidence.push(global);
        }
        Finding::new(
            "xrefs",
            found.confidence,
            format!(
                "{} capture in `{}` and a send to {} in `{}`: {relation}",
                mediums.into_iter().collect::<Vec<_>>().join("/"),
                self.name(source),
                found.kind.target(),
                self.name(sink)
            ),
        )
        .at(source)
        .evidence(evidence)
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
    fn triggers(
        &self,
        graph: &Graph,
        cones: &BTreeMap<u64, Cone>,
        roots: &BTreeMap<u64, Root>,
    ) -> (Vec<Finding>, usize, bool) {
        let mut findings = Vec::new();
        let mut unprompted = 0;
        let mut cut_any = false;
        for source in self.source_functions() {
            let hits = &self.sources[&source];
            let cone = &cones[&source];
            let mediums: BTreeSet<Medium> = hits.iter().map(|hit| hit.medium).collect();
            let input_only = mediums.iter().all(|medium| *medium == Medium::Input);
            let label = mediums.iter().map(|medium| medium.label()).collect::<Vec<_>>().join("/");
            cut_any |= cone.cut;
            let mut by_depth: Vec<(usize, u64)> =
                cone.reached.iter().map(|(&function, &(depth, _))| (depth, function)).collect();
            by_depth.sort_unstable();
            let mut start: Option<(u64, Root)> = None;
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut user_input = false;
            let mut indirect: Option<u64> = None;
            let name = self.name(source);
            for &(_, function) in &by_depth {
                if let Some(&root) = roots.get(&function) {
                    if start.is_none_or(|(_, found)| !found.at_start() && root.at_start()) {
                        start = Some((function, root));
                    }
                } else if indirect.is_none() && graph.data_referenced.contains(&function) {
                    indirect = Some(function);
                }
                // A function calling a user-input reader directly may start the capture only after input, even
                // when the reader is not on the chain (`if (button_pressed()) record();`).
                let sibling = graph.callees.get(&function).filter(|_| !input_only).and_then(|callees| {
                    callees.iter().copied().find(|&callee| {
                        !cone.reached.contains_key(&callee)
                            && self.markers.get(&callee).is_some_and(|markers| markers.contains_key(&Marker::UserInput))
                    })
                });
                if let Some(reader) = sibling {
                    user_input = true;
                    if seen.insert("user input") {
                        let rendered = self.render(&cone.chain(function)).join(" -> ");
                        findings.push(
                            Finding::new(
                                "xrefs",
                                Confidence::Low,
                                format!("{label} capture in `{name}` may follow user input"),
                            )
                            .at(source)
                            .evidence([
                                "trigger: user input".to_owned(),
                                format!(
                                    "`{}` also calls `{}`, which reads user input",
                                    self.name(function),
                                    self.name(reader)
                                ),
                                format!("chain: {rendered}"),
                            ]),
                        );
                    }
                }
                let Some(markers) = self.markers.get(&function) else { continue };
                for (&marker, api) in markers {
                    // An input reader is not its own user trigger; a capture beside it in the same function is.
                    if marker == Marker::UserInput && function == source && input_only {
                        continue;
                    }
                    let chain = cone.chain(function);
                    let edge = chain.first().and_then(|(_, edge)| *edge);
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
                    let rendered = self.render(&chain).join(" -> ");
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
                let withheld = if !root.at_start() || input_only || user_input {
                    None
                } else if cone.cut {
                    Some("the walk up its callers hit its bound".to_owned())
                } else if graph.pointer_scan_cut {
                    Some("the scan for function pointers in data was cut".to_owned())
                } else if let Some(table) = indirect {
                    Some(format!(
                        "`{}` is referenced from data (a table of handlers or operations), and callers through it \
                         were not followed",
                        self.name(table)
                    ))
                } else if !self.specific_capture(source) {
                    Some("the capture evidence does not show direction".to_owned())
                } else {
                    None
                };
                let mut evidence = vec![format!("trigger: {kind}"), format!("chain: {rendered}")];
                if let Some(reason) = &withheld {
                    evidence.push(format!("no_user_trigger not stated: {reason}"));
                }
                findings.push(
                    Finding::new(
                        "xrefs",
                        Confidence::Medium,
                        format!("{label} capture in `{name}` is reached from {}", root.label()),
                    )
                    .at(source)
                    .evidence(evidence),
                );
                if root.at_start() && !input_only && !user_input && withheld.is_none() {
                    unprompted += 1;
                    findings.push(
                        Finding::new(
                            "xrefs",
                            Confidence::Medium,
                            format!(
                                "no_user_trigger: {label} capture in `{name}` is reached from {} with no input-event \
                                 or UI handling found among its callers within {MAX_DEPTH} levels",
                                root.label()
                            ),
                        )
                        .at(source)
                        .evidence([
                            format!("chain: {rendered}"),
                            format!(
                                "{} functions within {MAX_DEPTH} call levels above it; none reads an input device, \
                                 runs a UI event loop or calls a function that does, and none is referenced from data",
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

/// The argument position a register name carries, if it is an argument register. Register-list braces and
/// writeback marks (`{r1`, `r2}`, `sp!`) are ignored.
fn register_index(arch: Arch, register: &str) -> Option<usize> {
    let register = register.trim_matches(|c| c == '{' || c == '}' || c == '!' || c == ' ');
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
fn split(text: &str) -> (String, Vec<String>) {
    let text = text.trim().to_ascii_lowercase();
    let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap_or((&text, ""));
    let operands =
        rest.split(',').map(|operand| operand.trim().to_owned()).filter(|operand| !operand.is_empty()).collect();
    (mnemonic.to_owned(), operands)
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

/// Mnemonics that write registers named after the first operand too (pair and multiple loads, exchanges).
fn writes_every_operand(mnemonic: &str) -> bool {
    mnemonic.starts_with("ldp")
        || mnemonic.starts_with("ldnp")
        || mnemonic.starts_with("ldxp")
        || mnemonic.starts_with("ldaxp")
        || mnemonic.starts_with("ldm")
        || mnemonic.starts_with("ldrd")
        || mnemonic.starts_with("pop")
        || mnemonic.starts_with("xchg")
        || mnemonic.starts_with("xadd")
        || mnemonic.starts_with("cmpxchg")
}

/// The argument positions an x86-64 instruction writes without naming them.
fn implicit_writes(arch: Arch, mnemonic: &str, operands: &[String]) -> &'static [usize] {
    if arch != Arch::X86_64 {
        return &[];
    }
    match mnemonic {
        "cwd" | "cdq" | "cqo" | "mul" | "div" | "idiv" | "rdtsc" => &[2],
        "imul" if operands.len() == 1 => &[2],
        "rdtscp" | "cpuid" => &[2, 3],
        "syscall" => &[3],
        _ if mnemonic.starts_with("rep")
            || ["movs", "stos", "cmps", "scas", "lods"].iter().any(|prefix| mnemonic.starts_with(prefix)) =>
        {
            &[0, 1, 3]
        }
        _ => &[],
    }
}

/// The value argument register `register` holds after `lines` (the instructions before a call in its block).
fn track(arch: Arch, register: usize, lines: &[Instruction], read: &dyn Fn(u64, u8) -> Option<u64>) -> Option<Held> {
    let mut value: Option<Held> = None;
    for line in lines {
        if line.call {
            value = None;
            continue;
        }
        let (mnemonic, operands) = split(line.text);
        if implicit_writes(arch, &mnemonic, &operands).contains(&register) {
            value = None;
            continue;
        }
        let names = |operand: &String| register_index(arch, operand) == Some(register);
        if operands.first().is_some_and(names) && writes_first_operand(&mnemonic) {
            value = written_value(&mnemonic, &operands, line, value, read);
        } else if writes_every_operand(&mnemonic) && operands.iter().any(names) {
            value = None;
        }
    }
    value
}

/// The value an instruction writing an argument register leaves in it, given the value before (`movk`/`movt`
/// merge into it); `None` when it is not a constant or address.
fn written_value(
    mnemonic: &str,
    operands: &[String],
    line: &Instruction,
    before: Option<Held>,
    read: &dyn Fn(u64, u8) -> Option<u64>,
) -> Option<Held> {
    let source = operands.get(1).map(String::as_str);
    let wide = operands.first().is_some_and(|register| register.starts_with('x') || register.starts_with('r'));
    match mnemonic {
        "xor" | "eor" | "sub" | "eors" | "subs"
            if operands.len() == 2 && source == operands.first().map(String::as_str) =>
        {
            Some(Held::Constant(0))
        }
        "mov" | "movs" | "mov.w" | "movs.w" | "movz" | "movabs" | "movw" => {
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
        "mvn" | "mvns" | "mvn.w" | "movn" => {
            let value = !(number(source?)? << shift(operands));
            let x64 = wide && operands.first().is_some_and(|register| register.starts_with('x'));
            Some(Held::Constant(if x64 { value } else { value & 0xffff_ffff }))
        }
        "orr" if operands.len() == 3 && matches!(operands[1].as_str(), "wzr" | "xzr") => {
            number(&operands[2]).map(Held::Constant)
        }
        "movk" => {
            let previous = before?.number();
            let amount = shift(operands);
            let value = number(source?)?;
            Some(Held::Constant((previous & !(0xffff << amount)) | (value << amount)))
        }
        "movt" | "movt.w" => {
            let previous = before?.number();
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
            read(address, width).map(Held::Constant)
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

    fn instruction(text: &str) -> Instruction<'_> {
        Instruction { text, data_ref: None, accesses: false, call: false }
    }

    fn held(arch: Arch, register: usize, texts: &[&str]) -> Option<Held> {
        let lines: Vec<Instruction> = texts.iter().map(|text| instruction(text)).collect();
        track(arch, register, &lines, &|_, _| None)
    }

    #[test]
    fn ioctl_requests_match_any_abi_size() {
        // VIDIOC_DQBUF with a 64-bit (88-byte) and a 32-bit (68-byte) struct v4l2_buffer, MIPS's direction bits,
        // and a code sign-extended into a 64-bit register.
        for code in [0xc058_5611, 0xc044_5611, 0x8058_5611, 0xffff_ffff_c058_5611] {
            assert_eq!(ioctl_request(code), Some((Medium::Camera, "VIDIOC_DQBUF", None)), "{code:#x}");
        }
        assert_eq!(ioctl_request(0x4004_5612), Some((Medium::Camera, "VIDIOC_STREAMON", None)));
        assert_eq!(ioctl_request(0x4004_4590), Some((Medium::Input, "EVIOCGRAB", None)));
        let (medium, name, note) = ioctl_request(0x4600).unwrap();
        assert_eq!((medium, name), (Medium::Screen, "FBIOGET_VSCREENINFO"));
        assert!(note.is_some(), "a framebuffer geometry query is not specific to capture");
        assert!(ioctl_request(0x8068_5600).unwrap().2.is_some(), "VIDIOC_QUERYCAP is ambiguous");
        // A console request (VT_OPENQRY, 0x5600) is a plain 'V' code, not V4L2.
        assert_eq!(ioctl_request(0x5600), None);
        assert_eq!(ioctl_request(0x5401), None);
    }

    #[test]
    fn pcm_nodes_need_an_explicit_direction_letter() {
        assert_eq!(pcm_node("/dev/snd/pcmc0d0c"), Some(true));
        assert_eq!(pcm_node("/dev/snd/pcmc%ud%uc"), Some(true));
        assert_eq!(pcm_node("/dev/snd/pcmc0d0p"), Some(false));
        assert_eq!(pcm_node("/dev/snd/pcmc%ud%u%c"), None);
        assert_eq!(pcm_node("/dev/snd/pcmc0d0"), None);
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
        assert!(!match_api(SOURCE_APIS, "drmModeGetFB").unwrap().specific);
        assert!(match_api(SOURCE_APIS, "snd_pcm_readi").unwrap().specific);
        assert_eq!(match_api(SINK_APIS, "curl_easy_perform").map(|sink| sink.kind), Some(SinkKind::Network));
        assert_eq!(match_api(SINK_APIS, "send").map(|sink| sink.kind), Some(SinkKind::Socket));
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
        assert_eq!(register_index(Arch::Arm, "{r1"), Some(1));
        assert!(!writes_first_operand("str"));
        assert!(!writes_first_operand("cmp"));
        assert!(writes_first_operand("mov"));
    }

    #[test]
    fn constants_are_tracked_across_move_forms() {
        assert_eq!(
            held(Arch::Aarch64, 1, &["mov w1, #0x5612", "movk w1, #0x4004, lsl #16"]),
            Some(Held::Constant(0x4004_5612))
        );
        assert_eq!(held(Arch::Aarch64, 2, &["mov w2, wzr"]), Some(Held::Constant(0)));
        assert_eq!(held(Arch::X86_64, 2, &["xor edx, edx"]), Some(Held::Constant(0)));
        // Thumb: narrow and wide moves, movw/movt pairs and inverted moves.
        assert_eq!(held(Arch::Arm, 2, &["movs r2, #1"]), Some(Held::Constant(1)));
        assert_eq!(held(Arch::Arm, 2, &["mov.w r2, #0x10000000"]), Some(Held::Constant(0x1000_0000)));
        assert_eq!(held(Arch::Arm, 1, &["movw r1, #0x5612", "movt r1, #0x4004"]), Some(Held::Constant(0x4004_5612)));
        assert_eq!(held(Arch::Arm, 0, &["mvn r0, #0"]), Some(Held::Constant(0xffff_ffff)));
    }

    #[test]
    fn writes_beyond_the_first_operand_end_a_constant() {
        // A pair load, a register-list pop and x86 instructions that write rdx or rcx without naming them.
        assert_eq!(held(Arch::Aarch64, 2, &["mov w2, #1", "ldp x1, x2, [sp, #0x10]"]), None);
        assert_eq!(held(Arch::Arm, 2, &["movs r2, #1", "pop {r1, r2}"]), None);
        assert_eq!(held(Arch::X86_64, 2, &["mov edx, 1", "cqo"]), None);
        assert_eq!(held(Arch::X86_64, 3, &["mov ecx, 8", "rep stosq"]), None);
        assert_eq!(held(Arch::X86_64, 2, &["mov edx, 1", "xchg rdx, rax"]), None);
        // Reading the register leaves it as it was.
        assert_eq!(held(Arch::X86_64, 2, &["mov edx, 1", "mov eax, edx"]), Some(Held::Constant(1)));
    }

    #[test]
    fn a_walk_past_the_depth_bound_is_cut() {
        let mut graph = Graph::default();
        for level in 0..MAX_DEPTH as u64 + 2 {
            graph.add(level + 1, level, Edge::Call);
        }
        let cone = graph.cone(0);
        assert!(cone.cut);
        assert_eq!(cone.reached.len(), MAX_DEPTH + 1);
        let mut graph = Graph::default();
        for level in 0..MAX_DEPTH as u64 {
            graph.add(level + 1, level, Edge::Call);
        }
        assert!(!graph.cone(0).cut);
    }
}

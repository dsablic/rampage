//! Whole-file code facts for the reports: which methods load each string, which methods each method invokes, the
//! Android capture and personal-data APIs invoked, and which methods are reachable from a set of entry methods.
//! Methods are keyed by their smali text, so calls across the DEX files of one APK connect.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::Serialize;

use crate::dex::Dex;
use crate::insn::{RefKind, references};

/// Methods kept per string, callees per method, call sites kept per capture API.
const MAX_USERS: usize = 8;
const MAX_CALLEES: usize = 4096;
const MAX_CALLERS: usize = 16;

/// The code facts of one DEX file.
#[derive(Debug, Default)]
pub struct CodeIndex {
    /// String index to the defined methods (smali text) whose code loads it, the first [`MAX_USERS`].
    pub string_users: HashMap<u32, Vec<String>>,
    /// Method (smali text) to the methods it invokes (smali text), deduplicated.
    pub calls: BTreeMap<String, BTreeSet<String>>,
    /// Defined class descriptor to its methods (smali text).
    pub class_methods: BTreeMap<String, Vec<String>>,
}

/// Indexes the code of every defined method of `dex`, within its member budget.
pub fn index(dex: &Dex) -> CodeIndex {
    let mut out = CodeIndex::default();
    let mut budget = dex.limits.max_members;
    let mut callee_text: HashMap<u32, String> = HashMap::new();
    for class_index in 0..dex.class_count() {
        let Ok(class) = dex.class_def(class_index) else { continue };
        let Ok(data) = dex.class_data(&class, &mut budget) else { continue };
        let class_name = dex.type_text(class.class_idx);
        for method in data.methods() {
            let caller = dex.method_text(method.method_idx);
            out.class_methods.entry(class_name.clone()).or_default().push(caller.clone());
            if method.code_off == 0 {
                continue;
            }
            let Ok(code) = dex.code_item(method.code_off) else { continue };
            let mut callees = BTreeSet::new();
            references(&code.insns, |kind, index, _| match kind {
                RefKind::String => {
                    let users = out.string_users.entry(index).or_default();
                    if users.len() < MAX_USERS && !users.contains(&caller) {
                        users.push(caller.clone());
                    }
                }
                RefKind::Method if callees.len() < MAX_CALLEES => {
                    let text = callee_text.entry(index).or_insert_with(|| dex.method_text(index)).clone();
                    callees.insert(text);
                }
                _ => {}
            });
            out.calls.entry(caller).or_default().extend(callees);
        }
    }
    out
}

/// What a capture or personal-data API reaches.
struct CaptureApi {
    class: &'static str,
    /// Method names that count; empty for any method of the class.
    methods: &'static [&'static str],
    medium: &'static str,
    /// The permissions that guard it; empty when the platform asks the user instead (screen capture).
    permissions: &'static [&'static str],
}

const fn api(
    class: &'static str,
    methods: &'static [&'static str],
    medium: &'static str,
    permissions: &'static [&'static str],
) -> CaptureApi {
    CaptureApi { class, methods, medium, permissions }
}

const MIC: &[&str] = &["android.permission.RECORD_AUDIO"];
const CAM: &[&str] = &["android.permission.CAMERA"];
const LOC: &[&str] = &["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"];
const PHONE: &[&str] = &["android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"];

/// Android framework APIs that capture audio, video, the screen or location, or read device identifiers.
const CAPTURE_APIS: &[CaptureApi] = &[
    api("Landroid/media/AudioRecord;", &["<init>", "startRecording", "read"], "microphone", MIC),
    api("Landroid/media/AudioRecord$Builder;", &["build"], "microphone", MIC),
    api("Landroid/media/MediaRecorder;", &["setAudioSource"], "microphone", MIC),
    api("Landroid/media/MediaRecorder;", &["setVideoSource"], "camera", CAM),
    api("Landroid/speech/SpeechRecognizer;", &["createSpeechRecognizer", "startListening"], "microphone", MIC),
    api("Landroid/service/voice/AlwaysOnHotwordDetector;", &[], "microphone", MIC),
    api("Landroid/media/AudioPlaybackCaptureConfiguration$Builder;", &["build"], "microphone", MIC),
    api("Landroid/hardware/Camera;", &["open", "takePicture", "startPreview"], "camera", CAM),
    api("Landroid/hardware/camera2/CameraManager;", &["openCamera"], "camera", CAM),
    api("Landroid/hardware/camera2/CameraDevice;", &["createCaptureSession", "createCaptureRequest"], "camera", CAM),
    api(
        "Landroid/media/projection/MediaProjectionManager;",
        &["createScreenCaptureIntent", "getMediaProjection"],
        "screen",
        &[],
    ),
    api("Landroid/media/projection/MediaProjection;", &["createVirtualDisplay"], "screen", &[]),
    api("Landroid/view/PixelCopy;", &["request"], "screen", &[]),
    api(
        "Landroid/accessibilityservice/AccessibilityService;",
        &["takeScreenshot", "getRootInActiveWindow"],
        "screen",
        &[],
    ),
    api("Landroid/view/accessibility/AccessibilityNodeInfo;", &["getText"], "screen", &[]),
    api(
        "Landroid/location/LocationManager;",
        &["requestLocationUpdates", "getLastKnownLocation", "getCurrentLocation"],
        "location",
        LOC,
    ),
    api("Landroid/net/wifi/WifiManager;", &["getScanResults", "startScan"], "location", LOC),
    api(
        "Landroid/telephony/TelephonyManager;",
        &["getDeviceId", "getImei", "getMeid", "getSubscriberId", "getLine1Number", "getSimSerialNumber"],
        "identifiers",
        PHONE,
    ),
    api("Landroid/os/Build;", &["getSerial"], "identifiers", PHONE),
];

/// One capture API invoked from the app's code.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureUse {
    pub api: String,
    pub medium: &'static str,
    /// The first callers (smali text).
    pub callers: Vec<String>,
    pub callers_total: usize,
    /// The permissions that guard it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<&'static str>,
}

/// Every capture API that some method in `calls` invokes, by API.
pub fn capture_uses(calls: &BTreeMap<String, BTreeSet<String>>) -> Vec<CaptureUse> {
    let mut found: BTreeMap<String, CaptureUse> = BTreeMap::new();
    for (caller, callees) in calls {
        for callee in callees {
            let Some((class, rest)) = callee.split_once("->") else { continue };
            let name = rest.split('(').next().unwrap_or(rest);
            let Some(api) = CAPTURE_APIS
                .iter()
                .find(|api| api.class == class && (api.methods.is_empty() || api.methods.contains(&name)))
            else {
                continue;
            };
            let entry = found.entry(callee.clone()).or_insert_with(|| CaptureUse {
                api: callee.clone(),
                medium: api.medium,
                callers: Vec::new(),
                callers_total: 0,
                permissions: api.permissions.to_vec(),
            });
            entry.callers_total += 1;
            if entry.callers.len() < MAX_CALLERS {
                entry.callers.push(caller.clone());
            }
        }
    }
    found.into_values().collect()
}

/// The methods reachable from `entries` through `calls`, each with the entry it was first reached from; at most
/// `max` methods are visited.
pub fn reachable(
    calls: &BTreeMap<String, BTreeSet<String>>,
    entries: &[String],
    max: usize,
) -> HashMap<String, String> {
    let mut reached: HashMap<String, String> = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for entry in entries {
        if reached.insert(entry.clone(), entry.clone()).is_none() {
            queue.push_back(entry.clone());
        }
    }
    while let Some(method) = queue.pop_front() {
        if reached.len() >= max {
            break;
        }
        let origin = reached[&method].clone();
        for callee in calls.get(&method).into_iter().flatten() {
            if !reached.contains_key(callee) {
                reached.insert(callee.clone(), origin.clone());
                queue.push_back(callee.clone());
            }
        }
    }
    reached
}

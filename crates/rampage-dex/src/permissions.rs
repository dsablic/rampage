//! Protection levels of Android platform permissions, and which ones reach personal data or capture hardware.
//!
//! The protection levels are those the Android Open Source Project declares in
//! `frameworks/base/core/res/AndroidManifest.xml` (Apache-2.0; see THIRD-PARTY-NOTICES), as of Android 14. Only the
//! levels are summarised where newer releases add role or internal flags: `signature` (or `signature|privileged`)
//! still means only the platform's own or preinstalled system apps can hold it. The `category` and `privacy`
//! columns are rampage's own classification.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Permission {
    pub name: &'static str,
    /// `dangerous` (a runtime prompt), `normal` (granted at install), `signature`, `signature|privileged`, ...
    pub protection_level: &'static str,
    /// What it reaches: `microphone`, `camera`, `location`, `contacts`, `screen`, `phone`, `sms`, `storage`,
    /// `sensors`, `accounts`, `calendar`, `nearby`, `usage`, `accessibility`, `notifications`, `network`, `boot`,
    /// `system`.
    pub category: &'static str,
    /// Whether it reaches personal data or capture hardware.
    pub privacy: bool,
}

const fn p(name: &'static str, protection_level: &'static str, category: &'static str, privacy: bool) -> Permission {
    Permission { name, protection_level, category, privacy }
}

const D: &str = "dangerous";
const N: &str = "normal";
const S: &str = "signature";
const SP: &str = "signature|privileged";

/// Platform permissions by short name (without `android.permission.`).
pub const PLATFORM: &[Permission] = &[
    p("RECORD_AUDIO", D, "microphone", true),
    p("CAPTURE_AUDIO_OUTPUT", SP, "microphone", true),
    p("CAPTURE_AUDIO_HOTWORD", SP, "microphone", true),
    p("CAPTURE_MEDIA_OUTPUT", SP, "microphone", true),
    p("CAPTURE_VOICE_COMMUNICATION_OUTPUT", SP, "microphone", true),
    p("RECORD_BACKGROUND_AUDIO", S, "microphone", true),
    p("MODIFY_AUDIO_ROUTING", SP, "microphone", true),
    p("FOREGROUND_SERVICE_MICROPHONE", N, "microphone", true),
    p("CAMERA", D, "camera", true),
    p("SYSTEM_CAMERA", SP, "camera", true),
    p("CAMERA_OPEN_CLOSE_LISTENER", S, "camera", false),
    p("FOREGROUND_SERVICE_CAMERA", N, "camera", true),
    p("CAPTURE_VIDEO_OUTPUT", S, "screen", true),
    p("CAPTURE_SECURE_VIDEO_OUTPUT", S, "screen", true),
    p("READ_FRAME_BUFFER", "signature|recents", "screen", true),
    p("MANAGE_MEDIA_PROJECTION", S, "screen", true),
    p("FOREGROUND_SERVICE_MEDIA_PROJECTION", N, "screen", true),
    p("CAPTURE_TV_INPUT", SP, "screen", true),
    p("TV_INPUT_HARDWARE", SP, "screen", true),
    p("ACCESS_FINE_LOCATION", D, "location", true),
    p("ACCESS_COARSE_LOCATION", D, "location", true),
    p("ACCESS_BACKGROUND_LOCATION", D, "location", true),
    p("ACCESS_MEDIA_LOCATION", D, "location", true),
    p("FOREGROUND_SERVICE_LOCATION", N, "location", true),
    p("READ_CONTACTS", D, "contacts", true),
    p("WRITE_CONTACTS", D, "contacts", true),
    p("GET_ACCOUNTS", D, "accounts", true),
    p("READ_CALENDAR", D, "calendar", true),
    p("WRITE_CALENDAR", D, "calendar", true),
    p("READ_PHONE_STATE", D, "phone", true),
    p("READ_PHONE_NUMBERS", D, "phone", true),
    p("READ_PRIVILEGED_PHONE_STATE", SP, "phone", true),
    p("CALL_PHONE", D, "phone", true),
    p("ANSWER_PHONE_CALLS", D, "phone", true),
    p("READ_CALL_LOG", D, "phone", true),
    p("WRITE_CALL_LOG", D, "phone", true),
    p("PROCESS_OUTGOING_CALLS", D, "phone", true),
    p("ADD_VOICEMAIL", D, "phone", true),
    p("USE_SIP", D, "phone", true),
    p("SEND_SMS", D, "sms", true),
    p("RECEIVE_SMS", D, "sms", true),
    p("READ_SMS", D, "sms", true),
    p("RECEIVE_MMS", D, "sms", true),
    p("RECEIVE_WAP_PUSH", D, "sms", true),
    p("READ_EXTERNAL_STORAGE", D, "storage", true),
    p("WRITE_EXTERNAL_STORAGE", D, "storage", true),
    p("READ_MEDIA_IMAGES", D, "storage", true),
    p("READ_MEDIA_VIDEO", D, "storage", true),
    p("READ_MEDIA_AUDIO", D, "storage", true),
    p("READ_MEDIA_VISUAL_USER_SELECTED", D, "storage", true),
    p("MANAGE_EXTERNAL_STORAGE", "signature|appop|preinstalled", "storage", true),
    p("BODY_SENSORS", D, "sensors", true),
    p("BODY_SENSORS_BACKGROUND", D, "sensors", true),
    p("ACTIVITY_RECOGNITION", D, "sensors", true),
    p("HIGH_SAMPLING_RATE_SENSORS", N, "sensors", false),
    p("BLUETOOTH_SCAN", D, "nearby", true),
    p("BLUETOOTH_CONNECT", D, "nearby", true),
    p("BLUETOOTH_ADVERTISE", D, "nearby", true),
    p("NEARBY_WIFI_DEVICES", D, "nearby", true),
    p("UWB_RANGING", D, "nearby", true),
    p("PACKAGE_USAGE_STATS", "signature|privileged|development|appop|retailDemo", "usage", true),
    p("READ_LOGS", "signature|privileged|development", "usage", true),
    p("GET_TASKS", N, "usage", false),
    p("REAL_GET_TASKS", SP, "usage", true),
    p("QUERY_ALL_PACKAGES", N, "usage", false),
    p("BIND_ACCESSIBILITY_SERVICE", S, "accessibility", true),
    p("BIND_NOTIFICATION_LISTENER_SERVICE", S, "notifications", true),
    p("POST_NOTIFICATIONS", D, "notifications", false),
    p("SYSTEM_ALERT_WINDOW", "signature|setup|appop|installer|pre23|development", "screen", false),
    p("INTERNET", N, "network", false),
    p("ACCESS_NETWORK_STATE", N, "network", false),
    p("ACCESS_WIFI_STATE", N, "network", false),
    p("CHANGE_WIFI_STATE", N, "network", false),
    p("CHANGE_NETWORK_STATE", N, "network", false),
    p("BLUETOOTH", N, "nearby", false),
    p("BLUETOOTH_ADMIN", N, "nearby", false),
    p("RECEIVE_BOOT_COMPLETED", N, "boot", false),
    p("FOREGROUND_SERVICE", N, "boot", false),
    p("WAKE_LOCK", N, "boot", false),
    p("BIND_DEVICE_ADMIN", S, "system", false),
    p("WRITE_SECURE_SETTINGS", "signature|privileged|development", "system", false),
    p("WRITE_SETTINGS", "signature|preinstalled|appop|pre23", "system", false),
    p("INSTALL_PACKAGES", SP, "system", false),
    p("REQUEST_INSTALL_PACKAGES", "signature", "system", false),
    p("INTERACT_ACROSS_USERS_FULL", SP, "system", false),
];

/// The platform entry for a permission name (`android.permission.RECORD_AUDIO` or `RECORD_AUDIO`).
pub fn lookup(name: &str) -> Option<&'static Permission> {
    let short = name.strip_prefix("android.permission.")?;
    PLATFORM.iter().find(|permission| permission.name == short)
}

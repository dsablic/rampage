//! Protection levels of Android platform permissions, and which ones reach personal data or capture hardware.
//!
//! The protection levels are those the Android Open Source Project declares in
//! `frameworks/base/core/res/AndroidManifest.xml` (Apache-2.0; see THIRD-PARTY-NOTICES) at the `android14-release`
//! tag, copied as written there, flags included (`dangerous|instant`, `signature|appop`, `internal|role`). The
//! `category` and `privacy` columns are rampage's own classification.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Permission {
    pub name: &'static str,
    /// The AOSP level with its flags: `dangerous` (a runtime prompt), `normal` (granted at install), `signature`
    /// and `internal` (platform or preinstalled apps), plus flags such as `privileged`, `role`, `appop`.
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

/// Platform permissions by short name (without `android.permission.`).
pub const PLATFORM: &[Permission] = &[
    p("RECORD_AUDIO", "dangerous|instant", "microphone", true),
    p("CAPTURE_AUDIO_OUTPUT", "signature|privileged|role", "microphone", true),
    p("CAPTURE_AUDIO_HOTWORD", "signature|privileged|role", "microphone", true),
    p("CAPTURE_MEDIA_OUTPUT", "signature|privileged|role", "microphone", true),
    p("CAPTURE_VOICE_COMMUNICATION_OUTPUT", "signature|privileged|role", "microphone", true),
    p("RECORD_BACKGROUND_AUDIO", "internal|role", "microphone", true),
    p("MODIFY_AUDIO_ROUTING", "signature|privileged|role", "microphone", true),
    p("FOREGROUND_SERVICE_MICROPHONE", "normal|instant", "microphone", true),
    p("CAMERA", "dangerous|instant", "camera", true),
    p("SYSTEM_CAMERA", "system|signature|role", "camera", true),
    p("CAMERA_OPEN_CLOSE_LISTENER", "signature", "camera", false),
    p("FOREGROUND_SERVICE_CAMERA", "normal|instant", "camera", true),
    p("CAPTURE_VIDEO_OUTPUT", "signature", "screen", true),
    p("CAPTURE_SECURE_VIDEO_OUTPUT", "signature", "screen", true),
    p("READ_FRAME_BUFFER", "signature|recents", "screen", true),
    p("MANAGE_MEDIA_PROJECTION", "signature", "screen", true),
    p("FOREGROUND_SERVICE_MEDIA_PROJECTION", "normal|instant", "screen", true),
    p("CAPTURE_TV_INPUT", "signature|privileged", "screen", true),
    p("TV_INPUT_HARDWARE", "signature|privileged|vendorPrivileged", "screen", true),
    p("ACCESS_FINE_LOCATION", "dangerous|instant", "location", true),
    p("ACCESS_COARSE_LOCATION", "dangerous|instant", "location", true),
    p("ACCESS_BACKGROUND_LOCATION", "dangerous|instant", "location", true),
    p("ACCESS_MEDIA_LOCATION", "dangerous", "location", true),
    p("FOREGROUND_SERVICE_LOCATION", "normal|instant", "location", true),
    p("READ_CONTACTS", "dangerous", "contacts", true),
    p("WRITE_CONTACTS", "dangerous", "contacts", true),
    p("GET_ACCOUNTS", "dangerous", "accounts", true),
    p("READ_CALENDAR", "dangerous", "calendar", true),
    p("WRITE_CALENDAR", "dangerous", "calendar", true),
    p("READ_PHONE_STATE", "dangerous", "phone", true),
    p("READ_PHONE_NUMBERS", "dangerous|instant", "phone", true),
    p("READ_PRIVILEGED_PHONE_STATE", "signature|privileged|role", "phone", true),
    p("CALL_PHONE", "dangerous", "phone", true),
    p("ANSWER_PHONE_CALLS", "dangerous|runtime", "phone", true),
    p("READ_CALL_LOG", "dangerous", "phone", true),
    p("WRITE_CALL_LOG", "dangerous", "phone", true),
    p("PROCESS_OUTGOING_CALLS", "dangerous", "phone", true),
    p("USE_SIP", "dangerous", "phone", true),
    p("SEND_SMS", "dangerous", "sms", true),
    p("RECEIVE_SMS", "dangerous", "sms", true),
    p("READ_SMS", "dangerous", "sms", true),
    p("RECEIVE_MMS", "dangerous", "sms", true),
    p("RECEIVE_WAP_PUSH", "dangerous", "sms", true),
    p("READ_EXTERNAL_STORAGE", "dangerous", "storage", true),
    p("WRITE_EXTERNAL_STORAGE", "dangerous", "storage", true),
    p("READ_MEDIA_IMAGES", "dangerous", "storage", true),
    p("READ_MEDIA_VIDEO", "dangerous", "storage", true),
    p("READ_MEDIA_AUDIO", "dangerous", "storage", true),
    p("READ_MEDIA_VISUAL_USER_SELECTED", "dangerous", "storage", true),
    p("MANAGE_EXTERNAL_STORAGE", "signature|appop|preinstalled", "storage", true),
    p("BODY_SENSORS", "dangerous", "sensors", true),
    p("BODY_SENSORS_BACKGROUND", "dangerous", "sensors", true),
    p("ACTIVITY_RECOGNITION", "dangerous|instant", "sensors", true),
    p("HIGH_SAMPLING_RATE_SENSORS", "normal", "sensors", false),
    p("BLUETOOTH_SCAN", "dangerous", "nearby", true),
    p("BLUETOOTH_CONNECT", "dangerous", "nearby", true),
    p("BLUETOOTH_ADVERTISE", "dangerous", "nearby", true),
    p("NEARBY_WIFI_DEVICES", "dangerous", "nearby", true),
    p("UWB_RANGING", "dangerous", "nearby", true),
    p("PACKAGE_USAGE_STATS", "signature|privileged|development|appop|retailDemo", "usage", true),
    p("READ_LOGS", "signature|privileged|development", "usage", true),
    p("GET_TASKS", "normal", "usage", false),
    p("REAL_GET_TASKS", "signature|privileged", "usage", true),
    p("QUERY_ALL_PACKAGES", "normal", "usage", false),
    p("BIND_ACCESSIBILITY_SERVICE", "signature", "accessibility", true),
    p("BIND_NOTIFICATION_LISTENER_SERVICE", "signature", "notifications", true),
    p("POST_NOTIFICATIONS", "dangerous|instant", "notifications", false),
    p("SYSTEM_ALERT_WINDOW", "signature|setup|appop|installer|pre23|development", "screen", false),
    p("INTERNET", "normal|instant", "network", false),
    p("ACCESS_NETWORK_STATE", "normal|instant", "network", false),
    p("ACCESS_WIFI_STATE", "normal", "network", false),
    p("CHANGE_WIFI_STATE", "normal", "network", false),
    p("CHANGE_NETWORK_STATE", "normal", "network", false),
    p("BLUETOOTH", "normal", "nearby", false),
    p("BLUETOOTH_ADMIN", "normal", "nearby", false),
    p("RECEIVE_BOOT_COMPLETED", "normal", "boot", false),
    p("FOREGROUND_SERVICE", "normal|instant", "boot", false),
    p("WAKE_LOCK", "normal|instant", "boot", false),
    p("BIND_DEVICE_ADMIN", "signature|role", "system", false),
    p("WRITE_SECURE_SETTINGS", "signature|privileged|development|role|installer", "system", false),
    p("WRITE_SETTINGS", "signature|preinstalled|appop|pre23|role", "system", false),
    p("INSTALL_PACKAGES", "signature|privileged", "system", false),
    p("REQUEST_INSTALL_PACKAGES", "signature|appop", "system", false),
    p("INTERACT_ACROSS_USERS_FULL", "signature|installer|role", "system", false),
];

/// The base level of a protection level string: `dangerous` for `dangerous|instant`.
pub fn base_level(level: &str) -> &str {
    level.split('|').next().unwrap_or(level)
}

/// The platform entry for a permission name (`android.permission.RECORD_AUDIO` or `RECORD_AUDIO`).
pub fn lookup(name: &str) -> Option<&'static Permission> {
    let short = name.strip_prefix("android.permission.")?;
    PLATFORM.iter().find(|permission| permission.name == short)
}

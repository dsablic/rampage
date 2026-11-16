//! `AndroidManifest.xml` as a model: the package, versions and SDK levels, requested and declared permissions, and
//! the components with their intent filters, exported state and start-at-boot triggers.

use serde::Serialize;

use crate::axml::{Document, Element};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Sdk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// The SDK the APK was compiled against (`compileSdkVersion` or `platformBuildVersionCode`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsesPermission {
    pub name: String,
    /// Requested only up to this SDK level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sdk: Option<i64>,
    /// From `uses-permission-sdk-23`: requested only on SDK 23 and later.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sdk23: bool,
}

/// A permission the package itself defines.
#[derive(Debug, Clone, Serialize)]
pub struct DeclaredPermission {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IntentFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// `data` elements as `scheme://host:port/path` or `mime:type`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "activity" => Self::Activity,
            "activity-alias" => Self::ActivityAlias,
            "service" => Self::Service,
            "receiver" => Self::Receiver,
            "provider" => Self::Provider,
            _ => return None,
        })
    }
}

/// Broadcasts that start a receiver when the device boots.
pub const BOOT_ACTIONS: [&str; 3] = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
];

/// Services the system binds for roles with wide access, by the permission that guards the binding.
const BOUND_ROLES: [(&str, &str); 6] = [
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", "accessibility_service"),
    ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "notification_listener"),
    ("android.permission.BIND_DEVICE_ADMIN", "device_admin"),
    ("android.permission.BIND_INPUT_METHOD", "input_method"),
    ("android.permission.BIND_VOICE_INTERACTION", "voice_interaction"),
    ("android.permission.BIND_VPN_SERVICE", "vpn_service"),
];

#[derive(Debug, Clone, Serialize)]
pub struct Component {
    pub kind: ComponentKind,
    /// The class name, made absolute against the package (`.Foo` becomes `com.example.Foo`).
    pub name: String,
    /// The explicit `exported` value, or the default: exported when it has an intent filter and the target SDK is
    /// below 31 (from 31 an explicit value is required).
    pub exported: bool,
    pub exported_explicit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// Services: `foregroundServiceType` (`microphone`, `camera`, `mediaProjection`, ...), as declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreground_service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorities: Option<String>,
    /// An activity-alias's target activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub intent_filters: Vec<IntentFilter>,
    /// A receiver for a boot broadcast: code that runs when the device starts, with no user action.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub start_at_boot: bool,
    /// A system role the binding permission grants (`accessibility_service`, `notification_listener`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_role: Option<&'static str>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Application {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debuggable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses_cleartext_traffic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_security_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_user_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Manifest {
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_name: Option<String>,
    pub sdk: Sdk,
    pub application: Application,
    pub uses_permissions: Vec<UsesPermission>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub declared_permissions: Vec<DeclaredPermission>,
    /// `uses-feature` names (`android.hardware.microphone`, `android.software.leanback`, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Components a manifest yields at most; the rest are counted in a warning.
const MAX_COMPONENTS: usize = 10_000;

fn absolute(package: &str, name: &str) -> String {
    if let Some(rest) = name.strip_prefix('.') {
        format!("{package}.{rest}")
    } else if !name.contains('.') && !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_owned()
    }
}

/// `foregroundServiceType` as its names: compiled manifests store the flag bits.
fn service_types(value: &crate::axml::Value) -> String {
    const FLAGS: [(i64, &str); 13] = [
        (0x1, "dataSync"),
        (0x2, "mediaPlayback"),
        (0x4, "phoneCall"),
        (0x8, "location"),
        (0x10, "connectedDevice"),
        (0x20, "mediaProjection"),
        (0x40, "camera"),
        (0x80, "microphone"),
        (0x100, "health"),
        (0x200, "remoteMessaging"),
        (0x400, "systemExempted"),
        (0x800, "shortService"),
        (0x4000_0000, "specialUse"),
    ];
    match value {
        crate::axml::Value::Int(bits) => {
            let names: Vec<&str> = FLAGS.iter().filter(|(bit, _)| bits & bit != 0).map(|(_, name)| *name).collect();
            if names.is_empty() { format!("{bits:#x}") } else { names.join("|") }
        }
        other => other.text(),
    }
}

fn filter(element: &Element) -> IntentFilter {
    let names = |tag: &str| -> Vec<String> {
        element.children_named(tag).filter_map(|child| child.attr_text("name")).collect()
    };
    let data = element
        .children_named("data")
        .map(|child| {
            if let Some(mime) = child.attr_text("mimeType") {
                return format!("mime:{mime}");
            }
            let mut text = child.attr_text("scheme").map(|scheme| format!("{scheme}://")).unwrap_or_default();
            text.push_str(&child.attr_text("host").unwrap_or_default());
            if let Some(port) = child.attr_text("port") {
                text.push_str(&format!(":{port}"));
            }
            for key in ["path", "pathPrefix", "pathPattern"] {
                if let Some(path) = child.attr_text(key) {
                    text.push_str(&path);
                }
            }
            text
        })
        .filter(|text| !text.is_empty())
        .collect();
    IntentFilter {
        actions: names("action"),
        categories: names("category"),
        data,
        priority: element.attr("priority").and_then(|value| value.as_int()),
    }
}

impl Manifest {
    pub fn from_document(document: &Document) -> Self {
        let root = &document.root;
        let mut manifest = Manifest { warnings: document.warnings.clone(), ..Manifest::default() };
        if root.name != "manifest" {
            manifest.warnings.push(format!("root element is `{}`, not `manifest`", root.name));
        }
        manifest.package = root.attr_text("package").unwrap_or_default();
        manifest.version_code = root.attr("versionCode").and_then(|value| value.as_int());
        manifest.version_name = root.attr_text("versionName");
        manifest.sdk.compile = root
            .attr("compileSdkVersion")
            .or_else(|| root.attr("platformBuildVersionCode"))
            .and_then(|value| value.as_int());
        if let Some(sdk) = root.children_named("uses-sdk").next() {
            manifest.sdk.min = sdk.attr("minSdkVersion").and_then(|value| value.as_int());
            manifest.sdk.target = sdk.attr("targetSdkVersion").and_then(|value| value.as_int());
            manifest.sdk.max = sdk.attr("maxSdkVersion").and_then(|value| value.as_int());
        }
        let target = manifest.sdk.target.or(manifest.sdk.min).unwrap_or(1);
        for child in &root.children {
            match child.name.as_str() {
                "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                    if let Some(name) = child.attr_text("name") {
                        manifest.uses_permissions.push(UsesPermission {
                            name,
                            max_sdk: child.attr("maxSdkVersion").and_then(|value| value.as_int()),
                            sdk23: child.name != "uses-permission",
                        });
                    }
                }
                "permission" => {
                    if let Some(name) = child.attr_text("name") {
                        manifest
                            .declared_permissions
                            .push(DeclaredPermission { name, protection_level: child.attr_text("protectionLevel") });
                    }
                }
                "uses-feature" => manifest.features.extend(child.attr_text("name")),
                _ => {}
            }
        }
        let Some(application) = root.children_named("application").next() else {
            return manifest;
        };
        manifest.application = Application {
            name: application.attr_text("name").map(|name| absolute(&manifest.package, &name)),
            debuggable: application.attr("debuggable").and_then(|value| value.as_bool()),
            allow_backup: application.attr("allowBackup").and_then(|value| value.as_bool()),
            uses_cleartext_traffic: application.attr("usesCleartextTraffic").and_then(|value| value.as_bool()),
            network_security_config: application.attr_text("networkSecurityConfig"),
            shared_user_id: root.attr_text("sharedUserId"),
        };
        let mut skipped = 0usize;
        for child in &application.children {
            let Some(kind) = ComponentKind::from_tag(&child.name) else { continue };
            if manifest.components.len() >= MAX_COMPONENTS {
                skipped += 1;
                continue;
            }
            let intent_filters: Vec<IntentFilter> = child.children_named("intent-filter").map(filter).collect();
            let explicit = child.attr("exported").and_then(|value| value.as_bool());
            let exported = explicit.unwrap_or(match kind {
                ComponentKind::Provider => target < 17,
                _ => !intent_filters.is_empty() && target < 31,
            });
            let start_at_boot = kind == ComponentKind::Receiver
                && intent_filters
                    .iter()
                    .any(|filter| filter.actions.iter().any(|action| BOOT_ACTIONS.contains(&action.as_str())));
            let permission = child.attr_text("permission");
            let bound_role = permission
                .as_deref()
                .and_then(|permission| BOUND_ROLES.iter().find(|(name, _)| *name == permission))
                .map(|(_, role)| *role);
            manifest.components.push(Component {
                kind,
                name: absolute(&manifest.package, &child.attr_text("name").unwrap_or_default()),
                exported,
                exported_explicit: explicit.is_some(),
                permission,
                disabled: child.attr("enabled").and_then(|value| value.as_bool()) == Some(false),
                process: child.attr_text("process"),
                foreground_service_type: child.attr("foregroundServiceType").map(service_types),
                authorities: child.attr_text("authorities"),
                target: child.attr_text("targetActivity").map(|name| absolute(&manifest.package, &name)),
                intent_filters,
                start_at_boot,
                bound_role,
            });
        }
        if skipped > 0 {
            manifest.warnings.push(format!("{skipped} components past the first {MAX_COMPONENTS} are not listed"));
        }
        manifest
    }
}

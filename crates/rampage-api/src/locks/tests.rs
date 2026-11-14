use std::collections::BTreeSet;

use super::labels::{Label, register_role};
use super::{categorize, not_lock_kind};
use crate::svd::{BitField, Peripheral, Register};

fn register(name: &str, fields: &[&str]) -> Register {
    Register {
        name: name.to_owned(),
        offset: 0,
        bits: 32,
        access: None,
        reset: None,
        description: None,
        fields: fields
            .iter()
            .map(|field| BitField { name: (*field).to_owned(), lsb: 0, width: 1, description: None, values: vec![] })
            .collect(),
    }
}

fn peripheral(name: &str, description: &str) -> Peripheral {
    Peripheral {
        device: "TEST".into(),
        name: name.into(),
        group: None,
        description: Some(description.into()),
        base: 0x4000_0000,
        registers: vec![],
    }
}

fn role(peripheral_name: &str, description: &str, register_name: &str, fields: &[&str]) -> Option<Label> {
    let register = register(register_name, fields);
    register_role(&peripheral(peripheral_name, description), Some(&register), "X", 1)
}

#[test]
fn register_roles_come_from_generic_names() {
    assert!(matches!(role("UID", "Unique device identifier", "UID0", &[]), Some(Label::UniqueId(..))));
    assert!(matches!(role("SYS", "", "DEVICEID", &[]), Some(Label::UniqueId(..))));
    assert!(matches!(role("FLASH", "", "OPTR", &["RDP", "BOR"]), Some(Label::Protection(..))));
    assert!(matches!(role("CTRL", "", "APPROTECT", &[]), Some(Label::Protection(..))));
    assert!(matches!(role("OTP", "One-time-programmable fuses", "VERCNT", &[]), Some(Label::Counter(..))));
    assert!(matches!(role("OTP", "", "FEATURES", &[]), Some(Label::Fuse(..))));
    assert!(matches!(role("RNG", "", "DR", &[]), Some(Label::Random(..))));
    // Unlock keys, the core's part number, status and data registers have no role.
    assert_eq!(role("FLASH", "", "OPTKEYR", &[]), None);
    assert_eq!(role("SCB", "System control block", "CPUID", &[]), None);
    assert_eq!(role("FLASH", "", "SR", &["BSY"]), None);
    assert_eq!(role("SPI1", "Serial peripheral interface", "DR", &[]), None);
    assert_eq!(role("FLASH", "", "CR", &["PG", "LOCK"]), None, "a flash write lock bit is not a debug lock");
}

#[test]
fn categories_follow_the_labels() {
    let set = |labels: Vec<Label>| labels.into_iter().collect::<BTreeSet<_>>();
    let signature = set(vec![Label::Signature("P-256".into()), Label::Hash("SHA-256".into())]);
    assert_eq!(categorize(&signature), Some("signature_verification"));
    let challenge = set(vec![Label::Random("RNG.DR".into()), Label::Mac("HMAC".into())]);
    assert_eq!(categorize(&challenge), Some("challenge_response"));
    assert_eq!(categorize(&set(vec![Label::Random("RNG.DR".into())])), None, "randomness alone decides nothing");
    assert_eq!(categorize(&set(vec![Label::UniqueId("UID.UID0".into(), 1)])), Some("device_binding"));
    assert_eq!(categorize(&set(vec![Label::Counter("OTP.VERCNT".into(), 1)])), Some("anti_rollback"));
    assert_eq!(categorize(&set(vec![Label::DebugStatus("DHCSR".into(), 1)])), Some("debug_lock"));
    assert_eq!(categorize(&set(vec![Label::Fuse("OTP.FEATURES".into(), 1)])), Some("feature_lock"));
    let crc = set(vec![Label::Crc]);
    assert_eq!((categorize(&crc), not_lock_kind(&crc)), (None, Some("integrity_check")));
    let digest = set(vec![Label::Hash("SHA-256".into())]);
    assert_eq!((categorize(&digest), not_lock_kind(&digest)), (None, Some("integrity_check")));
}

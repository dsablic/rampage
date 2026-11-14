//! What a source of a decision is: a register or memory location's role (from an imported CMSIS-SVD map, or an
//! architectural Cortex-M debug register), or a routine's role (from crypto constants in its call tree and
//! library function names).

use crate::svd::{Peripheral, Register};
use crate::workflows::match_api;

/// The role of data or a routine a decision consults.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Label {
    /// A public-key signature check (algorithm).
    Signature(String),
    /// A keyed MAC (algorithm).
    Mac(String),
    /// A hash digest, keyed or not (algorithm).
    Hash(String),
    /// A CRC or checksum routine.
    Crc,
    /// A unique device identifier register.
    UniqueId(String, u64),
    /// A random number source.
    Random(String),
    /// A monotonic or version counter in fuses or protected storage.
    Counter(String, u64),
    /// Fuse, OTP or option-byte storage (feature, region or configuration bits).
    Fuse(String, u64),
    /// A readout, write or debug protection setting.
    Protection(String, u64),
    /// The core's debug status (a debugger attached).
    DebugStatus(String, u64),
}

/// The architectural Debug Halting Control and Status Register (ARMv6-M, ARMv7-M, ARMv8-M).
pub(super) const DHCSR: u64 = 0xE000_EDF0;
/// The Application Interrupt and Reset Control Register.
pub(super) const AIRCR: u64 = 0xE000_ED0C;
/// ARMv8-M Debug Authentication Control Register.
pub(super) const DAUTHCTRL: u64 = 0xE000_EE04;

/// The role of an architectural Cortex-M register, when `address` is one this tool knows.
pub(super) fn architectural(address: u64) -> Option<Label> {
    match address {
        DHCSR => Some(Label::DebugStatus("DHCSR".into(), address)),
        DAUTHCTRL => Some(Label::Protection("DAUTHCTRL".into(), address)),
        _ => None,
    }
}

fn words(text: &str) -> String {
    text.to_ascii_uppercase()
}

fn has_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

/// Whether a register or field name says it controls readout, write or debug protection.
fn protection_name(name: &str) -> bool {
    let name = words(name);
    if name.contains("KEY") {
        return false;
    }
    has_any(&name, &["RDP", "READOUT", "APPROTECT", "CRP", "WRP"])
        || has_any(&name, &["DBG", "DEBUG", "JTAG", "SWD"]) && has_any(&name, &["DIS", "LOCK", "PROT"])
}

/// The role of `register` in `peripheral` (its name `name`), from SVD names only: generic words such as UID, OTP,
/// RDP, never a vendor's part names.
pub(super) fn register_role(
    peripheral: &Peripheral,
    register: Option<&Register>,
    name: &str,
    address: u64,
) -> Option<Label> {
    let peripheral_name = words(&peripheral.name);
    let peripheral_text = format!(
        "{} {} {}",
        peripheral_name,
        words(peripheral.group.as_deref().unwrap_or("")),
        words(peripheral.description.as_deref().unwrap_or(""))
    );
    let register_name = register.map(|register| words(&register.name)).unwrap_or_default();
    let register_text = register
        .map(|register| format!("{} {}", register_name, words(register.description.as_deref().unwrap_or(""))))
        .unwrap_or_default();
    if register_name.contains("KEY") {
        return None;
    }
    if let Some(register) = register
        && (protection_name(&register.name) || register.fields.iter().any(|field| protection_name(&field.name)))
    {
        return Some(Label::Protection(name.to_owned(), address));
    }
    let unique = |text: &str| {
        (has_any(text, &["UID", "UNIQUE", "DEVICEID", "DEVICE_ID", "DEVID", "SERIALNUM", "SERIAL_NUM"])
            || text.contains("SERIAL") && text.contains("NUMBER"))
            && !text.contains("CPUID")
    };
    if unique(&peripheral_text) || unique(&register_text) {
        return Some(Label::UniqueId(name.to_owned(), address));
    }
    let random = |text: &str| has_any(text, &["RNG", "RANDOM", "ENTROPY"]);
    if random(&peripheral_name) || random(&register_name) {
        return Some(Label::Random(name.to_owned()));
    }
    let storage = has_any(&peripheral_text, &["OTP", "FUSE", "ONE-TIME", "ONE TIME"])
        || has_any(&register_name, &["OTP", "FUSE"])
        || register_name.starts_with("OPT")
        || register_name.contains("OPTION");
    let counter = has_any(&register_text, &["ROLLBACK", "MONOTONIC", "NVCNT", "NV_CNT", "SVN"])
        || storage && has_any(&register_text, &["CNT", "COUNTER", "VERSION", "VER"]);
    if counter {
        return Some(Label::Counter(name.to_owned(), address));
    }
    if storage {
        return Some(Label::Fuse(name.to_owned(), address));
    }
    None
}

/// Library routines that verify a signature or certificate.
const SIGNATURE_APIS: &[(&str, &str)] = &[
    ("mbedtls_pk_verify*", "mbed TLS"),
    ("mbedtls_rsa_pkcs1_verify*", "mbed TLS RSA"),
    ("mbedtls_rsa_rsassa_pkcs1_v15_verify*", "mbed TLS RSA"),
    ("mbedtls_rsa_rsassa_pss_verify*", "mbed TLS RSA"),
    ("mbedtls_ecdsa_verify*", "mbed TLS ECDSA"),
    ("mbedtls_ecdsa_read_signature*", "mbed TLS ECDSA"),
    ("mbedtls_x509_crt_verify*", "mbed TLS X.509"),
    ("uecc_verify", "micro-ecc ECDSA"),
    ("ed25519_verify", "Ed25519"),
    ("crypto_sign_open", "NaCl/libsodium Ed25519"),
    ("crypto_sign_verify_detached", "NaCl/libsodium Ed25519"),
    ("crypto_sign_ed25519_verify_detached", "libsodium Ed25519"),
    ("evp_digestverify*", "OpenSSL"),
    ("evp_pkey_verify*", "OpenSSL"),
    ("evp_verifyfinal*", "OpenSSL"),
    ("rsa_verify", "OpenSSL RSA"),
    ("rsa_public_decrypt", "OpenSSL RSA"),
    ("ecdsa_verify", "OpenSSL ECDSA"),
    ("ecdsa_do_verify", "OpenSSL ECDSA"),
    ("x509_verify_cert", "OpenSSL X.509"),
    ("br_rsa_i15_pkcs1_vrfy*", "BearSSL RSA"),
    ("br_rsa_i31_pkcs1_vrfy*", "BearSSL RSA"),
    ("br_rsa_i32_pkcs1_vrfy*", "BearSSL RSA"),
    ("br_rsa_i62_pkcs1_vrfy*", "BearSSL RSA"),
    ("br_ecdsa_i15_vrfy*", "BearSSL ECDSA"),
    ("br_ecdsa_i31_vrfy*", "BearSSL ECDSA"),
    ("wc_signatureverify*", "wolfCrypt"),
    ("wc_rsassl_verify*", "wolfCrypt RSA"),
    ("wc_ecc_verify_hash*", "wolfCrypt ECDSA"),
    ("wc_ed25519_verify_msg*", "wolfCrypt Ed25519"),
    ("cryptverifysignature*", "Windows CryptoAPI"),
    ("bcryptverifysignature", "Windows CNG"),
    ("seckeyverifysignature", "Apple Security"),
];

/// Library routines that compute or verify a keyed MAC.
const MAC_APIS: &[(&str, &str)] = &[
    ("hmac*", "HMAC"),
    ("mbedtls_md_hmac*", "mbed TLS HMAC"),
    ("mbedtls_cipher_cmac*", "mbed TLS CMAC"),
    ("cmac_*", "CMAC"),
    ("crypto_auth*", "NaCl/libsodium HMAC"),
    ("crypto_onetimeauth*", "NaCl/libsodium Poly1305"),
    ("evp_mac_*", "OpenSSL MAC"),
    ("wc_hmac*", "wolfCrypt HMAC"),
];

/// Library routines that return random bytes.
const RANDOM_APIS: &[(&str, &str)] = &[
    ("getrandom", "getrandom"),
    ("getentropy", "getentropy"),
    ("arc4random*", "arc4random"),
    ("rand_bytes", "OpenSSL RAND_bytes"),
    ("rand_priv_bytes", "OpenSSL RAND_priv_bytes"),
    ("randombytes*", "libsodium randombytes"),
    ("mbedtls_ctr_drbg_random*", "mbed TLS CTR-DRBG"),
    ("mbedtls_hmac_drbg_random*", "mbed TLS HMAC-DRBG"),
    ("bcryptgenrandom", "Windows CNG"),
    ("cryptgenrandom", "Windows CryptoAPI"),
    ("secrandomcopybytes", "Apple Security"),
    ("rand", "C rand"),
    ("random", "C random"),
    ("lrand48", "C lrand48"),
];

/// Routines after which the program does not continue: a reset, an exit or an abort.
const STOP_APIS: &[(&str, &str)] = &[
    ("nvic_systemreset", "reset"),
    ("__nvic_systemreset", "reset"),
    ("reboot", "reset"),
    ("sys_reboot", "reset"),
    ("exit", "exit"),
    ("_exit", "exit"),
    ("_exit_group", "exit"),
    ("abort", "exit"),
    ("__assert_fail", "exit"),
    ("panic", "halt"),
];

pub(super) fn signature_api(name: &str) -> Option<&'static str> {
    match_api(SIGNATURE_APIS, name)
}

pub(super) fn mac_api(name: &str) -> Option<&'static str> {
    match_api(MAC_APIS, name)
}

pub(super) fn random_api(name: &str) -> Option<&'static str> {
    match_api(RANDOM_APIS, name)
}

pub(super) fn stop_api(name: &str) -> Option<&'static str> {
    match_api(STOP_APIS, name)
}

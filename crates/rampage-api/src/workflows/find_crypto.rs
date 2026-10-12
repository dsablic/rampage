//! `find_crypto`: cryptographic and data-transformation evidence -- algorithm constants embedded in the image
//! (from the `rampage-constants` database), crypto library APIs, the functions that reference either, and crypto
//! capability tags. A constant shows that a table is present, not that the algorithm runs or what it protects.

use std::collections::{BTreeMap, BTreeSet};

use rampage_constants::{ConstantDb, Endian, Kind, scan_binary};
use rampage_loaders::SymbolKind;
use serde_json::json;

use super::network_surface::{count, record, referencing};
use super::{Confidence, Finding, ReportLimits, Section, WorkflowReport, match_api};
use crate::{ApiError, Project};

/// Crypto library API patterns (see `api_matches`), each with the library family it belongs to.
const CRYPTO_APIS: &[(&str, &str)] = &[
    ("cryptacquirecontext", "Windows CryptoAPI"),
    ("cryptcreatehash", "Windows CryptoAPI"),
    ("crypthashdata", "Windows CryptoAPI"),
    ("cryptderivekey", "Windows CryptoAPI"),
    ("cryptgenkey", "Windows CryptoAPI"),
    ("cryptimportkey", "Windows CryptoAPI"),
    ("cryptexportkey", "Windows CryptoAPI"),
    ("cryptencrypt", "Windows CryptoAPI"),
    ("cryptdecrypt", "Windows CryptoAPI"),
    ("cryptgenrandom", "Windows CryptoAPI"),
    ("cryptprotectdata", "Windows DPAPI"),
    ("cryptunprotectdata", "Windows DPAPI"),
    ("bcrypt*", "Windows CNG"),
    ("ncrypt*", "Windows CNG"),
    ("evp_*", "OpenSSL"),
    ("aes_*", "OpenSSL"),
    ("sha1_*", "OpenSSL"),
    ("sha256_*", "OpenSSL"),
    ("sha512_*", "OpenSSL"),
    ("md5_*", "OpenSSL"),
    ("hmac_*", "OpenSSL"),
    ("rsa_*", "OpenSSL"),
    ("rand_bytes", "OpenSSL"),
    ("cc_sha*", "CommonCrypto"),
    ("cc_md5*", "CommonCrypto"),
    ("cccrypt*", "CommonCrypto"),
    ("cchmac*", "CommonCrypto"),
    ("mbedtls_aes_*", "mbed TLS"),
    ("mbedtls_sha*", "mbed TLS"),
    ("mbedtls_md*", "mbed TLS"),
    ("mbedtls_cipher_*", "mbed TLS"),
    ("crypto_secretbox*", "libsodium"),
    ("crypto_box*", "libsodium"),
    ("crypto_sign*", "libsodium"),
    ("crypto_aead_*", "libsodium"),
    ("crypto_generichash*", "libsodium"),
    ("randombytes_*", "libsodium"),
    ("gcry_cipher_*", "libgcrypt"),
    ("gcry_md_*", "libgcrypt"),
];

/// Functions suggested for decompilation in next steps.
const SUGGESTED_FUNCTIONS: usize = 3;

/// The library family of a crypto API, if `name` is one.
fn crypto_api(name: &str) -> Option<&'static str> {
    match_api(CRYPTO_APIS, name)
}

/// Ciphers, hashes, MACs and public-key parameters, as opposed to checksums, compression and encodings.
fn is_cryptographic(kind: Kind) -> bool {
    matches!(kind, Kind::BlockCipher | Kind::StreamCipher | Kind::Hash | Kind::Mac | Kind::PublicKey)
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::BlockCipher => "block cipher",
        Kind::StreamCipher => "stream cipher",
        Kind::Hash => "hash",
        Kind::Mac => "MAC",
        Kind::Checksum => "checksum",
        Kind::Compression => "compression",
        Kind::Encoding => "encoding",
        Kind::PublicKey => "public-key parameter",
    }
}

impl Project {
    /// The binary's cryptographic evidence: embedded algorithm constants, crypto APIs, the functions that
    /// reference them, and crypto capability tags.
    pub fn find_crypto(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("find_crypto", self);
        let analysis_error = self.analysis().err().map(|error| error.to_string());
        if let Some(error) = &analysis_error {
            report.limitation(format!(
                "Code references are unavailable ({error}); referencing functions are not listed."
            ));
        }
        let analyzed = analysis_error.is_none();
        // Function start to (name, evidence), across constants and APIs.
        let mut users: BTreeMap<u64, (String, Vec<String>)> = BTreeMap::new();

        let mut crypto = Section::new("Cryptographic constants", limits);
        let mut transforms = Section::new("Checksum, compression and encoding constants", limits);
        let mut first_constant = None;
        for hit in scan_binary(&self.binary, ConstantDb::bundled()) {
            first_constant.get_or_insert(hit.address);
            let found = self.users(&[hit.address], analyzed);
            let order = match hit.endian {
                Some(Endian::Little) => ", little-endian",
                Some(Endian::Big) => ", big-endian",
                None => "",
            };
            let extent = if hit.complete { "complete table" } else { "leading part of the table" };
            let mut evidence = vec![
                format!("{} bytes at {:#x}{order} ({extent})", hit.length, hit.address),
                format!("algorithm family: {}", hit.algorithm),
            ];
            evidence.extend(referencing(&found));
            // The bytes are read straight from the image; only a partial table leaves room for coincidence.
            let confidence = if hit.complete { Confidence::Observed } else { Confidence::Medium };
            let finding = Finding::new("find_crypto", confidence, format!("{} ({})", hit.what, kind_label(hit.kind)))
                .at(hit.address)
                .evidence(evidence);
            if is_cryptographic(hit.kind) {
                crypto.push(finding);
            } else {
                transforms.push(finding);
            }
            record(&mut users, &found, &format!("references the {}", hit.what));
        }

        let mut apis = Section::new("Crypto library APIs", limits);
        let mut seen = BTreeSet::new();
        for import in &self.binary.imports {
            let Some(family) = crypto_api(&import.name) else { continue };
            if !seen.insert(import.name.clone()) {
                continue;
            }
            let mut targets: Vec<u64> = self
                .binary
                .import_slots
                .iter()
                .filter(|slot| slot.name == import.name)
                .map(|slot| slot.address)
                .collect();
            targets.extend(self.resolve(&import.name).ok());
            let found = self.users(&targets, analyzed);
            let library = import.library.as_deref().unwrap_or("an unrecorded library");
            let mut finding = Finding::new(
                "list_imports",
                Confidence::Observed,
                format!("imports `{}` from {library} ({family})", import.name),
            )
            .evidence(referencing(&found));
            if let Some(&address) = targets.first() {
                finding = finding.at(address);
            }
            apis.push(finding);
            record(&mut users, &found, &format!("calls `{}` ({family})", import.name));
        }
        for symbol in &self.binary.symbols {
            if symbol.kind != SymbolKind::Function
                || !self.binary.is_code(symbol.address)
                || seen.contains(&symbol.name)
            {
                continue;
            }
            let Some(family) = crypto_api(&symbol.name) else { continue };
            seen.insert(symbol.name.clone());
            let found = self.users(&[symbol.address], analyzed);
            apis.push(
                Finding::new(
                    "list_functions",
                    Confidence::Observed,
                    format!("contains function `{}` ({family}), statically linked or local", symbol.name),
                )
                .at(symbol.address)
                .evidence(referencing(&found)),
            );
            record(&mut users, &found, &format!("calls `{}` ({family})", symbol.name));
        }

        let mut ranked: Vec<(u64, (String, Vec<String>))> = users.into_iter().collect();
        ranked.sort_by(|a, b| b.1.1.len().cmp(&a.1.1.len()).then(a.0.cmp(&b.0)));
        let mut functions = Section::new("Functions referencing crypto evidence", limits);
        for (address, (name, evidence)) in &ranked {
            functions.push(
                Finding::new(
                    "xrefs",
                    Confidence::Observed,
                    format!("`{name}` {} crypto or transformation evidence", count(evidence.len())),
                )
                .at(*address)
                .evidence(evidence.iter().cloned()),
            );
        }

        let mut tags = Section::new("Crypto capability tags", limits);
        for capability in self.capabilities().iter().filter(|capability| capability.category == "crypto") {
            tags.push(
                Finding::new(
                    "capabilities",
                    Confidence::Low,
                    format!(
                        "building blocks of '{}' are present; this does not show the behavior executes",
                        capability.name
                    ),
                )
                .evidence(capability.evidence.iter().cloned()),
            );
        }

        let empty = crypto.total == 0 && transforms.total == 0 && apis.total == 0 && tags.total == 0;
        report.summary.push(if empty {
            "No algorithm constants, crypto APIs or crypto capability tags were observed.".to_owned()
        } else {
            format!(
                "{} cryptographic constants, {} checksum/compression/encoding constants, {} crypto APIs and {} \
                 crypto capability tags observed; {} functions reference them.",
                crypto.total, transforms.total, apis.total, tags.total, functions.total
            )
        });
        for (address, (name, _)) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{address:#x}") }),
                format!("`{name}` references crypto evidence; read what it transforms and where the key comes from."),
            );
        }
        if let Some(address) = first_constant {
            report.step(
                "xrefs",
                json!({ "to": format!("{address:#x}") }),
                "Trace every reference to the first algorithm constant.",
            );
        }
        report.sections.extend([crypto, transforms, apis, functions, tags]);

        report.limitation(
            "A constant shows that an algorithm's table is in the image, not that the algorithm runs, which data it \
             protects, or where its key comes from; libraries often carry tables they never use.",
        );
        report.limitation(
            "Not detectable by constants: RC4, TEA/XTEA, Adler-32, HMAC and Poly1305 (no distinctive tables), \
             constants the compiler builds into instructions, and SIMD-interleaved or runtime-generated tables.",
        );
        report.limitation(
            "Absence of evidence is not evidence of absence: custom or obfuscated crypto and APIs resolved by name at \
             run time are not detected.",
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::crypto_api;

    #[test]
    fn matches_decorated_crypto_names() {
        assert_eq!(crypto_api("CryptEncrypt"), Some("Windows CryptoAPI"));
        assert_eq!(crypto_api("__imp_CryptAcquireContextW"), Some("Windows CryptoAPI"));
        assert_eq!(crypto_api("BCryptOpenAlgorithmProvider"), Some("Windows CNG"));
        assert_eq!(crypto_api("EVP_EncryptInit_ex@plt"), Some("OpenSSL"));
        assert_eq!(crypto_api("_CC_SHA256"), Some("CommonCrypto"));
        assert_eq!(crypto_api("crypto_secretbox_easy"), Some("libsodium"));
        assert_eq!(crypto_api("puts"), None);
        assert_eq!(crypto_api("encrypt_file"), None);
        assert_eq!(crypto_api("crypto_misc"), None);
    }
}

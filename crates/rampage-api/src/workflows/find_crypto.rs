//! `find_crypto`: cryptographic and data-transformation evidence -- algorithm constants embedded in the image
//! (from the `rampage-constants` database), crypto library APIs, the functions that reference either, and crypto
//! capability tags. A constant shows that a table is present, not that the algorithm runs or what it protects.

use rampage_constants::{ConstantDb, Endian, Kind, scan_binary_report};
use serde_json::{Value, json};

use super::registry::{Workflow, WorkflowOptions, report_options, report_schema};
use super::{Confidence, Finding, ReportLimits, Section, Tracer, WorkflowReport, capability_section, match_api};
use crate::tools::Group;
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

pub struct FindCrypto;

impl Workflow for FindCrypto {
    fn name(&self) -> &'static str {
        "find_crypto"
    }

    fn summary(&self) -> &'static str {
        "Algorithm constants, crypto APIs and the functions referencing them"
    }

    fn description(&self) -> &'static str {
        "Map cryptographic evidence: algorithm constants embedded in the image (AES/DES/Blowfish tables, SHA/MD5 \
         round constants, ChaCha, curve parameters; checksum/compression/encoding tables listed separately), \
         crypto library APIs, the functions that reference them (via xrefs), and crypto capability tags. A \
         constant shows a table is present, not that the algorithm runs."
    }

    fn group(&self) -> Group {
        Group::Detection
    }

    fn input_schema(&self) -> Value {
        report_schema()
    }

    fn options(&self, input: Value) -> Result<WorkflowOptions, String> {
        report_options(input)
    }

    fn run(&self, project: &Project, options: &WorkflowOptions) -> Result<WorkflowReport, ApiError> {
        project.find_crypto(options.limits)
    }
}

impl Project {
    /// The binary's cryptographic evidence: embedded algorithm constants, crypto APIs, the functions that
    /// reference them, and crypto capability tags.
    pub fn find_crypto(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("find_crypto", self);
        let mut tracer = Tracer::new(self, &mut report);

        let mut crypto = Section::new("Cryptographic constants", limits);
        let mut transforms = Section::new("Checksum, compression and encoding constants", limits);
        let mut first_constant = None;
        let scan = scan_binary_report(&self.binary, ConstantDb::bundled());
        for hit in scan.hits {
            first_constant.get_or_insert(hit.address);
            let found = tracer.users(&[hit.address]);
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
            evidence.extend(found.evidence());
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
            tracer.record(&found, &format!("references the {}", hit.what));
        }

        let apis = tracer.api_section("Crypto library APIs", limits, crypto_api);
        let (functions, ranked) = tracer.finish(
            &mut report,
            "Functions referencing crypto evidence",
            "crypto or transformation evidence",
            limits,
        );
        let capabilities = self.capabilities();
        let tags = capability_section(
            "Crypto capability tags",
            limits,
            capabilities.iter().filter(|capability| capability.category == "crypto"),
        );

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
        for (address, name) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
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

        if scan.truncated {
            report.limitation(format!(
                "The constant scan reached its cap of {} hits; hits past the cap were dropped or not searched for, \
                 so some constants may be missing.",
                rampage_constants::MAX_HITS
            ));
        }
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

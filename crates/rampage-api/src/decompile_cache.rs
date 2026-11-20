//! Stored decompilations: one function's decompiler result kept in the persistent analysis store, so asking for
//! it again (in this process or any later one) skips the decompiler. See "Persistent analysis store" in
//! `docs/mcp.md` and `docs/plans/2026-11-20-incremental-analysis.md`.
//!
//! The key hashes everything a decompilation reads: the binary's analysis key (its bytes, image, format, Raw
//! interpretation, rampage version and executable), the function, the decompiler options, where it runs (in
//! process, or the supervised worker with its limits and executable) and every annotation except comments and the
//! findings ledger ([`crate::annotations::Annotations::decompile_fingerprint`]). An edit therefore invalidates by
//! changing the key: a comment or finding keeps every stored decompilation; any other edit makes every one miss,
//! and each is recomputed when next asked for. Only successful results are stored. External specifications
//! (`GHIDRA_INSTALL_DIR`), which can change without rampage knowing, disable it.
//!
//! The row is untrusted: it is used only when the store's checksum and framing match and the body decodes
//! completely into the expected shape for this function, with every token span inside the code on a character
//! boundary. Anything else is a miss that decompiles afresh.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis_cache::{DerivedCounters, DerivedKind, DerivedLookup};
use crate::decompile::{Decompilation, DecompiledToken};
use crate::{AnalysisStore, Project};

/// Bump whenever the decompilation pipeline (the engine, the symbol, type and propagation plans, or the result
/// shape) changes for the same key inputs. `decompile_cache_golden` (tests/integration) records digests of the
/// decompiled C per fixture function and OS under this version and fails when they change but the version did not.
pub const DECOMPILE_CACHE_VERSION: u32 = 1;

/// A stored decompilation as kept in the store: everything [`Decompilation`] holds except what is recomputed from
/// it (`recovery_status` and `variables`, both functions of `structure`).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    address: u64,
    name: String,
    code: String,
    language_id: String,
    tokens: Vec<StoredToken>,
    structure: rampage_decompiler::StructuredResult,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredToken {
    text: String,
    kind: String,
    address: Option<u64>,
    span: Option<(usize, usize)>,
}

/// One decompilation's place in the store.
pub(crate) struct Entry<'a> {
    store: Arc<AnalysisStore>,
    key: String,
    address: u64,
    counters: &'a DerivedCounters,
}

impl<'a> Entry<'a> {
    /// The entry for decompiling `address` with `options` over `annotations` in `project`, or `None` when the
    /// project has no store entry identity (no store, a capture) or the decompiler reads
    /// external specifications.
    pub(crate) fn new(
        project: &'a Project,
        worker: Option<&rampage_decompiler::worker::WorkerConfig>,
        options: &rampage_decompiler::DecompilerOptions,
        annotations: &crate::annotations::Annotations,
        address: u64,
    ) -> Option<Self> {
        if std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
            return None;
        }
        // The key hashed the file as loaded; a file changed in place since then is not those bytes any more, so
        // neither read nor write, and decompile exactly as without a store (which may refuse the changed source).
        if project.binary.validate_available_backing_source().is_err() {
            return None;
        }
        let (store, analysis_key) = project.derived_store()?;
        let mut hash = Sha256::new();
        hash.update(b"rampage-decompile\0");
        hash.update(DECOMPILE_CACHE_VERSION.to_le_bytes());
        hash.update(analysis_key.as_bytes());
        hash.update([0]);
        hash.update(address.to_le_bytes());
        hash.update(format!("{options:?}\0").as_bytes());
        match worker {
            None => hash.update(b"in-process\0"),
            Some(config) => {
                hash.update(
                    format!(
                        "worker\0{:?}\0{}\0{}\0{}\0{}\0",
                        config.timeout,
                        config.memory_limit_bytes,
                        config.max_request_bytes,
                        config.max_stdout_bytes,
                        config.max_stderr_bytes
                    )
                    .as_bytes(),
                );
                hash.update(worker_stamp(config).as_bytes());
                hash.update([0]);
            }
        }
        hash.update(annotations.decompile_fingerprint());
        let key = format!("{}:{}", DerivedKind::Decompile.name(), rampage_arch::hex::bytes(&hash.finalize()));
        Some(Self { store, key, address, counters: &project.decompile_counts })
    }

    /// The stored decompilation, verified; `None` on a miss or any rejection.
    pub(crate) fn load(&self) -> Option<Decompilation> {
        let body = match self.store.load_derived(DerivedKind::Decompile, &self.key) {
            DerivedLookup::Hit(body) => body,
            DerivedLookup::Absent => return None,
            DerivedLookup::Rejected(reason) => {
                self.counters.reject(reason);
                return None;
            }
        };
        let Some(decompilation) = decode(&body, self.address) else {
            self.counters.reject("entry malformed: not a decompilation of this function".into());
            return None;
        };
        self.counters.hits.fetch_add(1, Ordering::Relaxed);
        Some(decompilation)
    }

    /// Stores `decompilation` (best effort: a busy or failing store only skips the write).
    pub(crate) fn store(&self, decompilation: &Decompilation) {
        if decompilation.address != self.address {
            return;
        }
        if self.store.store_derived(DerivedKind::Decompile, &self.key, &encode(decompilation)).is_ok() {
            self.counters.stored.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn encode(decompilation: &Decompilation) -> Vec<u8> {
    let stored = Stored {
        address: decompilation.address,
        name: decompilation.name.clone(),
        code: decompilation.code.clone(),
        language_id: decompilation.language_id.clone(),
        tokens: decompilation
            .tokens
            .iter()
            .map(|token| StoredToken {
                text: token.text.clone(),
                kind: token.kind.clone(),
                address: token.address,
                span: token.span,
            })
            .collect(),
        structure: decompilation.structure.clone(),
    };
    serde_json::to_vec(&stored).expect("stored decompilations serialize")
}

/// A stored body for the function at `address`, or `None` unless it decodes completely and consistently.
fn decode(body: &[u8], address: u64) -> Option<Decompilation> {
    let stored: Stored = serde_json::from_slice(body).ok()?;
    if stored.address != address {
        return None;
    }
    let spans_fit = stored.tokens.iter().all(|token| match token.span {
        None => true,
        Some((start, end)) => {
            start <= end
                && end <= stored.code.len()
                && stored.code.is_char_boundary(start)
                && stored.code.is_char_boundary(end)
        }
    });
    if !spans_fit {
        return None;
    }
    let recovery_status = stored.structure.recovery_status();
    let variables = crate::variables::descriptors(&stored.structure);
    Some(Decompilation {
        address: stored.address,
        name: stored.name,
        code: stored.code,
        language_id: stored.language_id,
        tokens: stored
            .tokens
            .into_iter()
            .map(|token| DecompiledToken {
                text: token.text,
                kind: token.kind,
                address: token.address,
                span: token.span,
            })
            .collect(),
        recovery_status,
        structure: stored.structure,
        variables,
    })
}

/// The worker executable the supervisor would start for `config` (as `rampage_decompiler::worker` resolves it),
/// by path, size and modification time, so another worker build never reads this one's results.
fn worker_stamp(config: &rampage_decompiler::worker::WorkerConfig) -> String {
    let executable = match &config.executable {
        Some(path) => Some(path.clone()),
        None => match std::env::var_os("RAMPAGE_WORKER") {
            Some(path) => Some(std::path::PathBuf::from(path)),
            None => std::env::current_exe()
                .ok()
                .map(|path| path.with_file_name(if cfg!(windows) { "rampage-worker.exe" } else { "rampage-worker" })),
        },
    };
    executable.map_or_else(|| "unknown".to_owned(), |path| crate::analysis_cache::file_stamp(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Decompilation {
        let structure = rampage_decompiler::StructuredResult::empty();
        Decompilation {
            address: 0x1000,
            name: "f".into(),
            code: "int f(void) { return 1; }".into(),
            language_id: "x86:LE:64:default".into(),
            tokens: vec![DecompiledToken {
                text: "f".into(),
                kind: "function".into(),
                address: Some(0x1000),
                span: Some((4, 5)),
            }],
            recovery_status: structure.recovery_status(),
            variables: crate::variables::descriptors(&structure),
            structure,
        }
    }

    #[test]
    fn a_stored_decompilation_round_trips() {
        let original = sample();
        let decoded = decode(&encode(&original), 0x1000).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), serde_json::to_value(&original).unwrap());
    }

    #[test]
    fn inconsistent_or_damaged_bodies_are_refused() {
        let body = encode(&sample());
        assert!(decode(&body, 0x1004).is_none(), "another function's result");
        for cut in [0, 1, body.len() / 2, body.len() - 1] {
            assert!(decode(&body[..cut], 0x1000).is_none(), "truncated at {cut}");
        }
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["tokens"][0]["span"] = serde_json::json!([4, 500]);
        assert!(decode(&serde_json::to_vec(&value).unwrap(), 0x1000).is_none(), "span past the code");
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(decode(&serde_json::to_vec(&value).unwrap(), 0x1000).is_none(), "unknown field");
        let mut multibyte = sample();
        multibyte.code = "int é(void);".into();
        multibyte.tokens[0].span = Some((4, 5));
        assert!(decode(&encode(&multibyte), 0x1000).is_none(), "span inside a character");
    }
}

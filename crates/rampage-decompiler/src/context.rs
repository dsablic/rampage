//! Checked-layout provenance for supported Rust native entry points. Direct foreign calls into the private
//! C ABI are outside this guard's boundary; they must not initialize or mutate Ghidra registries independently.
//! The embedded manifest is trusted build input; this does not authenticate arbitrary software builds.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::{Decompiler, Error, FFI_LOCK, specs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundledContext {
    home: PathBuf,
    bundle_id: &'static str,
}

impl VerifiedBundledContext {
    pub fn bundle_id(&self) -> &'static str {
        self.bundle_id
    }
    pub fn home(&self) -> &Path {
        &self.home
    }
    /// Feeds the exact trusted embedded manifest (names and bytes with length delimiters) to a caller's digest.
    /// This is an identity representation, not authentication or a substitute for rechecking the live context.
    pub fn feed_manifest_identity(&self, update: impl FnMut(&[u8])) {
        specs::feed_manifest_identity(update);
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        embedded_manifest_sha256()
    }
}

pub(crate) fn embedded_manifest_sha256() -> [u8; 32] {
    static DIGEST: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hash = ManifestSha256::new();
        specs::feed_manifest_identity(|bytes| hash.update(bytes));
        hash.finish()
    })
}

// Fixed-memory SHA-256 over trusted embedded manifest bytes; no filesystem or untrusted JSON is decoded here.
struct ManifestSha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    used: usize,
    bytes: u64,
}

impl ManifestSha256 {
    fn new() -> Self {
        Self {
            state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buffer: [0; 64],
            used: 0,
            bytes: 0,
        }
    }
    fn update(&mut self, mut bytes: &[u8]) {
        self.bytes += bytes.len() as u64;
        while !bytes.is_empty() {
            let count = (64 - self.used).min(bytes.len());
            self.buffer[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == 64 {
                self.compress(self.buffer);
                self.used = 0;
            }
        }
    }
    fn finish(mut self) -> [u8; 32] {
        let bits = self.bytes * 8;
        self.buffer[self.used] = 0x80;
        self.buffer[self.used + 1..].fill(0);
        if self.used >= 56 {
            self.compress(self.buffer);
            self.buffer.fill(0);
        }
        self.buffer[56..].copy_from_slice(&bits.to_be_bytes());
        self.compress(self.buffer);
        let mut digest = [0; 32];
        for (chunk, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
    fn compress(&mut self, block: [u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
            0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
            0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let at = index * 4;
            *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for index in 16..64 {
            let first = words[index - 15];
            let second = words[index - 2];
            let sigma0 = first.rotate_right(7) ^ first.rotate_right(18) ^ (first >> 3);
            let sigma1 = second.rotate_right(17) ^ second.rotate_right(19) ^ (second >> 10);
            words[index] = words[index - 16].wrapping_add(sigma0).wrapping_add(words[index - 7]).wrapping_add(sigma1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let first = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(first).wrapping_add(choose).wrapping_add(K[index]).wrapping_add(words[index]);
            let second = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = second.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, word) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(word);
        }
    }
}

#[derive(Default)]
struct NativeContext {
    attempted: bool,
    home: Option<PathBuf>,
    verified_bundled: bool,
}

impl NativeContext {
    fn accepts(&self, home: &Path) -> bool {
        !self.attempted || (self.verified_bundled && self.home.as_deref() == Some(home))
    }
    fn record(&mut self, home: Option<PathBuf>, verified: bool) {
        let compatible = verified && (!self.attempted || self.home == home);
        if !self.attempted {
            self.attempted = true;
            self.home = home;
            self.verified_bundled = compatible;
        } else if !compatible {
            self.verified_bundled = false;
        }
    }
}

static NATIVE_CONTEXT: Mutex<NativeContext> =
    Mutex::new(NativeContext { attempted: false, home: None, verified_bundled: false });

fn invalid() -> Error {
    Error::Ghidra(
        "checked layouts require an exact verified embedded specification context; restart in a fresh \
        process without external overrides or unexpected cache files"
            .to_owned(),
    )
}

fn identity(proof: specs::BundleProof) -> VerifiedBundledContext {
    VerifiedBundledContext { home: proof.home, bundle_id: specs::bundle_id() }
}

/// Checks the closed embedded manifest without initializing native state. Use for a freshly spawned worker;
/// this deliberately does not attest the calling process's already cached native context.
pub fn verify_bundled_specifications() -> Result<VerifiedBundledContext, Error> {
    let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    specs::verify_bundled().map(identity).map_err(|_| invalid())
}

/// Checks selected bundled bytes AND the source of every supported native-open attempt in this process.
/// Attempts are recorded before entering C, including attempts whose initialization subsequently fails.
/// Independent unsafe C ABI initialization outside these Rust wrappers is unsupported by this proof boundary.
pub fn require_verified_bundled_native_context() -> Result<VerifiedBundledContext, Error> {
    let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    require_verified_bundled_native_context_locked()
}

// The caller holds FFI_LOCK so checking and native initialization share one serialization boundary.
pub(crate) fn require_verified_bundled_native_context_locked() -> Result<VerifiedBundledContext, Error> {
    let proof = specs::verify_bundled().map_err(|_| invalid())?;
    let state = NATIVE_CONTEXT.lock().unwrap_or_else(|poison| poison.into_inner());
    if !state.accepts(&proof.home) {
        return Err(invalid());
    }
    Ok(identity(proof))
}

impl Decompiler {
    /// Checks named consumer measurements under the same exact bundled-context boundary as checked layouts.
    /// The API must separately constrain these records using retained producer evidence; matching metadata
    /// (including consumer alignments) is not authentication or producer layout proof.
    pub fn verify_bundled_named_types_counterpart(
        &self,
        language_id: &str,
        organization: crate::DataOrganization,
        expected: &[crate::NamedType],
    ) -> Result<(), Error> {
        crate::named_assertions::validate_named_types(language_id, organization, expected)?;
        let before = require_verified_bundled_native_context()?;
        self.assert_named_types(language_id, organization, expected)?;
        if require_verified_bundled_native_context()? != before {
            return Err(invalid());
        }
        Ok(())
    }

    /// Earns a checked counterpart proof, separately measuring native facts before the whole-layout assertion.
    /// Expected leaf names/categories describe the canonical declaration actually parsed, not producer display
    /// names. Missing producer facts must remain missing in the caller's independently retained producer DTO.
    pub fn verify_bundled_plain_struct_counterpart(
        &self,
        expected: &crate::layout::PlainStructLayout,
    ) -> Result<(), Error> {
        let before = require_verified_bundled_native_context()?;
        expected.validate()?;
        let measured = self.inspect_plain_struct(&expected.name)?;
        if measured != *expected {
            return Err(Error::Ghidra(
                "checked native counterpart differs from the producer-constrained declaration".to_owned(),
            ));
        }
        self.assert_plain_struct_layout(&measured)?;
        if require_verified_bundled_native_context()? != before {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Called only while FFI_LOCK is held, immediately before the first possible native initialization side effect.
pub(crate) fn begin_native_attempt(home: &Path) -> Option<specs::BundleProof> {
    let proof = specs::verify_bundled()
        .ok()
        .filter(|proof| home.to_str().is_some() && home.canonicalize().ok().as_ref() == Some(&proof.home));
    let mut state = NATIVE_CONTEXT.lock().unwrap_or_else(|poison| poison.into_inner());
    state.record(home.canonicalize().ok(), proof.is_some());
    proof
}

pub(crate) fn finish_native_attempt(before: Option<specs::BundleProof>) {
    let stable = before.is_some_and(|before| specs::verify_bundled().ok().as_ref() == Some(&before));
    if !stable {
        NATIVE_CONTEXT.lock().unwrap_or_else(|poison| poison.into_inner()).verified_bundled = false;
    }
}

pub(crate) fn failed_native_attempt() {
    NATIVE_CONTEXT.lock().unwrap_or_else(|poison| poison.into_inner()).verified_bundled = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sha256_matches_independent_standard_vectors_with_fragmented_updates() {
        for (input, expected) in [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut hash = ManifestSha256::new();
            for byte in input.as_bytes() {
                hash.update(std::slice::from_ref(byte));
            }
            assert_eq!(rampage_arch::hex::bytes(&hash.finish()), expected);
        }
        let mut hash = ManifestSha256::new();
        for _ in 0..1000 {
            hash.update(&[b'a'; 1000]);
        }
        assert_eq!(
            rampage_arch::hex::bytes(&hash.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn an_unverified_or_failed_first_attempt_cannot_be_upgraded_by_a_later_bundle() {
        let bundle = PathBuf::from("bundled");
        for first in [bundle.clone(), PathBuf::from("external")] {
            let mut state = NativeContext::default();
            state.record(Some(first), false);
            state.record(Some(bundle.clone()), true);
            assert!(!state.accepts(&bundle));
        }
        let mut state = NativeContext::default();
        state.record(Some(bundle.clone()), true);
        assert!(state.accepts(&bundle));
        state.record(Some(PathBuf::from("external")), false);
        state.record(Some(bundle.clone()), true);
        assert!(!state.accepts(&bundle));
    }
}

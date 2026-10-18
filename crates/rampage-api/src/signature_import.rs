//! Read-only admission of explicitly selected user signature databases.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use rampage_arch::Arch;
use rampage_signatures::SignatureDb;

use crate::files::{read_open_bounded, size_label};
use crate::{ApiError, FuzzyBuildReport, FuzzyBuildRequest, FuzzySuggestRequest, FuzzySuggestions, Project};

const MAX_IMPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;

/// Load a user database without executing tools or writing project annotations.
///
/// `.pat` selects bounded FLIRT PAT text using the target's supplied architecture; `.json` and
/// extensionless paths select native JSON, and `.gz` selects the native gzip format (not gzipped PAT).
/// Input files must be regular, non-symlink files: PAT/gzip sources are capped at 16 MiB and native JSON
/// at 64 MiB (the core direct-JSON limit, narrower than the legacy path helper's 256 MiB cap).
/// Gzip's expanded input is additionally bounded by the signature crate's 256 MiB JSON limit.
/// No format is inferred from file contents. Final-component symlinks, including legacy JSON ones, are refused.
///
/// PAT supports a 32-byte prefix, CRC, public/local symbols and a contiguous tail. References, negative
/// offsets, unsupported symbol flags and dumpsig tail tuples fail atomically with a PAT line/reason error.
/// `.fidbf` requires a separate explicitly configured trusted JVM/Ghidra import path; this loader never
/// launches Ghidra. Other extensions are rejected rather than interpreted as JSON.
pub fn load_signature_database(path: &Path, arch: Arch) -> Result<SignatureDb, ApiError> {
    let extension = path.extension().map(|value| value.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        None | Some("json") => {
            let file = open_database(path, MAX_JSON_BYTES)?;
            let text = read_open_bounded(file, path, MAX_JSON_BYTES, "signature database")
                .map_err(|error| parse_error(path, error))?;
            SignatureDb::from_json(&text).map_err(|error| parse_error(path, error))
        }
        Some("pat") => {
            let file = open_database(path, MAX_IMPORT_BYTES)?;
            let text = read_open_bounded(file, path, MAX_IMPORT_BYTES, "signature database")
                .map_err(|error| parse_error(path, error))?;
            SignatureDb::from_pat(arch, text.as_bytes()).map_err(|error| parse_error(path, error))
        }
        Some("gz") => {
            let file = open_database(path, MAX_IMPORT_BYTES)?;
            let mut bytes = Vec::new();
            file.take(MAX_IMPORT_BYTES + 1).read_to_end(&mut bytes).map_err(|error| parse_error(path, error))?;
            if bytes.len() as u64 > MAX_IMPORT_BYTES {
                return Err(parse_error(path, format!("larger than {}", size_label(MAX_IMPORT_BYTES))));
            }
            SignatureDb::from_gzip(&bytes).map_err(|error| parse_error(path, error))
        }
        Some("fidbf") => Err(parse_error(
            path,
            "FID import requires an explicitly configured trusted JVM/Ghidra path; no external tool was executed",
        )),
        Some(_) => Err(parse_error(path, "unsupported extension; use .pat, .json, .gz or extensionless native JSON")),
    }
}

fn parse_error(path: &Path, reason: impl std::fmt::Display) -> ApiError {
    ApiError::Invalid(format!("cannot load signature database {path:?}: {}", reason.to_string().escape_debug()))
}

impl Project {
    /// Read a bounded standalone fuzzy database and explicit cohort/entry request, then suggest only.
    /// Neither loading nor querying creates annotations. Exact application must occur after this succeeds.
    pub fn suggest_fuzzy_signature_files(
        &self,
        database: &Path,
        request: &Path,
        user_exact: Option<&SignatureDb>,
    ) -> Result<FuzzySuggestions, ApiError> {
        let bytes = read_signature_text(database, MAX_JSON_BYTES)?;
        let database = rampage_signatures::fuzzy::FuzzyDb::load_json(bytes.as_bytes())
            .map_err(|error| parse_error(database, error))?;
        let text = read_signature_text(request, MAX_IMPORT_BYTES)?;
        let request: FuzzySuggestRequest = serde_json::from_str(&text).map_err(|error| parse_error(request, error))?;
        self.suggest_fuzzy_signatures(&database, user_exact, &request)
    }

    /// Build secondary evidence from an explicit source-label/provenance request without writing a database.
    pub fn build_fuzzy_signature_file(&self, request: &Path) -> Result<FuzzyBuildReport, ApiError> {
        let text = read_signature_text(request, MAX_IMPORT_BYTES)?;
        let request: FuzzyBuildRequest = serde_json::from_str(&text).map_err(|error| parse_error(request, error))?;
        self.build_fuzzy_signatures(&request)
    }
}

fn read_signature_text(path: &Path, max: u64) -> Result<String, ApiError> {
    read_open_bounded(open_database(path, max)?, path, max, "signature database")
        .map_err(|error| parse_error(path, error))
}

#[cfg(any(unix, windows))]
fn open_database(path: &Path, max: u64) -> Result<File, ApiError> {
    let invalid = |reason: String| {
        ApiError::Invalid(format!(
            "cannot read signature database {}: {}",
            path.to_string_lossy().escape_debug(),
            reason.escape_debug()
        ))
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|error| invalid(error.to_string()))?;
    if !metadata.is_file() {
        return Err(invalid("not a regular file".to_owned()));
    }
    if metadata.len() > max {
        return Err(invalid(format!("larger than {}", size_label(max))));
    }
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        File::from(rustix::fs::open(path, flags, Mode::empty()).map_err(|error| invalid(error.to_string()))?)
    };
    #[cfg(windows)]
    let file = open_windows_database(path).map_err(|error| invalid(error.to_string()))?;
    let opened = file.metadata().map_err(|error| invalid(error.to_string()))?;
    if !opened.is_file() {
        return Err(invalid("not a regular file".to_owned()));
    }
    if opened.len() > max {
        return Err(invalid(format!("larger than {}", size_label(max))));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_database(path: &Path, _max: u64) -> Result<File, ApiError> {
    Err(parse_error(path, "safe signature database reads are unsupported on this platform"))
}

#[cfg(windows)]
fn open_windows_database(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileType"]
        fn get_file_type(file: *mut std::ffi::c_void) -> u32;
    }
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_SHARE_READ: u32 = 1;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    // SAFETY: this handle belongs to the live File; the query does not take ownership.
    let kind = unsafe { get_file_type(file.as_raw_handle()) };
    if kind != FILE_TYPE_DISK || file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular non-reparse disk file"));
    }
    Ok(file)
}

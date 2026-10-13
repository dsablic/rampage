//! Bounded reads of files a caller (a person or an agent) names: only regular files and only up to a cap, so that
//! a path such as `/dev/zero` or a FIFO can neither exhaust memory nor block.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::ApiError;

const MIB: u64 = 1024 * 1024;
/// The largest signature database (JSON) read from a path.
pub const MAX_SIGNATURE_DB_BYTES: u64 = 256 * MIB;
/// The largest PeID `userdb.txt` read from a path.
pub const MAX_PEID_BYTES: u64 = 16 * MIB;
/// The largest single YARA or capa rule file read from a data pack.
pub const MAX_RULE_FILE_BYTES: u64 = 16 * MIB;
/// The largest data-pack manifest read from a path.
pub const MAX_PACK_MANIFEST_BYTES: u64 = MIB;

/// The UTF-8 text of the regular file at `path`, refusing anything else or anything over `max` bytes. `what` names
/// the file in errors, beside its path.
pub fn read_bounded(path: &Path, max: u64, what: &str) -> Result<String, ApiError> {
    let invalid = |reason: String| ApiError::Invalid(format!("cannot read {what} {}: {reason}", path.display()));
    // Checked before opening: opening a FIFO for reading blocks until a writer appears.
    let metadata = std::fs::metadata(path).map_err(|error| invalid(error.to_string()))?;
    if !metadata.is_file() {
        return Err(invalid("not a regular file".to_owned()));
    }
    let file = File::open(path).map_err(|error| invalid(error.to_string()))?;
    if !file.metadata().map_err(|error| invalid(error.to_string()))?.is_file() {
        return Err(invalid("not a regular file".to_owned()));
    }
    let too_large = || invalid(format!("larger than {}", size_label(max)));
    if metadata.len() > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(|error| invalid(error.to_string()))?;
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(|_| invalid("not UTF-8 text".to_owned()))
}

fn size_label(bytes: u64) -> String {
    if bytes >= MIB && bytes.is_multiple_of(MIB) { format!("{} MiB", bytes / MIB) } else { format!("{bytes} bytes") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_bounded_regular_files() {
        let directory = std::env::temp_dir().join(format!("rampage-read-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("db.json");
        std::fs::write(&file, "0123456789").unwrap();
        assert_eq!(read_bounded(&file, 10, "test file").unwrap(), "0123456789");

        let error = read_bounded(&file, 9, "test file").unwrap_err().to_string();
        assert!(error.contains("test file") && error.contains("db.json") && error.contains("larger than 9 bytes"));
        let error = read_bounded(Path::new("/dev/zero"), MAX_PEID_BYTES, "PeID database").unwrap_err().to_string();
        assert_eq!(error, "cannot read PeID database /dev/zero: not a regular file");
        assert!(read_bounded(&directory, MIB, "test file").unwrap_err().to_string().contains("not a regular file"));
        assert!(read_bounded(&directory.join("missing"), MIB, "test file").is_err());
        std::fs::write(&file, [0xff, 0xfe]).unwrap();
        assert!(read_bounded(&file, MIB, "test file").unwrap_err().to_string().ends_with("not UTF-8 text"));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

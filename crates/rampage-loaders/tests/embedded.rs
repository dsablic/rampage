use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::{Binary, Embedded, LoadError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// Bytes that start no executable header.
fn junk(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|index| b'a' + (index as u8).wrapping_add(seed) % 26).collect()
}

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file(name: &str, bytes: &[u8]) -> TempFile {
    let path = std::env::temp_dir().join(format!("rampage-embedded-{}-{name}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

/// The fixture between odd-sized junk, and its offset.
fn embed(tag: &str, name: &str) -> (TempFile, u64, u64) {
    let image = std::fs::read(fixture(name)).unwrap();
    let mut file = junk(1001, 3);
    let offset = file.len() as u64;
    file.extend(&image);
    file.extend(junk(777, 5));
    (temp_file(&format!("{tag}-{name}"), &file), offset, image.len() as u64)
}

fn without_embedded(binary: &Binary) -> serde_json::Value {
    let mut value = serde_json::to_value(binary).unwrap();
    value.as_object_mut().unwrap().remove("embedded");
    value
}

#[test]
fn an_embedded_image_loads_as_the_extracted_file_does() {
    let names = ["hello-x64-dyn.elf", "hello-x64.exe", "hello-x64.macho", "hello-arm64.macho", "hello-universal.macho"];
    for name in names {
        let (temp, offset, size) = embed("same", name);
        let direct = Binary::open(fixture(name)).unwrap();
        let embedded = Binary::open_at(&temp.0, offset, None).unwrap();
        assert_eq!(without_embedded(&embedded), without_embedded(&direct), "{name}");
        assert_eq!(embedded.image_bytes(), direct.image_bytes(), "{name}");
        let file_size = std::fs::metadata(&temp.0).unwrap().len();
        assert_eq!(embedded.embedded, Some(Embedded { offset, size, file_size }), "{name}");
        assert!(!embedded.function_starts.is_empty() || !embedded.symbols.is_empty(), "{name}");
    }
}

#[test]
fn an_embedded_universal_binary_selects_the_requested_slice() {
    let (temp, offset, _) = embed("slice", "hello-universal.macho");
    let direct = Binary::open_with(fixture("hello-universal.macho"), Some(Arch::Aarch64)).unwrap();
    let embedded = Binary::open_at_with(&temp.0, offset, None, Some(Arch::Aarch64)).unwrap();
    assert_eq!(embedded.arch, Arch::Aarch64);
    assert_eq!(without_embedded(&embedded), without_embedded(&direct));
    let missing = Binary::open_at_with(&temp.0, offset, None, Some(Arch::Mips)).unwrap_err();
    assert!(matches!(missing, LoadError::Unsupported(_)), "{missing:?}");
}

#[test]
fn an_explicit_length_to_the_end_of_the_file_reports_the_trailing_bytes_as_overlay() {
    let (temp, offset, size) = embed("overlay", "hello-x64.exe");
    let file_size = std::fs::metadata(&temp.0).unwrap().len();
    let binary = Binary::open_at(&temp.0, offset, Some(file_size - offset)).unwrap();
    let overlay = binary.overlay.expect("the junk after the image is overlay");
    assert_eq!((overlay.offset, overlay.size, overlay.file_offset), (size, 777, offset + size));
}

#[test]
fn invalid_locations_are_errors() {
    let (temp, offset, _) = embed("invalid", "hello-x64-dyn.elf");
    let file_size = std::fs::metadata(&temp.0).unwrap().len();
    let malformed = |result: Result<Binary, LoadError>| matches!(result, Err(LoadError::Malformed(_)));
    let location = |result: Result<Binary, LoadError>| matches!(result, Err(LoadError::Location(_)));
    assert!(malformed(Binary::open_at(&temp.0, 0, None)), "junk has no header");
    assert!(malformed(Binary::open_at(&temp.0, offset + 1, None)), "one byte into the header");
    assert!(location(Binary::open_at(&temp.0, file_size, None)), "at the end of the file");
    assert!(location(Binary::open_at(&temp.0, u64::MAX, None)), "far past the end");
    assert!(location(Binary::open_at(&temp.0, offset, Some(u64::MAX))), "length overflows");
    assert!(location(Binary::open_at(&temp.0, offset, Some(0))), "empty");
    assert!(location(Binary::open_at(&temp.0, offset, Some(file_size - offset + 1))), "length past the end");
    let error = Binary::open_at(&temp.0, offset, Some(u64::MAX)).unwrap_err().to_string();
    assert!(error.contains("overflows"), "{error}");
}

#[test]
fn a_truncated_embedded_header_is_rejected() {
    let image = std::fs::read(fixture("hello-x64-dyn.elf")).unwrap();
    let mut file = junk(513, 1);
    file.extend(&image[..40]);
    let temp = temp_file("truncated", &file);
    let error = Binary::open_at(&temp.0, 513, None).unwrap_err();
    assert!(matches!(error, LoadError::Malformed(ref reason) if reason.contains("truncated")), "{error:?}");
}

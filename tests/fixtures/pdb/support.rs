use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/pdb").join(name)
}

pub struct TempFiles(PathBuf);

impl TempFiles {
    pub fn new() -> Self {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-pdb-test-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[allow(dead_code)]
    pub fn fifo(&self, name: &str) -> PathBuf {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        #[cfg(target_os = "macos")]
        type Mode = u16;
        #[cfg(target_os = "linux")]
        type Mode = u32;
        unsafe extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: Mode) -> i32;
        }
        let path = self.0.join(name);
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is NUL-terminated and lives through the call; Mode matches the host's mode_t.
        assert_eq!(unsafe { mkfifo(c_path.as_ptr(), 0o600) }, 0);
        path
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&self.0).unwrap();
    }
}

pub fn uint(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

pub fn stream_offset(bytes: &[u8], stream: usize, within: usize) -> usize {
    let page_size = uint(bytes, 32);
    let directory_length = uint(bytes, 44);
    let block_map = uint(bytes, 52) * page_size;
    let mut directory = Vec::new();
    for index in 0..directory_length.div_ceil(page_size) {
        let page = uint(bytes, block_map + index * 4) * page_size;
        directory.extend_from_slice(&bytes[page..page + page_size]);
    }
    let streams = uint(&directory, 0);
    assert!(stream < streams);
    let mut pages_before = 0;
    for index in 0..stream {
        let size = uint(&directory, 4 + index * 4);
        if size != u32::MAX as usize {
            pages_before += size.div_ceil(page_size);
        }
    }
    let page_index = pages_before + within / page_size;
    uint(&directory, 4 + streams * 4 + page_index * 4) * page_size + within % page_size
}

pub fn module_stream(bytes: &[u8]) -> usize {
    let offset = stream_offset(bytes, 3, 64 + 34);
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize
}

pub fn rsds_offset(bytes: &[u8]) -> usize {
    bytes.windows(4).position(|bytes| bytes == b"RSDS").unwrap()
}

#[allow(dead_code)]
pub fn corrupt_local_offset(bytes: &[u8], section: u16, offset: u32) -> Vec<u8> {
    let mut corrupt = bytes.to_vec();
    let start = stream_offset(bytes, module_stream(bytes), 0);
    let name = bytes[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let procedure = start + name - 39;
    assert_eq!(u16::from_le_bytes(bytes[procedure + 2..procedure + 4].try_into().unwrap()), 0x110f);
    corrupt[procedure + 32..procedure + 36].copy_from_slice(&offset.to_le_bytes());
    corrupt[procedure + 36..procedure + 38].copy_from_slice(&section.to_le_bytes());
    corrupt
}

/// Changes only kind and numeric-prefix bytes in a real procedure; not a compiler-generated constant record.
#[allow(dead_code)]
pub fn corrupt_local_constant_numeric_prefix(bytes: &[u8], kind: u16, prefix: u16) -> Vec<u8> {
    let mut corrupt = bytes.to_vec();
    let start = stream_offset(bytes, module_stream(bytes), 0);
    let name = bytes[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    let procedure = start + name - 39;
    assert_eq!(u16::from_le_bytes(bytes[procedure + 2..procedure + 4].try_into().unwrap()), 0x110f);
    corrupt[procedure + 2..procedure + 4].copy_from_slice(&kind.to_le_bytes());
    corrupt[procedure + 8..procedure + 10].copy_from_slice(&prefix.to_le_bytes());
    corrupt
}

#[allow(dead_code)]
pub fn corrupt_text_permissions(bytes: &[u8], remove: u32) -> Vec<u8> {
    let mut corrupt = bytes.to_vec();
    let nt = uint(bytes, 0x3c);
    let optional_size = u16::from_le_bytes(bytes[nt + 20..nt + 22].try_into().unwrap()) as usize;
    let flags = nt + 24 + optional_size + 36;
    assert_eq!(uint(bytes, flags), 0x60000020);
    corrupt[flags..flags + 4].copy_from_slice(&(0x60000020u32 & !remove).to_le_bytes());
    corrupt
}

fn streams(bytes: &[u8]) -> Vec<Option<Vec<u8>>> {
    let page_size = uint(bytes, 32);
    let map = uint(bytes, 52) * page_size;
    let directory = uint(bytes, map) * page_size;
    let count = uint(bytes, directory);
    (0..count)
        .map(|index| {
            let size = uint(bytes, directory + 4 + index * 4);
            if size == u32::MAX as usize {
                return None;
            }
            let mut data = Vec::with_capacity(size);
            for within in (0..size).step_by(page_size) {
                let offset = stream_offset(bytes, index, within);
                data.extend_from_slice(&bytes[offset..offset + (size - within).min(page_size)]);
            }
            Some(data)
        })
        .collect()
}

fn repack(original: &[u8], streams: &[Option<Vec<u8>>]) -> Vec<u8> {
    let page_size = 4096;
    let mut bytes = vec![0; 3 * page_size];
    let mut directory = (streams.len() as u32).to_le_bytes().to_vec();
    for stream in streams {
        directory.extend_from_slice(&stream.as_ref().map_or(u32::MAX, |stream| stream.len() as u32).to_le_bytes());
    }
    for stream in streams.iter().flatten() {
        for data in stream.chunks(page_size) {
            directory.extend_from_slice(&((bytes.len() / page_size) as u32).to_le_bytes());
            let start = bytes.len();
            bytes.resize(start + page_size, 0);
            bytes[start..start + data.len()].copy_from_slice(data);
        }
    }
    finish_msf(original, bytes, &directory, page_size, 0)
}

fn finish_msf(original: &[u8], mut bytes: Vec<u8>, directory: &[u8], page_size: usize, minimum: usize) -> Vec<u8> {
    let first_directory_page = bytes.len() / page_size;
    for data in directory.chunks(page_size) {
        let start = bytes.len();
        bytes.resize(start + page_size, 0);
        bytes[start..start + data.len()].copy_from_slice(data);
    }
    let map: Vec<u8> = (0..directory.len().div_ceil(page_size))
        .flat_map(|index| ((first_directory_page + index) as u32).to_le_bytes())
        .collect();
    let first_map_page = bytes.len() / page_size;
    for data in map.chunks(page_size) {
        let start = bytes.len();
        bytes.resize(start + page_size, 0);
        bytes[start..start + data.len()].copy_from_slice(data);
    }
    bytes.resize(bytes.len().max(minimum.div_ceil(page_size) * page_size), 0);
    bytes[..32].copy_from_slice(&original[..32]);
    bytes[32..36].copy_from_slice(&(page_size as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&1u32.to_le_bytes());
    let pages = (bytes.len() / page_size) as u32;
    bytes[40..44].copy_from_slice(&pages.to_le_bytes());
    bytes[44..48].copy_from_slice(&(directory.len() as u32).to_le_bytes());
    for index in 0..map.len().div_ceil(page_size) {
        let at = 52 + index * 4;
        bytes[at..at + 4].copy_from_slice(&((first_map_page + index) as u32).to_le_bytes());
    }
    bytes
}

/// Corrupt derived containers only: aliased page lists are not compiler-generated acceptance fixtures.
#[allow(dead_code)]
pub fn corrupt_aliased_msf(original: &[u8], sizes: &[u32], page_size: usize, minimum: usize) -> Vec<u8> {
    let mut directory = (sizes.len() as u32).to_le_bytes().to_vec();
    for &size in sizes {
        directory.extend_from_slice(&size.to_le_bytes());
    }
    for &size in sizes {
        if size == u32::MAX {
            continue;
        }
        for _ in 0..(size as usize).div_ceil(page_size) {
            directory.extend_from_slice(&16u32.to_le_bytes());
        }
    }
    finish_msf(original, vec![0; 17 * page_size], &directory, page_size, minimum)
}

/// Appends hostile S_ALIGN/S_SKIP records to real symbol bytes; not a new compiler-generated PDB.
#[allow(dead_code)]
pub fn corrupt_skipped_symbols(original: &[u8], module: bool, kind: u16, count: usize) -> Vec<u8> {
    let mut streams = streams(original);
    let index = if module { module_stream(original) } else { uint(original, stream_offset(original, 3, 20)) & 0xffff };
    let size =
        if module { uint(streams[3].as_ref().unwrap(), 64 + 36) } else { streams[index].as_ref().unwrap().len() };
    let old = streams[index].take().unwrap();
    let mut data = old[..size].to_vec();
    for _ in 0..count {
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&kind.to_le_bytes());
    }
    data.extend_from_slice(&old[size..]);
    streams[index] = Some(data);
    if module {
        streams[3].as_mut().unwrap()[64 + 36..64 + 40].copy_from_slice(&((size + count * 4) as u32).to_le_bytes());
    }
    repack(original, &streams)
}

#[allow(dead_code)]
pub fn corrupt_module_lookup_work(original: &[u8]) -> Vec<u8> {
    let mut streams = streams(original);
    let old = streams[3].take().unwrap();
    let mut end = 128;
    for _ in 0..2 {
        end += old[end..].iter().position(|&byte| byte == 0).unwrap() + 1;
    }
    end = (end + 3) & !3;
    let mut module = old[64..end].to_vec();
    module[34..36].copy_from_slice(&32767u16.to_le_bytes());
    module[36..48].fill(0);
    let old_end = 64 + uint(&old, 24);
    let mut dbi = old[..64].to_vec();
    for _ in 0..300 {
        dbi.extend_from_slice(&module);
    }
    let length = dbi.len() - 64;
    dbi[24..28].copy_from_slice(&(length as u32).to_le_bytes());
    dbi.extend_from_slice(&old[old_end..]);
    streams[3] = Some(dbi);
    streams.resize(32768, None);
    streams[32767] = Some(Vec::new());
    repack(original, &streams)
}

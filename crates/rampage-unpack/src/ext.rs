//! ext2, ext3 and ext4 (extents included) through ext4-view, which is written for untrusted input.

use ext4_view::{Ext4, Ext4Read, PathBuf};

use crate::error::{Result, UnpackError};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::Limits;
use crate::source::Source;

struct SourceRead(Source);

impl Ext4Read for SourceRead {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(self.0.read_at(start_byte, dst)?)
    }
}

fn malformed(error: impl std::fmt::Display) -> UnpackError {
    UnpackError::malformed("ext", error.to_string())
}

pub struct Ext {
    fs: Ext4,
    entries: Vec<Entry>,
    /// The ext4-view path of each entry, to reopen it.
    paths: Vec<PathBuf>,
    notes: Vec<String>,
}

impl Ext {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let fs = Ext4::load(Box::new(SourceRead(source))).map_err(malformed)?;
        let mut entries = Vec::new();
        let mut paths = Vec::new();
        // Depth-first with an explicit stack: a directory entry naming an ancestor would loop forever, so the
        // directory depth and the entry count are both capped.
        let root = PathBuf::try_from("/").map_err(malformed)?;
        let mut pending = vec![(root, 0usize)];
        while let Some((directory, depth)) = pending.pop() {
            let mut children = Vec::new();
            for item in fs.read_dir(&directory).map_err(malformed)? {
                let item = item.map_err(malformed)?;
                let name = item.file_name();
                if name.as_ref() == b"." || name.as_ref() == b".." {
                    continue;
                }
                if entries.len() >= limits.max_entries {
                    return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
                }
                let path = item.path();
                let metadata = item.metadata().map_err(malformed)?;
                let kind = file_kind(metadata.file_type());
                let link = if kind == EntryKind::Symlink {
                    let target = fs.read_link(&path).map_err(malformed)?;
                    Some(String::from_utf8_lossy(target.as_ref()).into_owned())
                } else {
                    None
                };
                let text = String::from_utf8_lossy(path.as_ref());
                entries.push(Entry {
                    path: text.trim_start_matches('/').to_owned(),
                    kind,
                    size: if kind == EntryKind::File { metadata.len() } else { 0 },
                    mode: u32::from(metadata.mode()) & 0o7777,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    link,
                    note: None,
                });
                if kind == EntryKind::Dir {
                    if depth + 1 >= limits.max_path_depth {
                        return Err(UnpackError::Limit(format!(
                            "directories nested deeper than {} levels",
                            limits.max_path_depth
                        )));
                    }
                    children.push((path.clone(), depth + 1));
                }
                paths.push(path);
            }
            // Visit subdirectories in listing order.
            pending.extend(children.into_iter().rev());
        }
        let mut notes = Vec::new();
        if let Ok(label) = fs.label().to_str()
            && !label.is_empty()
        {
            notes.push(format!("label {label}"));
        }
        Ok(Self { fs, entries, paths, notes })
    }
}

fn file_kind(kind: ext4_view::FileType) -> EntryKind {
    if kind.is_regular_file() {
        EntryKind::File
    } else if kind.is_dir() {
        EntryKind::Dir
    } else if kind.is_symlink() {
        EntryKind::Symlink
    } else if kind.is_char_dev() {
        EntryKind::CharDevice
    } else if kind.is_block_dev() {
        EntryKind::BlockDevice
    } else if kind.is_fifo() {
        EntryKind::Fifo
    } else if kind.is_socket() {
        EntryKind::Socket
    } else {
        EntryKind::Other
    }
}

impl Image for Ext {
    fn format(&self) -> Format {
        Format::Ext
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn read(&self, index: usize, limit: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let entry = self.entries.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        if entry.kind != EntryKind::File {
            return Err(UnpackError::Invalid(format!("`{}` is not a file", entry.path)));
        }
        if entry.size > limit {
            return Err(UnpackError::Limit(format!("`{}` is larger than max_file_bytes ({limit})", entry.path)));
        }
        let mut file = self.fs.open(&self.paths[index]).map_err(malformed)?;
        let mut buffer = vec![0; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = file.read_bytes(&mut buffer).map_err(malformed)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > entry.size {
                return Err(malformed(format!("`{}` holds more than its size", entry.path)));
            }
            sink(&buffer[..read])?;
        }
        Ok(())
    }
}

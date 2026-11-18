//! UBIFS, from a UBI volume or a bare dump of its LEBs back to back: the superblock, the newest master node, the
//! index B-tree from its root, then the journal written since the last commit replayed over it. Inode, directory
//! entry and data nodes give the tree; data is uncompressed, LZO, zlib (raw deflate) or zstd. Extended attributes
//! are not read. Layouts follow `ubifs-media.h`.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::codec::{Codec, decompress};
use crate::error::{Result, UnpackError};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::{Budget, Limits};
use crate::source::Source;
use crate::ubi::crc32;

const FORMAT: &str = "ubifs";
const MAGIC: u32 = 0x0610_1831;
/// The common header every node starts with.
const CH: usize = 24;
const INO_NODE: u8 = 0;
const DATA_NODE: u8 = 1;
const DENT_NODE: u8 = 2;
const XENT_NODE: u8 = 3;
const TRUN_NODE: u8 = 4;
const PAD_NODE: u8 = 5;
const SB_NODE: u8 = 6;
const MST_NODE: u8 = 7;
const REF_NODE: u8 = 8;
const IDX_NODE: u8 = 9;
const CS_NODE: u8 = 10;
const INO_SIZE: usize = 160;
const DENT_SIZE: usize = 56;
const DATA_SIZE: usize = 48;
const MST_SIZE: usize = 512;
const BLOCK: u64 = 4096;
const ROOT_INODE: u64 = 1;
const MASTER_LEB: u32 = 1;
const LOG_LEB: u32 = 3;
/// Index levels: a fanout of 8 reaches billions of nodes in 12.
const MAX_LEVEL: u16 = 64;
const MAX_INDEX_NODES: usize = 4_000_000;
/// Inodes, directory entries and data blocks kept, index and journal together.
const MAX_LEAVES: usize = 8_000_000;
/// The largest node read: index nodes of a wide fanout; data nodes are at most 4 KiB and change.
const MAX_NODE: u64 = 1 << 20;
const CRYPT_FLAG: u32 = 0x40;
/// Input charged to the ratio meter for a file's holes, which UBIFS stores as missing data nodes.
const NOMINAL_HOLE_INPUT: u64 = 4096;

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from(le32(bytes, at)) | (u64::from(le32(bytes, at + 4)) << 32)
}

/// Where a node lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Loc {
    lnum: u32,
    offs: u32,
    len: u32,
}

impl std::fmt::Display for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LEB {} offset {}", self.lnum, self.offs)
    }
}

/// A node key in the simple format: the inode number, then the key type and a block number or name hash.
#[derive(Debug, Clone, Copy)]
struct Key {
    inum: u64,
    kind: u8,
    value: u32,
}

fn key(bytes: &[u8], at: usize) -> Key {
    let second = le32(bytes, at + 4);
    Key { inum: u64::from(le32(bytes, at)), kind: (second >> 29) as u8, value: second & 0x1fff_ffff }
}

#[derive(Debug, Clone)]
struct Inode {
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: u32,
    /// Inline data: a symlink's target or a device number.
    data: Vec<u8>,
}

fn parse_inode(node: &[u8]) -> Result<(u64, Inode, u32)> {
    if node.len() < INO_SIZE {
        return Err(malformed("inode node is too short"));
    }
    let data_len = le32(node, 112) as usize;
    let data = node.get(INO_SIZE..INO_SIZE.saturating_add(data_len)).ok_or_else(|| malformed("inode data overruns"))?;
    let inode = Inode {
        size: le64(node, 48),
        mode: le32(node, 104),
        uid: le32(node, 96),
        gid: le32(node, 100),
        flags: le32(node, 108),
        data: if data_len <= BLOCK as usize { data.to_vec() } else { Vec::new() },
    };
    Ok((key(node, CH).inum, inode, le32(node, 92)))
}

/// A directory entry: the parent's inode number and name, then the target inode (0 for a deletion) and its type.
fn parse_dent(node: &[u8]) -> Result<(u64, Vec<u8>, u64)> {
    if node.len() < DENT_SIZE {
        return Err(malformed("directory entry node is too short"));
    }
    let nlen = usize::from(le16(node, 50));
    let name = node.get(DENT_SIZE..DENT_SIZE + nlen).ok_or_else(|| malformed("directory entry name overruns"))?;
    Ok((key(node, CH).inum, name.to_vec(), le64(node, 40)))
}

/// What the index and the journal say, merged.
#[derive(Default)]
struct Tree {
    inodes: HashMap<u64, Inode>,
    dents: HashMap<(u64, Vec<u8>), u64>,
    data: BTreeMap<(u64, u32), Loc>,
    index_nodes: usize,
    xattrs: usize,
}

impl Tree {
    fn leaves(&self) -> usize {
        self.inodes.len() + self.dents.len() + self.data.len()
    }
}

pub struct Ubifs {
    source: Source,
    leb_size: u64,
    leb_cnt: u32,
    min_io: u64,
    tree: Tree,
    entries: Vec<Entry>,
    /// The inode of each entry.
    inums: Vec<u64>,
    notes: Vec<String>,
}

/// The nodes a LEB holds from an offset, and whether the scan stopped at a damaged node.
type Scanned = (Vec<(Loc, Vec<u8>)>, bool);

fn align8(value: u64) -> u64 {
    value.div_ceil(8) * 8
}

impl Ubifs {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let mut sb = vec![0u8; 4096.min(source.size()) as usize];
        source.read_at(0, &mut sb).map_err(|_| malformed("truncated superblock"))?;
        if sb.len() < 128 || le32(&sb, 0) != MAGIC || sb[20] != SB_NODE {
            return Err(malformed("no superblock node at the start"));
        }
        let len = le32(&sb, 16) as usize;
        if !(128..=sb.len()).contains(&len) || crc32(&sb[8..len]) != le32(&sb, 4) {
            return Err(malformed("the superblock fails its CRC"));
        }
        let (key_fmt, flags, min_io, leb_size, leb_cnt) =
            (sb[27], le32(&sb, 28), le32(&sb, 32), le32(&sb, 36), le32(&sb, 40));
        let (log_lebs, fmt_version, compr) = (le32(&sb, 56), le32(&sb, 80), le16(&sb, 84));
        if key_fmt != 0 {
            return Err(UnpackError::Unsupported(format!("UBIFS key format {key_fmt}")));
        }
        if !(4096..=(64 << 20)).contains(&leb_size) || !min_io.is_power_of_two() || min_io > leb_size {
            return Err(malformed(format!("LEB size {leb_size}, minimum I/O size {min_io}")));
        }
        if leb_cnt < LOG_LEB + 1 || log_lebs == 0 || log_lebs > leb_cnt - LOG_LEB {
            return Err(malformed(format!("{leb_cnt} LEBs with {log_lebs} for the log")));
        }
        let mut fs = Self {
            source,
            leb_size: u64::from(leb_size),
            leb_cnt,
            min_io: u64::from(min_io),
            tree: Tree::default(),
            entries: Vec::new(),
            inums: Vec::new(),
            notes: Vec::new(),
        };
        fs.notes.push(format!("LEB size {leb_size}, {leb_cnt} LEBs"));
        fs.notes.push(format!("format version {fmt_version}"));
        fs.notes.push(format!("default compression {}", compression_name(compr)));
        if flags & 0x8 != 0 {
            fs.notes.push("encryption enabled: encrypted files are listed, not decrypted".to_owned());
        }
        if flags & 0x10 != 0 {
            fs.notes.push("authenticated: HMACs and hashes are not checked, node CRCs are".to_owned());
        }
        let master = fs.master()?;
        if le32(&master, 40) & 1 != 0 {
            fs.notes.push("not unmounted cleanly".to_owned());
        }
        let root = Loc { lnum: le32(&master, 48), offs: le32(&master, 52), len: le32(&master, 56) };
        fs.walk_index(root)?;
        let (log_lnum, cmt_no) = (le32(&master, 44), le64(&master, 32));
        fs.replay(log_lnum, log_lebs, cmt_no)?;
        fs.notes.push(format!("{} index nodes", fs.tree.index_nodes));
        if fs.tree.xattrs > 0 {
            fs.notes.push(format!("{} extended attributes not read", fs.tree.xattrs));
        }
        fs.list(limits)?;
        Ok(fs)
    }

    /// The node at `loc`, whole, its magic, length, CRC and type (when `kind` is given) checked.
    fn node(&self, loc: Loc, kind: Option<u8>) -> Result<Vec<u8>> {
        let (offs, len) = (u64::from(loc.offs), u64::from(loc.len));
        if loc.lnum >= self.leb_cnt || len < CH as u64 || len > MAX_NODE || offs + len > self.leb_size {
            return Err(malformed(format!("a node reference ({loc}, {len} bytes) lies outside the LEBs")));
        }
        let at = u64::from(loc.lnum) * self.leb_size + offs;
        let mut node = vec![0u8; len as usize];
        self.source.read_at(at, &mut node).map_err(|_| {
            malformed(format!("the node at {loc} lies past the end of the image (truncated, or the LEB is unmapped)"))
        })?;
        if le32(&node, 0) != MAGIC || u64::from(le32(&node, 16)) != len {
            return Err(malformed(format!("no node of {len} bytes at {loc}")));
        }
        if crc32(&node[8..]) != le32(&node, 4) {
            return Err(malformed(format!("the node at {loc} fails its CRC")));
        }
        if let Some(kind) = kind
            && node[20] != kind
        {
            return Err(malformed(format!("the node at {loc} has type {}, not {kind}", node[20])));
        }
        Ok(node)
    }

    /// The node starting at `offs` of LEB `lnum` when one is written there, with its length checked.
    fn node_at(&self, lnum: u32, offs: u64) -> Result<Option<Vec<u8>>> {
        let mut header = [0u8; CH];
        let at = u64::from(lnum) * self.leb_size + offs;
        if offs + CH as u64 > self.leb_size || self.source.read_at(at, &mut header).is_err() {
            return Ok(None);
        }
        if le32(&header, 0) != MAGIC {
            return Ok(None);
        }
        let len = le32(&header, 16);
        let loc = Loc { lnum, offs: offs as u32, len };
        self.node(loc, None).map(Some)
    }

    /// The master node with the highest sequence number in either master LEB.
    fn master(&self) -> Result<Vec<u8>> {
        let stride = align_up(MST_SIZE as u64, self.min_io);
        let mut best: Option<Vec<u8>> = None;
        for lnum in [MASTER_LEB, MASTER_LEB + 1] {
            let mut offs = 0;
            while offs + MST_SIZE as u64 <= self.leb_size {
                let Ok(Some(node)) = self.node_at(lnum, offs) else { break };
                if node[20] == MST_NODE
                    && node.len() >= MST_SIZE
                    && best.as_ref().is_none_or(|best| le64(&node, 8) > le64(best, 8))
                {
                    best = Some(node);
                }
                offs += stride;
            }
        }
        best.ok_or_else(|| malformed("no intact master node"))
    }

    /// Walks the index B-tree from `root` with an explicit stack. Each child must sit one level below its parent
    /// and no node may be reached twice, so a forged tree can neither loop nor fan out without bound.
    fn walk_index(&mut self, root: Loc) -> Result<()> {
        let mut visited: HashSet<(u32, u32)> = HashSet::new();
        let mut pending = vec![(root, None::<u16>)];
        while let Some((loc, expected)) = pending.pop() {
            if !visited.insert((loc.lnum, loc.offs)) {
                return Err(malformed(format!("the index reaches the node at {loc} twice (a cycle)")));
            }
            if visited.len() > MAX_INDEX_NODES {
                return Err(UnpackError::Limit(format!("more than {MAX_INDEX_NODES} index nodes")));
            }
            let node = self.node(loc, Some(IDX_NODE))?;
            let (children, level) = (usize::from(le16(&node, 24)), le16(&node, 26));
            if level > MAX_LEVEL || expected.is_some_and(|expected| expected != level) {
                return Err(malformed(format!("the index node at {loc} is at level {level}, out of place")));
            }
            let room = node.len() - 28;
            if children == 0 || room % children != 0 || room / children < 20 {
                return Err(malformed(format!("the index node at {loc} has {children} branches in {room} bytes")));
            }
            let branch = room / children;
            for child in 0..children {
                let at = 28 + child * branch;
                let child_loc = Loc { lnum: le32(&node, at), offs: le32(&node, at + 4), len: le32(&node, at + 8) };
                if level > 0 {
                    pending.push((child_loc, Some(level - 1)));
                } else {
                    self.leaf(child_loc, key(&node, at + 12))?;
                }
            }
        }
        self.tree.index_nodes = visited.len();
        Ok(())
    }

    /// Records the leaf node the index points at: inodes and entries are read now, data nodes when a file is.
    fn leaf(&mut self, loc: Loc, key: Key) -> Result<()> {
        if self.tree.leaves() >= MAX_LEAVES {
            return Err(UnpackError::Limit(format!("more than {MAX_LEAVES} inodes, entries and data blocks")));
        }
        match key.kind {
            0 => {
                let (inum, inode, _) = parse_inode(&self.node(loc, Some(INO_NODE))?)?;
                self.tree.inodes.insert(inum, inode);
            }
            1 => {
                self.tree.data.insert((key.inum, key.value), loc);
            }
            2 => {
                let (parent, name, inum) = parse_dent(&self.node(loc, Some(DENT_NODE))?)?;
                self.tree.dents.insert((parent, name), inum);
            }
            3 => self.tree.xattrs += 1,
            other => return Err(malformed(format!("index key type {other} at {loc}"))),
        }
        Ok(())
    }

    /// Nodes written in LEB `lnum` from `offs`, in order, up to erased space or the first damaged node: the end of
    /// what was written before power was lost.
    fn scan(&self, lnum: u32, mut offs: u64) -> Result<Scanned> {
        let mut nodes = Vec::new();
        while offs + CH as u64 <= self.leb_size {
            let at = u64::from(lnum) * self.leb_size + offs;
            let mut byte = [0u8];
            if self.source.read_at(at, &mut byte).is_err() {
                break;
            }
            if byte[0] == 0xce {
                // Padding bytes fill gaps too small for a padding node.
                offs = align8(offs + 1);
                continue;
            }
            let node = match self.node_at(lnum, offs) {
                Ok(Some(node)) => node,
                Ok(None) => break,
                Err(_) => return Ok((nodes, true)),
            };
            let len = node.len() as u64;
            if node[20] == PAD_NODE && node.len() >= CH + 4 {
                offs += len + u64::from(le32(&node, CH));
                continue;
            }
            nodes.push((Loc { lnum, offs: offs as u32, len: len as u32 }, node));
            offs = align8(offs + len);
        }
        Ok((nodes, false))
    }

    /// Replays the journal written since the last commit over the index: the log names the bud LEBs, whose nodes
    /// newer than the commit start node win, in sequence order.
    fn replay(&mut self, log_lnum: u32, log_lebs: u32, cmt_no: u64) -> Result<()> {
        if !(LOG_LEB..LOG_LEB + log_lebs).contains(&log_lnum) {
            return Err(malformed(format!("the log head LEB {log_lnum} is outside the log")));
        }
        let (log, _) = self.scan(log_lnum, 0)?;
        let Some((_, start)) = log.first().filter(|(_, node)| node[20] == CS_NODE && node.len() >= 32) else {
            self.notes.push("journal not replayed: the log head has no commit start node".to_owned());
            return Ok(());
        };
        if le64(start, CH) != cmt_no {
            self.notes.push("journal not replayed: the log head belongs to another commit".to_owned());
            return Ok(());
        }
        let commit = le64(start, 8);
        // Each bud LEB is scanned once, from the lowest offset any reference names: a forged log cannot make the
        // scanning quadratic.
        let mut buds: BTreeMap<u32, u64> = BTreeMap::new();
        for step in 0..log_lebs {
            let lnum = LOG_LEB + (log_lnum - LOG_LEB + step) % log_lebs;
            let nodes = if step == 0 { log.clone() } else { self.scan(lnum, 0)?.0 };
            let refs: Vec<_> =
                nodes.iter().filter(|(_, node)| node[20] == REF_NODE && le64(node, 8) > commit).collect();
            if refs.is_empty() && step > 0 {
                break;
            }
            for (_, node) in refs {
                if node.len() >= CH + 12 {
                    let (lnum, offs) = (le32(node, CH), u64::from(le32(node, CH + 4)));
                    let start = buds.entry(lnum).or_insert(offs);
                    *start = (*start).min(offs);
                }
            }
        }
        let mut newer = Vec::new();
        let mut cut = 0;
        for (&lnum, &offs) in &buds {
            if lnum >= self.leb_cnt {
                return Err(malformed(format!("the log names bud LEB {lnum}, past the last LEB")));
            }
            let (nodes, damaged) = self.scan(lnum, offs)?;
            cut += usize::from(damaged);
            for (loc, node) in nodes {
                if le64(&node, 8) > commit
                    && matches!(node[20], INO_NODE | DATA_NODE | DENT_NODE | XENT_NODE | TRUN_NODE)
                {
                    if newer.len() + self.tree.leaves() >= MAX_LEAVES {
                        return Err(UnpackError::Limit(format!("more than {MAX_LEAVES} nodes")));
                    }
                    let node = if node[20] == DATA_NODE { node[..CH + 16].to_vec() } else { node };
                    newer.push((le64(&node, 8), loc, node));
                }
            }
        }
        newer.sort_by_key(|(sqnum, _, _)| *sqnum);
        for (_, loc, node) in &newer {
            match node[20] {
                INO_NODE => {
                    let (inum, inode, nlink) = parse_inode(node)?;
                    if nlink == 0 {
                        self.tree.inodes.remove(&inum);
                        let blocks: Vec<_> =
                            self.tree.data.range((inum, 0)..=(inum, u32::MAX)).map(|(k, _)| *k).collect();
                        for block in blocks {
                            self.tree.data.remove(&block);
                        }
                    } else {
                        self.tree.inodes.insert(inum, inode);
                    }
                }
                DATA_NODE => {
                    let key = key(node, CH);
                    self.tree.data.insert((key.inum, key.value), *loc);
                }
                DENT_NODE => {
                    let (parent, name, inum) = parse_dent(node)?;
                    if inum == 0 {
                        self.tree.dents.remove(&(parent, name));
                    } else {
                        self.tree.dents.insert((parent, name), inum);
                    }
                }
                TRUN_NODE if node.len() >= 56 => {
                    let (inum, new_size) = (u64::from(le32(node, CH)), le64(node, 48));
                    let first = u32::try_from(new_size.div_ceil(BLOCK)).unwrap_or(u32::MAX);
                    let blocks: Vec<_> =
                        self.tree.data.range((inum, first)..=(inum, u32::MAX)).map(|(k, _)| *k).collect();
                    for block in blocks {
                        self.tree.data.remove(&block);
                    }
                }
                _ => {}
            }
        }
        if !newer.is_empty() {
            self.notes.push(format!("journal replayed: {} nodes from {} LEBs", newer.len(), buds.len()));
        }
        if cut > 0 {
            self.notes.push(format!("journal: {cut} LEBs end in a damaged node (an interrupted write), read up to it"));
        }
        Ok(())
    }

    /// The entries, depth-first from the root directory, each directory's entries in name order.
    fn list(&mut self, limits: &Limits) -> Result<()> {
        let mut children: HashMap<u64, Vec<(&[u8], u64)>> = HashMap::new();
        for ((parent, name), inum) in &self.tree.dents {
            children.entry(*parent).or_default().push((name, *inum));
        }
        let mut entries = Vec::new();
        let mut inums = Vec::new();
        let mut first_path: HashMap<u64, String> = HashMap::new();
        let mut seen_dirs: HashSet<u64> = HashSet::from([ROOT_INODE]);
        let (mut relinked, mut missing) = (0usize, 0usize);
        let mut pending = vec![(ROOT_INODE, String::new(), 0usize)];
        while let Some((dir, prefix, depth)) = pending.pop() {
            let mut items = children.remove(&dir).unwrap_or_default();
            items.sort_unstable();
            let mut subdirs = Vec::new();
            for (name, inum) in items {
                if entries.len() >= limits.max_entries {
                    return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
                }
                let name = String::from_utf8_lossy(name);
                let path = if prefix.is_empty() { name.into_owned() } else { format!("{prefix}/{name}") };
                let Some(inode) = self.tree.inodes.get(&inum) else {
                    missing += 1;
                    continue;
                };
                let kind = EntryKind::from_mode(inode.mode);
                let (mut link, mut note) = (None, None);
                match kind {
                    EntryKind::Dir => {
                        if !seen_dirs.insert(inum) {
                            relinked += 1;
                            continue;
                        }
                        if depth + 1 >= limits.max_path_depth {
                            return Err(UnpackError::Limit(format!(
                                "directories nested deeper than {} levels",
                                limits.max_path_depth
                            )));
                        }
                        subdirs.push((inum, path.clone(), depth + 1));
                    }
                    EntryKind::File => match first_path.get(&inum) {
                        Some(first) => {
                            note = Some(format!("hard link to {first}"));
                            link = Some(first.clone());
                        }
                        None => {
                            first_path.insert(inum, path.clone());
                        }
                    },
                    EntryKind::Symlink => link = Some(String::from_utf8_lossy(&inode.data).into_owned()),
                    EntryKind::CharDevice | EntryKind::BlockDevice => note = device(&inode.data),
                    _ => {}
                }
                if inode.flags & CRYPT_FLAG != 0 {
                    note = Some("encrypted (fscrypt): content and names are not decrypted".to_owned());
                }
                entries.push(Entry {
                    path,
                    kind,
                    size: if kind == EntryKind::File { inode.size } else { 0 },
                    mode: inode.mode & 0o7777,
                    uid: inode.uid,
                    gid: inode.gid,
                    link,
                    note,
                });
                inums.push(inum);
            }
            pending.extend(subdirs.into_iter().rev());
        }
        if relinked > 0 {
            self.notes.push(format!("{relinked} directory entries skipped: a directory linked twice (a cycle)"));
        }
        if missing > 0 {
            self.notes.push(format!("{missing} directory entries skipped: their inode is missing"));
        }
        self.entries = entries;
        self.inums = inums;
        Ok(())
    }
}

fn align_up(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

fn compression_name(kind: u16) -> String {
    match kind {
        0 => "none".to_owned(),
        1 => "lzo".to_owned(),
        2 => "zlib".to_owned(),
        3 => "zstd".to_owned(),
        other => format!("unknown ({other})"),
    }
}

/// `major:minor` from an inode's inline device number (the kernel's "new" encoding, in 4 or 8 bytes).
fn device(data: &[u8]) -> Option<String> {
    let dev = match data.len() {
        4 => u64::from(le32(data, 0)),
        8 => le64(data, 0),
        _ => return None,
    };
    Some(format!("device {}:{}", (dev & 0xfff00) >> 8, (dev & 0xff) | ((dev >> 12) & 0xfff00)))
}

impl Image for Ubifs {
    fn format(&self) -> Format {
        Format::Ubifs
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let entry = self.entries.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        if entry.kind != EntryKind::File {
            return Err(UnpackError::Invalid(format!("`{}` is not a file", entry.path)));
        }
        let inum = self.inums[index];
        let inode = &self.tree.inodes[&inum];
        if inode.flags & CRYPT_FLAG != 0 {
            return Err(UnpackError::Unsupported(format!("`{}` is encrypted (fscrypt)", entry.path)));
        }
        let limit = budget.limits.max_file_bytes;
        if inode.size > limit {
            return Err(UnpackError::Limit(format!("`{}` is larger than max_file_bytes ({limit})", entry.path)));
        }
        let blocks = inode.size.div_ceil(BLOCK);
        if blocks > 0x2000_0000 {
            return Err(malformed(format!("`{}` is larger than a UBIFS file can be", entry.path)));
        }
        let zeros = [0u8; BLOCK as usize];
        let mut hole_input = NOMINAL_HOLE_INPUT;
        let mut emit = |bytes: &[u8], synthesised: bool, budget: &mut Budget| -> Result<()> {
            if synthesised {
                crate::limits::account(std::mem::take(&mut hole_input), bytes.len() as u64)?;
            }
            budget.charge_bytes(bytes.len() as u64)?;
            sink(bytes)
        };
        let block_len = |block: u64| (inode.size - block * BLOCK).min(BLOCK) as usize;
        let mut next = 0u64;
        for (&(_, block), &loc) in self.tree.data.range((inum, 0)..(inum, blocks as u32)) {
            let block = u64::from(block);
            while next < block {
                emit(&zeros[..block_len(next)], true, budget)?;
                next += 1;
            }
            let node = self.node(loc, Some(DATA_NODE))?;
            let found = key(&node, CH);
            if node.len() < DATA_SIZE || found.inum != inum || found.kind != 1 || u64::from(found.value) != block {
                return Err(malformed(format!("the data node at {loc} does not belong to `{}`", entry.path)));
            }
            let (size, compr) = (le32(&node, 40) as usize, le16(&node, 44));
            let payload = &node[DATA_SIZE..];
            if size > BLOCK as usize {
                return Err(malformed(format!("the data node at {loc} holds {size} bytes")));
            }
            let mut data = match compr {
                0 => payload.to_vec(),
                1 => decompress(Codec::Lzo, payload, size)?,
                2 => decompress(Codec::Deflate, payload, size)?,
                3 => decompress(Codec::Zstd, payload, size)?,
                other => return Err(UnpackError::Unsupported(format!("UBIFS compression type {other}"))),
            };
            if data.len() != size {
                return Err(malformed(format!("the data node at {loc} yields {} bytes, not {size}", data.len())));
            }
            // A short block ends in zeros.
            let len = block_len(block);
            data.resize(len.max(data.len()), 0);
            emit(&data[..len], false, budget)?;
            next = block + 1;
        }
        while next < blocks {
            emit(&zeros[..block_len(next)], true, budget)?;
            next += 1;
        }
        Ok(())
    }
}

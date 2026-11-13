use super::*;

const TYPES: u64 = 0x10000;

fn layout(len: usize) -> Layout {
    Layout {
        ptr: 8,
        big_endian: false,
        names: NameEncoding::Varint,
        offset_embed: false,
        module: GoModuleLayout::Go120,
        text: 0x1000,
        types: TYPES,
        etypes: TYPES + len as u64,
    }
}

/// A synthetic types section: descriptors and names written at chosen offsets.
struct Section(Vec<u8>);

impl Section {
    fn new(len: usize) -> Self {
        Section(vec![0; len])
    }

    fn put(&mut self, at: usize, bytes: &[u8]) {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn word(&mut self, at: usize, value: u64) {
        self.put(at, &value.to_le_bytes());
    }

    fn name(&mut self, at: usize, text: &str, flags: u8) {
        self.put(at, &[flags, text.len() as u8]);
        self.put(at + 2, text.as_bytes());
    }

    /// An `abi.Type` header (64-bit) of `kind` at `at`, named by the name at `name`.
    fn header(&mut self, at: usize, size: u64, kind: u8, name: usize, ptr_to_this: i32) {
        self.word(at, size);
        self.put(at + 20, &[TFLAG_NAMED, 8, 8, kind]);
        self.put(at + 40, &(name as i32).to_le_bytes());
        self.put(at + 44, &ptr_to_this.to_le_bytes());
    }

    fn reader(&self) -> Reader<'_> {
        Reader { layout: layout(self.0.len()), section: &self.0, binary: None, steps: 0, budget: MAX_LOOKUP_STEPS }
    }
}

/// `S` holds itself by value (impossible in Go, possible in a hostile image) and its pointer type points back.
fn cyclic() -> Section {
    let mut section = Section::new(0x1000);
    section.name(0x10, "main.S", 1);
    section.name(0x20, "*main.S", 1);
    section.name(0x30, "self", 1);
    section.header(0x100, 64, KIND_STRUCT, 0x10, 0x200);
    // pkgPath, then the fields slice: one field at 0x180.
    section.word(0x100 + 48 + 8, TYPES + 0x180);
    section.word(0x100 + 48 + 16, 1);
    section.word(0x100 + 48 + 24, 1);
    section.word(0x180, TYPES + 0x30);
    section.word(0x188, TYPES + 0x100);
    section.word(0x190, 0);
    section.header(0x200, 8, KIND_POINTER, 0x20, 0);
    section.word(0x200 + 48, TYPES + 0x100);
    section
}

#[test]
fn cyclic_types_are_walked_once_and_expanded_within_budget() {
    let section = cyclic();
    let mut reader = section.reader();
    let mut stats = GoIndexStats::default();
    let (types, _) = walk(&mut reader, vec![TYPES + 0x100, TYPES + 0x100], &mut stats);
    let names: Vec<_> = types.iter().map(|ty| ty.name.to_string()).collect();
    assert_eq!(names, ["main.S", "*main.S"]);
    assert!(reader.steps < 50, "{}", reader.steps);

    let mut reader = section.reader();
    let request = GoTypeRequest { name: "main.S".into(), depth: MAX_LOOKUP_DEPTH, limit: 512, ..Default::default() };
    let definition = define(&mut reader, TYPES + 0x100, &request).unwrap();
    let mut depth = 0;
    let mut member = &definition.members[0];
    while let Some(next) = member.members.first() {
        member = next;
        depth += 1;
    }
    assert_eq!(depth, MAX_LOOKUP_DEPTH);
    assert!(reader.steps < 200, "{}", reader.steps);

    // A byte offset into a type that contains itself descends a bounded number of levels.
    let mut reader = section.reader();
    let header = reader.header(TYPES + 0x100).unwrap();
    let selection = select_offset(&mut reader, &header, 8).unwrap();
    assert_eq!(selection.path.matches("self").count(), MAX_SELECTION_DEPTH);
    let mut reader = section.reader();
    let deep = vec!["self"; 64].join(".");
    assert!(select_path(&mut reader, &header, &deep).unwrap_err().contains("too deep"));
}

#[test]
fn huge_counts_and_out_of_section_references_are_refused_without_allocating() {
    let mut section = cyclic();
    // 2^40 fields: rejected by the count cap before any read.
    section.word(0x100 + 48 + 16, 1 << 40);
    section.word(0x100 + 48 + 24, 1 << 40);
    let mut reader = section.reader();
    let header = reader.header(TYPES + 0x100).unwrap();
    assert!(reader.body(&header).is_none());
    let request = GoTypeRequest { name: "main.S".into(), limit: 512, ..Default::default() };
    assert!(define(&mut section.reader(), TYPES + 0x100, &request).is_err());

    // A slice whose data runs past the section, a name offset outside it, a truncated header.
    let mut section = cyclic();
    section.word(0x100 + 48 + 8, TYPES + 0xff0);
    assert!(section.reader().header(TYPES + 0x100).and_then(|h| section.reader().body(&h)).is_none());
    let mut section = cyclic();
    section.put(0x100 + 40, &0x7fff_0000i32.to_le_bytes());
    assert!(section.reader().header(TYPES + 0x100).is_none());
    assert!(section.reader().header(TYPES + 0xff8).is_none());
    assert!(section.reader().header(TYPES - 8).is_none());

    // A name whose varint length never terminates, or claims more bytes than remain.
    let mut section = Section::new(0x40);
    section.put(0, &[1, 0x80, 0x80, 0x80, 0x80, 0x01]);
    section.put(0x20, &[1, 0x7f]);
    assert!(section.reader().name(TYPES).is_none());
    assert!(section.reader().name(TYPES + 0x20).is_none());
}

#[test]
fn a_walk_stops_at_its_step_budget() {
    // A chain of pointer types, each pointing to the next: the walk is cut by its budget, not by the chain.
    let count = 400;
    let mut section = Section::new(0x100 + count * 64);
    section.name(0x10, "*T", 1);
    for index in 0..count {
        let at = 0x100 + index * 64;
        section.header(at, 8, KIND_POINTER, 0x10, 0);
        section.word(at + 48, TYPES + (0x100 + (index + 1) % count * 64) as u64);
    }
    let mut reader = section.reader();
    reader.budget = 100;
    let mut stats = GoIndexStats::default();
    let (types, _) = walk(&mut reader, vec![TYPES + 0x100], &mut stats);
    assert!(stats.truncated && types.len() < count, "{}", types.len());
}

#[test]
fn corrupted_fixture_bytes_never_panic() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/gotypes-go1.20-x64.elf");
    let binary = Binary::open(path).unwrap();
    let index = go_type_index(&binary).unwrap();
    let roots: Vec<u64> = index.types.iter().map(|ty| ty.address).collect();
    let mut image = binary.image_bytes().to_vec();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let span = index.types_file.clone();
    for round in 0..64 {
        for _ in 0..256 {
            let at = span.start + (next() as usize) % span.len();
            image[at] = next() as u8;
        }
        for name in ["main.Record", "main.Shape", "main.Index", "*main.Error", "main.Square"] {
            for request in [
                GoTypeRequest { name: name.into(), depth: 4, limit: 512, ..Default::default() },
                GoTypeRequest { name: name.into(), member: Some("Inner.Ratio".into()), ..Default::default() },
                GoTypeRequest { name: name.into(), byte_offset: Some(60), ..Default::default() },
            ] {
                let lookup = index.lookup(&image, &request).unwrap();
                assert!(lookup.work.steps <= MAX_LOOKUP_STEPS + 64, "round {round}");
            }
        }
        let mut reader = Reader {
            layout: index.layout,
            section: &image[span.clone()],
            binary: None,
            steps: 0,
            budget: MAX_BUILD_STEPS,
        };
        let mut stats = GoIndexStats::default();
        let (types, _) = walk(&mut reader, roots.clone(), &mut stats);
        assert!(types.len() <= roots.len() * 4, "round {round}: {}", types.len());
    }
}

impl Section {
    /// A struct at `at` whose fields array lies at `at + 0x80`: (name offset, type offset, field offset).
    fn structure(&mut self, at: usize, name: usize, size: u64, fields: &[(usize, usize, u64)]) {
        self.header(at, size, KIND_STRUCT, name, 0);
        self.word(at + 56, TYPES + (at + 0x80) as u64);
        self.word(at + 64, fields.len() as u64);
        self.word(at + 72, fields.len() as u64);
        for (index, &(field_name, ty, offset)) in fields.iter().enumerate() {
            let entry = at + 0x80 + index * 24;
            self.word(entry, TYPES + field_name as u64);
            self.word(entry + 8, TYPES + ty as u64);
            self.word(entry + 16, offset);
        }
    }
}

/// Promotions: `Outer { A; B }` with `A` (embedded) holding `Deep` (embedded) holding `X`, `B` (embedded)
/// holding `X` directly, and `A` and `B` both holding `Twin`.
fn promotions() -> Section {
    let mut section = Section::new(0x2000);
    for (at, text, flags) in [
        (0x10, "main.Outer", 1),
        (0x20, "main.A", 1),
        (0x30, "main.B", 1),
        (0x40, "main.Deep", 1),
        (0x50, "A", 1 | 8),
        (0x58, "B", 1 | 8),
        (0x60, "Deep", 1 | 8),
        (0x70, "X", 1),
        (0x78, "Twin", 1),
        (0x88, "int64", 1),
    ] {
        section.name(at, text, flags);
    }
    section.header(0x100, 8, 6, 0x88, 0);
    section.structure(0x200, 0x10, 64, &[(0x50, 0x400, 0), (0x58, 0x600, 32)]);
    section.structure(0x400, 0x20, 32, &[(0x60, 0x800, 0), (0x78, 0x100, 24)]);
    section.structure(0x600, 0x30, 32, &[(0x70, 0x100, 16), (0x78, 0x100, 24)]);
    section.structure(0x800, 0x40, 24, &[(0x70, 0x100, 8)]);
    section
}

#[test]
fn promoted_fields_resolve_shallowest_first_and_report_ambiguity() {
    let section = promotions();
    let mut reader = section.reader();
    let outer = reader.header(TYPES + 0x200).unwrap();
    // Depth-first search would find A.Deep.X (offset 8); Go picks B.X at the shallower depth (32 + 16).
    let x = select_path(&mut reader, &outer, "X").unwrap();
    assert_eq!((x.offset, x.type_name.as_str()), (48, "int64"));
    let twin = select_path(&mut section.reader(), &outer, "Twin").unwrap_err();
    assert!(twin.contains("ambiguous"), "{twin}");
}

#[test]
fn overflowing_offsets_are_errors_not_wraps() {
    let mut section = cyclic();
    section.word(0x190, u64::MAX - 4);
    let mut reader = section.reader();
    let header = reader.header(TYPES + 0x100).unwrap();
    assert!(select_path(&mut reader, &header, "self.self").unwrap_err().contains("overflows"));
    let mut section = cyclic();
    section.word(0x100, u64::MAX);
    section.word(0x190, 8);
    let mut reader = section.reader();
    let header = reader.header(TYPES + 0x100).unwrap();
    assert!(select_offset(&mut reader, &header, u64::MAX - 1).is_err());
}

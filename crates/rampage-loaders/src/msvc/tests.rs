//! Malformed and hostile MSVC tables in hand-built x86 PE images: a data section at 0x401000 and a code section
//! of `ret` instructions after it.

use std::time::{Duration, Instant};

use rampage_arch::Arch;

use super::*;
use crate::pe_test_image::{IMAGE_BASE_32, SECTION_RVA, TestPe};

const DATA: u64 = IMAGE_BASE_32 + SECTION_RVA as u64;
const MAGIC: u32 = 0x1993_0520;

struct Image {
    data: Vec<u8>,
    code: Vec<u8>,
}

impl Image {
    fn new(data_len: usize, code_len: usize) -> Self {
        Self { data: vec![0; data_len], code: vec![0xc3; code_len] }
    }

    fn code_va(&self) -> u64 {
        IMAGE_BASE_32 + u64::from(self.pe().code_rva())
    }

    fn pe(&self) -> TestPe {
        let mut pe = TestPe::new(32, self.data.clone());
        pe.code = self.code.clone();
        pe
    }

    fn put(&mut self, va: u64, value: u32) {
        let at = (va - DATA) as usize;
        self.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, va: u64, bytes: &[u8]) {
        let at = (va - DATA) as usize;
        self.data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A type descriptor named `.H` (int) at `va`: vftable pointer, spare word, name.
    fn type_descriptor(&mut self, va: u64) {
        self.put(va, DATA as u32);
        self.bytes(va + 8, b".H\0");
    }

    /// An x86 FuncInfo at `va` with one unwind state and `try_count` try blocks at `try_map`.
    fn func_info(&mut self, va: u64, unwind: u64, try_count: u32, try_map: u64) {
        self.put(va, MAGIC);
        self.put(va + 4, 1);
        self.put(va + 8, unwind as u32);
        self.put(va + 12, try_count);
        self.put(va + 16, try_map as u32);
    }

    fn binary(&self) -> Binary {
        let binary = Binary::from_owned_native_bytes(self.pe().build(), Arch::X86).unwrap();
        assert!(binary.is_code(self.code_va()) && !binary.is_code(DATA));
        binary
    }
}

/// An unwind map entry for state 0 (to state -1, no action) and one try map entry whose `catches` handlers live
/// at `handlers`, each catching `int` into the first code byte.
fn shared_tables(image: &mut Image, unwind: u64, try_map: u64, try_count: u32, handlers: u64, catches: u32) {
    image.put(unwind, u32::MAX);
    let descriptor = DATA + 0x10;
    image.type_descriptor(descriptor);
    let code = image.code_va() as u32;
    for catch in 0..u64::from(catches) {
        let entry = handlers + catch * 16;
        image.put(entry + 4, descriptor as u32);
        image.put(entry + 12, code);
    }
    for index in 0..u64::from(try_count) {
        let entry = try_map + index * 20;
        image.put(entry + 12, catches);
        image.put(entry + 16, handlers as u32);
    }
}

#[test]
fn many_func_infos_sharing_one_huge_try_map_stop_at_the_budget() {
    // 4096 try blocks of 256 catches each, shared by 2000 FuncInfo records: about a million handlers per record.
    let (handlers, try_map, unwind, infos) = (DATA + 0x100, DATA + 0x1100, DATA + 0x80, DATA + 0x15100);
    let mut image = Image::new(0x15100 + 2000 * 36, 0x10);
    shared_tables(&mut image, unwind, try_map, 4096, handlers, 256);
    for index in 0..2000 {
        image.func_info(infos + index * 36, unwind, 4096, try_map);
    }
    let binary = image.binary();
    let started = Instant::now();
    let metadata = read(&binary);
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    assert!(metadata.budget_exhausted);
    assert!(metadata.exceptions.warnings.iter().any(|warning| warning.contains("budget exhausted")));
    let retained: usize = metadata
        .exceptions
        .functions
        .iter()
        .flat_map(|function| &function.try_blocks)
        .map(|block| block.catches.len())
        .sum();
    assert!(retained <= (RETAIN_BUDGET / CATCH_BYTES) as usize, "{retained}");
    // The load-time copy is bounded the same way and does not fail the load.
    assert!(binary.msvc_metadata().unwrap().budget_exhausted);
}

#[test]
fn a_small_budget_bounds_work_on_shared_tables() {
    let (handlers, try_map, unwind, infos) = (DATA + 0x100, DATA + 0x200, DATA + 0x80, DATA + 0x400);
    let mut image = Image::new(0x400 + 64 * 36, 0x10);
    shared_tables(&mut image, unwind, try_map, 4, handlers, 8);
    for index in 0..64 {
        image.func_info(infos + index * 36, unwind, 4, try_map);
    }
    let binary = image.binary();
    let full = read(&binary);
    assert!(!full.budget_exhausted);
    assert_eq!(full.exceptions.functions.len(), 64);
    assert!(full.exceptions.functions.iter().all(|function| function.try_blocks.len() == 4));
    let starved = read_with_budget(&binary, 500, RETAIN_BUDGET);
    assert!(starved.budget_exhausted);
    assert!(starved.exceptions.functions.len() < 64);
}

#[test]
fn truncated_huge_and_segment_crossing_tables_are_rejected_without_panicking() {
    let (handlers, try_map, unwind) = (DATA + 0x100, DATA + 0x200, DATA + 0x80);
    let mut image = Image::new(0x1000, 0x10);
    shared_tables(&mut image, unwind, try_map, 1, handlers, 1);
    image.func_info(DATA + 0x300, unwind, 1, try_map);
    // Huge counts.
    image.func_info(DATA + 0x340, unwind, u32::MAX, try_map);
    image.put(DATA + 0x384, u32::MAX);
    image.put(DATA + 0x380, MAGIC);
    // A try map that runs off the end of the data section.
    image.func_info(DATA + 0x3c0, unwind, 8, DATA + 0xff0);
    // A handler array that crosses the section end.
    image.put(DATA + 0xf00 + 12, 8);
    image.put(DATA + 0xf00 + 16, (DATA + 0xff8) as u32);
    image.func_info(DATA + 0x400, unwind, 1, DATA + 0xf00);
    // A FuncInfo whose tables point at unmapped and wrapping addresses.
    image.func_info(DATA + 0x440, 0xffff_fff0, 1, 0xffff_fffc);
    let binary = image.binary();
    let report = &read(&binary).exceptions;
    let tables: Vec<u64> = report.functions.iter().map(|function| function.table).collect();
    assert_eq!(tables, [DATA + 0x300]);
}

#[test]
fn func_info_magic_in_unrelated_data_yields_nothing() {
    let mut image = Image::new(0x1000, 0x10);
    for index in 0..0x400 {
        // Every word is the version stamp, so each candidate's pointers are the stamp too: unmapped.
        image.put(DATA + index * 4, MAGIC);
    }
    let metadata = read(&image.binary());
    assert!(metadata.exceptions.functions.is_empty() && metadata.exceptions.throws.is_empty());
    assert!(metadata.vftables.is_empty() && !metadata.budget_exhausted);
}

#[test]
fn x86_handler_thunk_starts_at_the_registration_nearest_its_load() {
    let (handlers, try_map, unwind, info) = (DATA + 0x100, DATA + 0x200, DATA + 0x80, DATA + 0x300);
    let mut image = Image::new(0x1000, 0x80);
    shared_tables(&mut image, unwind, try_map, 1, handlers, 1);
    image.func_info(info, unwind, 1, try_map);
    let code = image.code_va();
    let thunk = code + 0x40;
    // The thunk: `mov eax, FuncInfo; jmp rel8`.
    image.code[0x40] = 0xb8;
    image.code[0x41..0x45].copy_from_slice(&(info as u32).to_le_bytes());
    image.code[0x45..0x47].copy_from_slice(&[0xeb, 0x00]);
    // The real registration, `push thunk`, and a stray `push` of an address 0x30 bytes before it.
    image.code[0x10] = 0x68;
    image.code[0x11..0x15].copy_from_slice(&(thunk as u32).to_le_bytes());
    image.code[0x20] = 0x68;
    image.code[0x21..0x25].copy_from_slice(&((thunk - 0x30) as u32).to_le_bytes());
    let metadata = read(&image.binary());
    let function = &metadata.exceptions.functions[0];
    assert_eq!(function.handler, Some(thunk));
    assert_eq!(function.registrations, [code + 0x10, code + 0x20]);
}

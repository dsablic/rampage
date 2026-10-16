//! Allocation-free gate before wasmparser's owning type/instance readers.
//!
//! This is intentionally a subset, not a universal Wasm grammar. Core types must be plain function types:
//! no explicit rec groups, subtyping, GC, module types, or typed references. Component types support only
//! synchronous functions, primitive/list/tuple values, and depth-bounded inline instance types. Inline
//! component/resource/record/variant/async types are unsupported. Instance argument/export vectors are
//! capped at 256 and canonical option vectors at 16 before dependency readers can allocate them.
//! Constant expressions support one scalar/vector constant, global.get, ref.null funcref, or ref.func.
//! Nested binary module/component envelopes remain supported with independent depth/count limits.
//! wasmparser and Wasmtime still perform decoding/semantic validation after this gate succeeds.
//! Unsupported forms return the existing `Preflight` classification; this gate adds no public error variant.

use super::{
    MAX_BODY_BYTES, MAX_CUSTOM_BYTES, MAX_DATA_BYTES, MAX_DEPTH, MAX_ENTRIES, MAX_FUNCTIONS, MAX_LOCALS,
    MAX_LOCALS_PER_FUNCTION, MAX_NAME_BYTES, MAX_NAMES_BYTES, MAX_SEGMENTS, MAX_TYPES, Structure, add,
};
use crate::{MAX_INSTANCES, MAX_MEMORIES, MAX_MEMORY_BYTES, MAX_TABLE_ELEMENTS, MAX_TABLES, PluginError};

const MAX_INSTANCE_ITEMS: usize = 256;
const MAX_CANONICAL_OPTIONS: usize = 16;

pub(super) fn admit(bytes: &[u8]) -> Result<(), PluginError> {
    envelope(bytes, true, 1, &mut Structure::default())
}

fn envelope(bytes: &[u8], component: bool, depth: usize, state: &mut Structure) -> Result<(), PluginError> {
    if depth > MAX_DEPTH {
        return Err(PluginError::StructuralLimit);
    }
    let mut reader = Reader::new(bytes);
    let header = reader.bytes(8)?;
    let expected = if component { b"\0asm\x0d\0\x01\0" } else { b"\0asm\x01\0\0\0" };
    if header != expected {
        return Err(PluginError::Preflight);
    }
    while !reader.done() {
        let id = reader.byte()?;
        let length = reader.u32()? as usize;
        let mut section = Reader::new(reader.bytes(length)?);
        if id == 0 {
            section.name(state)?;
            add(&mut state.custom, section.remaining(), MAX_CUSTOM_BYTES)?;
            section.skip_remaining();
        } else if component {
            component_section(id, &mut section, depth, state)?;
        } else {
            module_section(id, &mut section, state)?;
        }
        if !section.done() {
            return Err(PluginError::Preflight);
        }
    }
    Ok(())
}

fn component_section(id: u8, reader: &mut Reader<'_>, depth: usize, state: &mut Structure) -> Result<(), PluginError> {
    if matches!(id, 1 | 4) {
        if id == 1 {
            add(&mut state.modules, 1, MAX_INSTANCES)?;
        } else {
            add(&mut state.components, 1, MAX_INSTANCES)?;
        }
        envelope(reader.bytes(reader.remaining())?, id == 4, depth + 1, state)?;
        return Ok(());
    }
    if !matches!(id, 2 | 3 | 5 | 6 | 7 | 8 | 10 | 11) {
        return Err(PluginError::Preflight);
    }
    let count = reader.count(if matches!(id, 3 | 7) { MAX_TYPES } else { MAX_ENTRIES }, state)?;
    if matches!(id, 3 | 7) {
        add(&mut state.types, count, MAX_TYPES)?;
    }
    if id == 10 && depth == 1 && count != 0 {
        return Err(PluginError::Abi);
    }
    for _ in 0..count {
        match id {
            2 => instance(reader, false, state)?,
            3 => core_func(reader, state)?,
            5 => instance(reader, true, state)?,
            6 => alias(reader, state)?,
            7 => component_type(reader, 1, state)?,
            8 => canonical(reader, state)?,
            10 => {
                reader.component_name(state)?;
                component_ref(reader)?;
            }
            11 => {
                component_export(reader, state)?;
                match reader.byte()? {
                    0 => {}
                    1 => component_ref(reader)?,
                    _ => return Err(PluginError::Preflight),
                }
            }
            _ => return Err(PluginError::Preflight),
        }
    }
    Ok(())
}

fn core_func(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    if reader.byte()? != 0x60 {
        return Err(PluginError::Preflight);
    }
    let params = reader.count(128, state)?;
    for _ in 0..params {
        reader.core_value()?;
    }
    let results = reader.count(16, state)?;
    for _ in 0..results {
        reader.core_value()?;
    }
    Ok(())
}

fn component_type(reader: &mut Reader<'_>, depth: usize, state: &mut Structure) -> Result<(), PluginError> {
    if depth > MAX_DEPTH {
        return Err(PluginError::StructuralLimit);
    }
    match reader.byte()? {
        0x73..=0x7f => {}
        0x70 => reader.component_value()?,
        0x6f => {
            let count = reader.count(16, state)?;
            for _ in 0..count {
                reader.component_value()?;
            }
        }
        0x40 => {
            let count = reader.count(128, state)?;
            for _ in 0..count {
                reader.name(state)?;
                reader.component_value()?;
            }
            match reader.byte()? {
                0 => reader.component_value()?,
                1 if reader.u32()? == 0 => {}
                _ => return Err(PluginError::Preflight),
            }
        }
        0x42 => {
            let count = reader.count(MAX_INSTANCE_ITEMS, state)?;
            for _ in 0..count {
                match reader.byte()? {
                    0 => {
                        add(&mut state.types, 1, MAX_TYPES)?;
                        core_func(reader, state)?;
                    }
                    1 => {
                        add(&mut state.types, 1, MAX_TYPES)?;
                        component_type(reader, depth + 1, state)?;
                    }
                    2 => alias(reader, state)?,
                    4 => {
                        reader.component_name(state)?;
                        component_ref(reader)?;
                    }
                    _ => return Err(PluginError::Preflight),
                }
            }
        }
        _ => return Err(PluginError::Preflight),
    }
    Ok(())
}

fn component_ref(reader: &mut Reader<'_>) -> Result<(), PluginError> {
    match reader.sort()? {
        (0, Some(0x11)) | (1 | 4 | 5, None) => {
            reader.u32()?;
        }
        (2, None) => reader.component_value()?,
        (3, None) if reader.byte()? == 0 => {
            reader.u32()?;
        }
        _ => return Err(PluginError::Preflight),
    }
    Ok(())
}

fn alias(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    let sort = reader.sort()?;
    match reader.byte()? {
        0 if matches!(sort, (0, Some(0x11)) | (1..=5, None)) => {
            reader.u32()?;
            reader.name(state)?;
        }
        1 if matches!(sort, (0, Some(0..=3))) => {
            reader.u32()?;
            reader.name(state)?;
        }
        2 if matches!(sort, (0, Some(0x10 | 0x11)) | (3 | 4, None)) => {
            reader.u32()?;
            reader.u32()?;
        }
        _ => return Err(PluginError::Preflight),
    }
    Ok(())
}

fn component_export(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    reader.component_name(state)?;
    match reader.sort()? {
        (0, Some(0x11)) | (1..=5, None) => {}
        _ => return Err(PluginError::Preflight),
    }
    reader.u32()?;
    Ok(())
}

fn instance(reader: &mut Reader<'_>, component: bool, state: &mut Structure) -> Result<(), PluginError> {
    let kind = reader.byte()?;
    if kind == 0 {
        if component {
            add(&mut state.component_instances, 1, MAX_INSTANCES)?;
        } else {
            add(&mut state.instances, 1, MAX_INSTANCES)?;
        }
        reader.u32()?;
    } else if kind != 1 {
        return Err(PluginError::Preflight);
    }
    let count = reader.count(MAX_INSTANCE_ITEMS, state)?;
    for _ in 0..count {
        if kind == 0 {
            reader.name(state)?;
            if component {
                match reader.sort()? {
                    (0, Some(0x11)) | (1..=5, None) => {}
                    _ => return Err(PluginError::Preflight),
                }
            } else if reader.byte()? != 0x12 {
                return Err(PluginError::Preflight);
            }
            reader.u32()?;
        } else if component {
            component_export(reader, state)?;
        } else {
            reader.name(state)?;
            reader.core_kind()?;
            reader.u32()?;
        }
    }
    Ok(())
}

fn canonical(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    let kind = reader.byte()?;
    if !matches!(kind, 0 | 1) || reader.byte()? != 0 {
        return Err(PluginError::Preflight);
    }
    reader.u32()?;
    let count = reader.count(MAX_CANONICAL_OPTIONS, state)?;
    for _ in 0..count {
        match reader.byte()? {
            0..=2 => {}
            3..=5 => {
                reader.u32()?;
            }
            _ => return Err(PluginError::Preflight),
        }
    }
    if kind == 0 {
        reader.u32()?;
    }
    Ok(())
}

fn module_section(id: u8, reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    if id == 8 {
        reader.u32()?;
        return Ok(());
    }
    let limit = match id {
        1 => MAX_TYPES,
        2 | 6 | 7 => MAX_ENTRIES,
        3 | 10 => MAX_FUNCTIONS,
        4 => MAX_TABLES,
        5 => MAX_MEMORIES,
        9 | 11 | 12 => MAX_SEGMENTS,
        _ => return Err(PluginError::Preflight),
    };
    let count = reader.count(limit, state)?;
    match id {
        1 => add(&mut state.types, count, MAX_TYPES)?,
        3 => add(&mut state.functions, count, MAX_FUNCTIONS)?,
        4 => add(&mut state.tables, count, MAX_TABLES)?,
        5 => add(&mut state.memories, count, MAX_MEMORIES)?,
        9 | 11 => add(&mut state.segments, count, MAX_SEGMENTS)?,
        10 => add(&mut state.bodies, count, MAX_FUNCTIONS)?,
        12 => return Ok(()),
        _ => {}
    }
    for _ in 0..count {
        match id {
            1 => core_func(reader, state)?,
            2 => {
                reader.name(state)?;
                reader.name(state)?;
                match reader.core_kind()? {
                    0 => {
                        add(&mut state.functions, 1, MAX_FUNCTIONS)?;
                        reader.u32()?;
                    }
                    1 => reader.table_type()?,
                    2 => reader.limits(MAX_MEMORY_BYTES / 65_536)?,
                    3 => reader.global_type()?,
                    _ => return Err(PluginError::Preflight),
                }
            }
            3 => {
                reader.u32()?;
            }
            4 => {
                let expression = reader.peek()? == 0x40;
                if expression {
                    reader.byte()?;
                    if reader.byte()? != 0 {
                        return Err(PluginError::Preflight);
                    }
                }
                reader.table_type()?;
                if expression {
                    reader.const_expr()?;
                }
            }
            5 => reader.limits(MAX_MEMORY_BYTES / 65_536)?,
            6 => {
                reader.global_type()?;
                reader.const_expr()?;
            }
            7 => {
                reader.name(state)?;
                reader.core_kind()?;
                reader.u32()?;
            }
            9 => element(reader, state)?,
            10 => body(reader, state)?,
            11 => {
                match reader.u32()? {
                    0 => reader.const_expr()?,
                    1 => {}
                    2 => {
                        reader.u32()?;
                        reader.const_expr()?;
                    }
                    _ => return Err(PluginError::Preflight),
                }
                let length = reader.u32()? as usize;
                add(&mut state.data, length, MAX_DATA_BYTES)?;
                reader.bytes(length)?;
            }
            _ => return Err(PluginError::Preflight),
        }
    }
    Ok(())
}

fn body(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    let length = reader.u32()? as usize;
    if length > MAX_BODY_BYTES {
        return Err(PluginError::StructuralLimit);
    }
    let mut body = Reader::new(reader.bytes(length)?);
    let groups = body.count(MAX_LOCALS_PER_FUNCTION, state)?;
    let mut locals = 0;
    for _ in 0..groups {
        add(&mut locals, body.u32()? as usize, MAX_LOCALS_PER_FUNCTION)?;
        body.core_value()?;
    }
    add(&mut state.locals, locals, MAX_LOCALS)?;
    Ok(())
}

fn element(reader: &mut Reader<'_>, state: &mut Structure) -> Result<(), PluginError> {
    let flags = reader.u32()?;
    if flags > 7 {
        return Err(PluginError::Preflight);
    }
    if flags & 1 == 0 {
        if flags & 2 != 0 {
            reader.u32()?;
        }
        reader.const_expr()?;
    }
    let expressions = flags & 4 != 0;
    if flags & 3 != 0 {
        let expected = if expressions { 0x70 } else { 0 };
        if reader.byte()? != expected {
            return Err(PluginError::Preflight);
        }
    }
    let count = reader.count(MAX_TABLE_ELEMENTS, state)?;
    for _ in 0..count {
        if expressions {
            reader.const_expr()?;
        } else {
            reader.u32()?;
        }
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn skip_remaining(&mut self) {
        self.offset = self.bytes.len();
    }

    fn peek(&self) -> Result<u8, PluginError> {
        self.bytes.get(self.offset).copied().ok_or(PluginError::Preflight)
    }

    fn byte(&mut self) -> Result<u8, PluginError> {
        let byte = self.peek()?;
        self.offset += 1;
        Ok(byte)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], PluginError> {
        let end = self.offset.checked_add(length).ok_or(PluginError::Preflight)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(PluginError::Preflight)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, PluginError> {
        let mut value = 0;
        for shift in (0..35).step_by(7) {
            let byte = self.byte()?;
            if shift == 28 && byte > 15 {
                return Err(PluginError::Preflight);
            }
            value |= ((byte & 127) as u32) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err(PluginError::Preflight)
    }

    fn count(&mut self, limit: usize, state: &mut Structure) -> Result<usize, PluginError> {
        let count = self.u32()? as usize;
        if count > limit {
            return Err(PluginError::StructuralLimit);
        }
        add(&mut state.entries, count, MAX_ENTRIES)?;
        Ok(count)
    }

    fn name(&mut self, state: &mut Structure) -> Result<(), PluginError> {
        let length = self.u32()? as usize;
        if length > MAX_NAME_BYTES {
            return Err(PluginError::StructuralLimit);
        }
        add(&mut state.names, length, MAX_NAMES_BYTES)?;
        std::str::from_utf8(self.bytes(length)?).map_err(|_| PluginError::Preflight)?;
        Ok(())
    }

    fn component_name(&mut self, state: &mut Structure) -> Result<(), PluginError> {
        if !matches!(self.byte()?, 0 | 1) {
            return Err(PluginError::Preflight);
        }
        self.name(state)
    }

    fn core_value(&mut self) -> Result<(), PluginError> {
        if matches!(self.byte()?, 0x7b..=0x7f | 0x70) { Ok(()) } else { Err(PluginError::Preflight) }
    }

    fn component_value(&mut self) -> Result<(), PluginError> {
        if matches!(self.peek()?, 0x73..=0x7f) {
            self.byte()?;
            return Ok(());
        }
        for index in 0..5 {
            let byte = self.byte()?;
            if byte & 128 == 0 {
                if byte & 64 != 0 || (index == 4 && byte > 15) {
                    return Err(PluginError::Preflight);
                }
                return Ok(());
            }
        }
        Err(PluginError::Preflight)
    }

    fn sort(&mut self) -> Result<(u8, Option<u8>), PluginError> {
        let byte = self.byte()?;
        Ok((byte, if byte == 0 { Some(self.byte()?) } else { None }))
    }

    fn core_kind(&mut self) -> Result<u8, PluginError> {
        let kind = self.byte()?;
        if kind <= 3 { Ok(kind) } else { Err(PluginError::Preflight) }
    }

    fn limits(&mut self, limit: usize) -> Result<(), PluginError> {
        let flags = self.byte()?;
        if flags > 1 {
            return Err(PluginError::Preflight);
        }
        if self.u32()? as usize > limit || (flags == 1 && self.u32()? as usize > limit) {
            return Err(PluginError::StructuralLimit);
        }
        Ok(())
    }

    fn table_type(&mut self) -> Result<(), PluginError> {
        if self.byte()? != 0x70 {
            return Err(PluginError::Preflight);
        }
        self.limits(MAX_TABLE_ELEMENTS)
    }

    fn global_type(&mut self) -> Result<(), PluginError> {
        self.core_value()?;
        if self.byte()? > 1 {
            return Err(PluginError::Preflight);
        }
        Ok(())
    }

    fn signed_leb(&mut self, limit: usize) -> Result<(), PluginError> {
        for _ in 0..limit {
            if self.byte()? & 128 == 0 {
                return Ok(());
            }
        }
        Err(PluginError::Preflight)
    }

    fn const_expr(&mut self) -> Result<(), PluginError> {
        match self.byte()? {
            0x41 => self.signed_leb(5)?,
            0x42 => self.signed_leb(10)?,
            0x43 => {
                self.bytes(4)?;
            }
            0x44 => {
                self.bytes(8)?;
            }
            0x23 | 0xd2 => {
                self.u32()?;
            }
            0xd0 if self.byte()? == 0x70 => {}
            0xfd if self.u32()? == 12 => {
                self.bytes(16)?;
            }
            _ => return Err(PluginError::Preflight),
        }
        if self.byte()? != 0x0b {
            return Err(PluginError::Preflight);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut value: usize, bytes: &mut Vec<u8>) {
        loop {
            let byte = (value & 127) as u8;
            value >>= 7;
            bytes.push(if value == 0 { byte } else { byte | 128 });
            if value == 0 {
                break;
            }
        }
    }

    fn section(component: bool, id: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = if component { b"\0asm\x0d\0\x01\0".to_vec() } else { b"\0asm\x01\0\0\0".to_vec() };
        bytes.push(id);
        leb(payload.len(), &mut bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn core_types(payload: &[u8]) -> Vec<u8> {
        section(true, 1, &section(false, 1, payload))
    }

    #[test]
    fn truncated_huge_core_counts_fail_in_raw_gate_not_allocating_type_readers() {
        let mut count = Vec::new();
        leb(1_000_000, &mut count);
        assert_eq!(admit(&core_types(&count)), Err(PluginError::StructuralLimit));
        for prefix in [&[1, 0x60][..], &[1, 0x60, 0][..]] {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&count);
            assert_eq!(admit(&core_types(&payload)), Err(PluginError::StructuralLimit));
        }
        let mut rec_group = vec![1, 0x4e];
        rec_group.extend_from_slice(&count);
        assert_eq!(admit(&core_types(&rec_group)), Err(PluginError::Preflight));
        assert_eq!(admit(&core_types(&[1, 0x50])), Err(PluginError::Preflight));
        assert_eq!(admit(&core_types(&[1, 0x5f])), Err(PluginError::Preflight));
    }

    #[test]
    fn inline_component_forms_and_huge_instance_arrays_reject_before_owning_readers() {
        for id in [2, 5] {
            for prefix in [&[1, 0, 0][..], &[1, 1][..]] {
                let mut payload = prefix.to_vec();
                leb(1_000_000, &mut payload);
                assert_eq!(admit(&section(true, id, &payload)), Err(PluginError::StructuralLimit));
            }
        }
        for prefix in [&[1, 0x40][..], &[1, 0x42][..], &[1, 0x6f][..]] {
            let mut payload = prefix.to_vec();
            leb(1_000_000, &mut payload);
            assert_eq!(admit(&section(true, 7, &payload)), Err(PluginError::StructuralLimit));
        }
        for unsupported in [0x41, 0x43, 0x72, 0x71, 0x3f] {
            assert_eq!(admit(&section(true, 7, &[1, unsupported])), Err(PluginError::Preflight));
        }
    }

    #[test]
    fn deep_truncated_inline_instance_tree_hits_depth_before_dependency_descent() {
        let mut payload = vec![1];
        for _ in 0..MAX_DEPTH {
            payload.extend_from_slice(&[0x42, 1, 1]);
        }
        assert_eq!(admit(&section(true, 7, &payload)), Err(PluginError::StructuralLimit));
    }

    #[test]
    fn cumulative_types_and_nested_envelopes_are_raw_budgets() {
        let half = MAX_TYPES / 2 + 1;
        let mut payload = Vec::new();
        leb(half, &mut payload);
        for _ in 0..half {
            payload.extend_from_slice(&[0x60, 0, 0]);
        }
        let module = section(false, 1, &payload);
        let mut component = section(true, 1, &module);
        component.push(1);
        leb(module.len(), &mut component);
        component.extend_from_slice(&module);
        assert_eq!(admit(&component), Err(PluginError::StructuralLimit));
        let mut nested = b"\0asm\x0d\0\x01\0".to_vec();
        for _ in 0..MAX_DEPTH {
            nested = section(true, 4, &nested);
        }
        assert_eq!(admit(&nested), Err(PluginError::StructuralLimit));
    }

    #[test]
    fn admits_owned_abi_value_shapes_and_bounded_instance_type() {
        let payload = [3, 0x70, 0x7d, 0x6f, 4, 0x77, 0x77, 0x77, 0x77, 0x42, 1, 1, 0x40, 0, 1, 0];
        assert_eq!(admit(&section(true, 7, &payload)), Ok(()));
        assert_eq!(admit(&section(true, 2, &[1, 1, 0])), Ok(()));
        assert_eq!(admit(&section(true, 5, &[1, 1, 0])), Ok(()));
    }
}

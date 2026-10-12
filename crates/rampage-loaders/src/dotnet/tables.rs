//! The `#~` / `#-` table stream: its header, the variable column widths, and the row layout of every
//! ECMA-335 table (II.22), so any table present can be located or skipped even when it is not decoded.

use rampage_arch::bytes::read_uint;

use super::{Warnings, read_u32};

/// A metadata token's row index is 24 bits (II.22), so no real table can have more rows than this.
pub(super) const MAX_ROWS: u32 = 0x00FF_FFFF;

/// Number of tables ECMA-335 defines (0x00..=0x2C). Ids above are not standard and cannot be sized.
pub(super) const TABLE_COUNT: usize = 0x2D;

pub(super) const MODULE: u8 = 0x00;
pub(super) const TYPE_REF: u8 = 0x01;
pub(super) const TYPE_DEF: u8 = 0x02;
pub(super) const FIELD_PTR: u8 = 0x03;
pub(super) const FIELD: u8 = 0x04;
pub(super) const METHOD_PTR: u8 = 0x05;
pub(super) const METHOD_DEF: u8 = 0x06;
pub(super) const PARAM_PTR: u8 = 0x07;
pub(super) const PARAM: u8 = 0x08;
pub(super) const MEMBER_REF: u8 = 0x0A;
const EVENT: u8 = 0x14;
const PROPERTY: u8 = 0x17;
pub(super) const MODULE_REF: u8 = 0x1A;
pub(super) const TYPE_SPEC: u8 = 0x1B;
pub(super) const ASSEMBLY: u8 = 0x20;
pub(super) const ASSEMBLY_REF: u8 = 0x23;
pub(super) const FILE: u8 = 0x26;
pub(super) const NESTED_CLASS: u8 = 0x29;
const GENERIC_PARAM: u8 = 0x2A;

pub(super) const TABLE_NAMES: [&str; TABLE_COUNT] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "EncLog",
    "EncMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

/// Coded indexes (II.24.2.6): a tag in the low bits selects the table, the rest is the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl Coded {
    /// The tables each tag value selects, in tag order; `None` marks a tag the spec leaves unused.
    fn tables(self) -> &'static [Option<u8>] {
        match self {
            Self::TypeDefOrRef => &[Some(0x02), Some(0x01), Some(0x1B)],
            Self::HasConstant => &[Some(0x04), Some(0x08), Some(0x17)],
            Self::HasCustomAttribute => &[
                Some(0x06),
                Some(0x04),
                Some(0x01),
                Some(0x02),
                Some(0x08),
                Some(0x09),
                Some(0x0A),
                Some(0x00),
                Some(0x0E),
                Some(0x17),
                Some(0x14),
                Some(0x11),
                Some(0x1A),
                Some(0x1B),
                Some(0x20),
                Some(0x23),
                Some(0x26),
                Some(0x27),
                Some(0x28),
                Some(0x2A),
                Some(0x2C),
                Some(0x2B),
            ],
            Self::HasFieldMarshal => &[Some(0x04), Some(0x08)],
            Self::HasDeclSecurity => &[Some(0x02), Some(0x06), Some(0x20)],
            Self::MemberRefParent => &[Some(0x02), Some(0x01), Some(0x1A), Some(0x06), Some(0x1B)],
            Self::HasSemantics => &[Some(0x14), Some(0x17)],
            Self::MethodDefOrRef => &[Some(0x06), Some(0x0A)],
            Self::MemberForwarded => &[Some(0x04), Some(0x06)],
            Self::Implementation => &[Some(0x26), Some(0x23), Some(0x27)],
            // II.24.2.6: tags 0, 1 and 4 are reserved, yet the tag is still 3 bits wide.
            Self::CustomAttributeType => &[None, None, Some(0x06), Some(0x0A), None],
            Self::ResolutionScope => &[Some(0x00), Some(0x1A), Some(0x23), Some(0x01)],
            Self::TypeOrMethodDef => &[Some(0x02), Some(0x06)],
        }
    }

    fn tag_bits(self) -> u32 {
        let count = self.tables().len() as u32;
        u32::BITS - (count - 1).leading_zeros()
    }

    /// Splits a coded value into `(table, row)`; `None` for a reserved tag.
    pub(super) fn decode(self, value: u32) -> Option<(u8, u32)> {
        let bits = self.tag_bits();
        let tag = (value & ((1 << bits) - 1)) as usize;
        let table = (*self.tables().get(tag)?)?;
        Some((table, value >> bits))
    }
}

#[derive(Debug, Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Index(u8),
    Coded(Coded),
}

use Coded as C;
use Col::{Blob, Guid, Index, Str, U16, U32};

/// Column layout of every table, II.22.2 through II.22.39, indexed by table id.
const SCHEMA: [&[Col]; TABLE_COUNT] = [
    /* Module */ &[U16, Str, Guid, Guid, Guid],
    /* TypeRef */ &[Col::Coded(C::ResolutionScope), Str, Str],
    /* TypeDef */ &[U32, Str, Str, Col::Coded(C::TypeDefOrRef), Index(FIELD), Index(METHOD_DEF)],
    /* FieldPtr */ &[Index(FIELD)],
    /* Field */ &[U16, Str, Blob],
    /* MethodPtr */ &[Index(METHOD_DEF)],
    /* MethodDef */ &[U32, U16, U16, Str, Blob, Index(PARAM)],
    /* ParamPtr */ &[Index(PARAM)],
    /* Param */ &[U16, U16, Str],
    /* InterfaceImpl */ &[Index(TYPE_DEF), Col::Coded(C::TypeDefOrRef)],
    /* MemberRef */ &[Col::Coded(C::MemberRefParent), Str, Blob],
    // II.22.9: Type is a 1-byte constant followed by a 1-byte zero pad, so two bytes in all.
    /* Constant */
    &[U16, Col::Coded(C::HasConstant), Blob],
    /* CustomAttribute */ &[Col::Coded(C::HasCustomAttribute), Col::Coded(C::CustomAttributeType), Blob],
    /* FieldMarshal */ &[Col::Coded(C::HasFieldMarshal), Blob],
    /* DeclSecurity */ &[U16, Col::Coded(C::HasDeclSecurity), Blob],
    /* ClassLayout */ &[U16, U32, Index(TYPE_DEF)],
    /* FieldLayout */ &[U32, Index(FIELD)],
    /* StandAloneSig */ &[Blob],
    /* EventMap */ &[Index(TYPE_DEF), Index(EVENT)],
    /* EventPtr */ &[Index(EVENT)],
    /* Event */ &[U16, Str, Col::Coded(C::TypeDefOrRef)],
    /* PropertyMap */ &[Index(TYPE_DEF), Index(PROPERTY)],
    /* PropertyPtr */ &[Index(PROPERTY)],
    /* Property */ &[U16, Str, Blob],
    /* MethodSemantics */ &[U16, Index(METHOD_DEF), Col::Coded(C::HasSemantics)],
    /* MethodImpl */ &[Index(TYPE_DEF), Col::Coded(C::MethodDefOrRef), Col::Coded(C::MethodDefOrRef)],
    /* ModuleRef */ &[Str],
    /* TypeSpec */ &[Blob],
    /* ImplMap */ &[U16, Col::Coded(C::MemberForwarded), Str, Index(MODULE_REF)],
    /* FieldRVA */ &[U32, Index(FIELD)],
    /* EncLog */ &[U32, U32],
    /* EncMap */ &[U32],
    /* Assembly */ &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
    /* AssemblyProcessor */ &[U32],
    /* AssemblyOS */ &[U32, U32, U32],
    /* AssemblyRef */ &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
    /* AssemblyRefProcessor */ &[U32, Index(ASSEMBLY_REF)],
    /* AssemblyRefOS */ &[U32, U32, U32, Index(ASSEMBLY_REF)],
    /* File */ &[U32, Str, Blob],
    /* ExportedType */ &[U32, U32, Str, Str, Col::Coded(C::Implementation)],
    /* ManifestResource */ &[U32, U32, Str, Col::Coded(C::Implementation)],
    /* NestedClass */ &[Index(TYPE_DEF), Index(TYPE_DEF)],
    /* GenericParam */ &[U16, U16, Col::Coded(C::TypeOrMethodDef), Str],
    /* MethodSpec */ &[Col::Coded(C::MethodDefOrRef), Blob],
    /* GenericParamConstraint */ &[Index(GENERIC_PARAM), Col::Coded(C::TypeDefOrRef)],
];

/// Where one table lives within the stream, and the byte offset and width of each of its columns.
#[derive(Debug, Clone, Default)]
struct Layout {
    offset: usize,
    row_size: usize,
    /// Rows that actually fit in the stream, which is fewer than declared for a truncated stream.
    readable: u32,
    columns: Vec<(usize, usize)>,
}

#[derive(Debug)]
pub(super) struct Tables<'a> {
    stream: &'a [u8],
    /// Declared row counts for all 64 possible table ids.
    pub(super) declared: [u32; 64],
    layouts: Vec<Layout>,
}

/// II.24.2.6 HeapSizes bits: a set bit widens that heap's indexes to 4 bytes.
const WIDE_STRINGS: u8 = 0x01;
const WIDE_GUIDS: u8 = 0x02;
const WIDE_BLOBS: u8 = 0x04;
/// Not in ECMA-335, but the CLR honours it: an extra 4-byte value follows the row counts.
const EXTRA_DATA: u8 = 0x40;

impl<'a> Tables<'a> {
    /// Parses the table stream header and lays out every standard table. Problems become warnings: a table
    /// that does not fit is truncated to its readable rows and nothing after it is located. `all_wide` makes
    /// every heap, table and coded index 4 bytes, as a `#JTD` stream does for an uncompressed `#-` stream.
    pub(super) fn parse(stream: &'a [u8], all_wide: bool, warnings: &mut Warnings) -> Option<Self> {
        let Some(heap_sizes) = stream.get(6).copied() else {
            warnings.push("table stream too small for its header".to_owned());
            return None;
        };
        let valid = read_uint(stream, 8, 8, false)?;
        let mut declared = [0u32; 64];
        let mut cursor = 24usize;
        for (id, count) in declared.iter_mut().enumerate() {
            if valid & (1 << id) == 0 {
                continue;
            }
            let Some(rows) = read_u32(stream, cursor) else {
                warnings.push("table stream truncated in its row counts".to_owned());
                return None;
            };
            *count = rows;
            cursor += 4;
        }
        if heap_sizes & EXTRA_DATA != 0 {
            cursor += 4;
        }
        if valid >> TABLE_COUNT != 0 {
            warnings.push(format!("table stream marks non-standard tables present (valid {valid:#018x})"));
        }

        let heap_width = |bit: u8| if all_wide || heap_sizes & bit != 0 { 4 } else { 2 };
        let index_width = |table: u8| if all_wide || declared[usize::from(table)] > 0xFFFF { 4 } else { 2 };
        let coded_width = |coded: Coded| {
            let limit = 1u32 << (16 - coded.tag_bits());
            let largest = coded.tables().iter().flatten().map(|&table| declared[usize::from(table)]).max();
            if all_wide || largest.unwrap_or(0) >= limit { 4 } else { 2 }
        };

        let mut layouts = vec![Layout::default(); TABLE_COUNT];
        let mut offset = Some(cursor);
        for (id, layout) in layouts.iter_mut().enumerate() {
            let rows = declared[id];
            if rows == 0 {
                continue;
            }
            let mut columns = Vec::with_capacity(SCHEMA[id].len());
            let mut row_size = 0usize;
            for column in SCHEMA[id] {
                let width = match *column {
                    U16 => 2,
                    U32 => 4,
                    Str => heap_width(WIDE_STRINGS),
                    Guid => heap_width(WIDE_GUIDS),
                    Blob => heap_width(WIDE_BLOBS),
                    Index(table) => index_width(table),
                    Col::Coded(coded) => coded_width(coded),
                };
                columns.push((row_size, width));
                row_size += width;
            }
            let Some(start) = offset else { continue };
            let available = stream.len().saturating_sub(start) / row_size;
            let readable = u32::try_from(available).unwrap_or(u32::MAX).min(rows).min(MAX_ROWS);
            if readable < rows {
                warnings.push(format!(
                    "{} table declares {rows} rows but only {readable} are readable; later tables are skipped",
                    TABLE_NAMES[id]
                ));
                offset = None;
            } else {
                offset = (rows as usize).checked_mul(row_size).and_then(|size| start.checked_add(size));
            }
            *layout = Layout { offset: start, row_size, readable, columns };
        }
        Some(Self { stream, declared, layouts })
    }

    /// Rows of `table` that can be read: zero for an absent or unlocatable table.
    pub(super) fn rows(&self, table: u8) -> u32 {
        self.layouts.get(usize::from(table)).map_or(0, |layout| layout.readable)
    }

    /// Column `column` of 1-based `row` in `table`, widened to `u32`.
    pub(super) fn cell(&self, table: u8, row: u32, column: usize) -> Option<u32> {
        let layout = self.layouts.get(usize::from(table))?;
        if row == 0 || row > layout.readable {
            return None;
        }
        let &(column_offset, width) = layout.columns.get(column)?;
        let position = (row as usize - 1).checked_mul(layout.row_size)?.checked_add(layout.offset)?;
        read_uint(self.stream, position.checked_add(column_offset)?, width, false).map(|value| value as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_widths_follow_the_spec() {
        assert_eq!(Coded::TypeDefOrRef.tag_bits(), 2);
        assert_eq!(Coded::HasCustomAttribute.tag_bits(), 5);
        assert_eq!(Coded::MemberRefParent.tag_bits(), 3);
        assert_eq!(Coded::CustomAttributeType.tag_bits(), 3);
        assert_eq!(Coded::MethodDefOrRef.tag_bits(), 1);
        assert_eq!(Coded::ResolutionScope.tag_bits(), 2);
    }

    #[test]
    fn decodes_coded_indexes() {
        assert_eq!(Coded::TypeDefOrRef.decode(0x0D), Some((TYPE_REF, 3)));
        assert_eq!(Coded::CustomAttributeType.decode(0x0B), Some((MEMBER_REF, 1)));
        assert_eq!(Coded::CustomAttributeType.decode(0x08), None);
        assert_eq!(Coded::TypeDefOrRef.decode(0x03), None);
    }
}

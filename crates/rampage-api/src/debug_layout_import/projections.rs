//! Pure projection metadata and its canonical, non-JSON wire codec.
//!
//! A line has no newline and is exactly `p0`, or these 21 space-separated tokens in order:
//! `p1 opaque_vptr field_index unit_offset language dwarf_version address_size record_die member_die
//! record_byte_size record_alignment member_offset member_byte_size member_alignment pointer_die
//! pointer_byte_size pointer_alignment pointee_pointer_die pointee_pointer_byte_size
//! pointee_pointer_alignment subroutine_die`.
//! Numbers are unsigned canonical decimal u64 values, at most 20 digits, with no leading zero except `0`.
//! The six optional size/alignment facts use `-` for absence. Separators are single ASCII spaces only.
//! The one CU offset supplies every ID's unit offset; DIE offsets are absolute `.debug_info` offsets.
//! All five role IDs are distinct, greater than the CU offset and strictly below the 128 KiB section cap.
//! The ordered roles attest member.type -> pointer -> pointee_pointer -> subroutine, not an exact callback ABI.
//! `OpaqueVptr` itself records recognized artificial-member origin; absent producer facts stay absent.
//! Decoding validates bounded metadata only. Consumers must also validate it against the paired layout.

use rampage_decompiler::layout::{LayoutType, MAX_LAYOUT_SIZE, PlainStructLayout, ScalarKind};
use rampage_loaders::debug::{DebugLayoutSource, DebugLayoutTypeId};
use serde::Serialize;

use super::invalid;
use crate::ApiError;

pub(crate) const TYPE_MAGIC_V2: &str = "!rampage-plain-layout-v2\n";
pub(crate) const MAX_PROJECTION_LINE_BYTES: usize = 1024;
const MAX_DEBUG_INFO_BYTES: u64 = 128 * 1024;

/// Recognized producer origin of a deliberately opaque consumer field, not a native C++ ABI assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugLayoutProjection {
    OpaqueVptr {
        field_index: usize,
        record_id: DebugLayoutTypeId,
        member_id: DebugLayoutTypeId,
        source: DebugLayoutSource,
        record_byte_size: u64,
        record_alignment: u64,
        member_offset: u64,
        member_byte_size: Option<u64>,
        member_alignment: Option<u64>,
        pointer_id: DebugLayoutTypeId,
        pointer_byte_size: Option<u64>,
        pointer_alignment: Option<u64>,
        pointee_pointer_id: DebugLayoutTypeId,
        pointee_pointer_byte_size: Option<u64>,
        pointee_pointer_alignment: Option<u64>,
        subroutine_id: DebugLayoutTypeId,
    },
}

impl DebugLayoutProjection {
    fn validate_metadata(&self) -> Result<(), ApiError> {
        let Self::OpaqueVptr {
            field_index,
            record_id,
            member_id,
            source,
            record_byte_size,
            record_alignment,
            member_offset,
            member_byte_size,
            member_alignment,
            pointer_id,
            pointer_byte_size,
            pointer_alignment,
            pointee_pointer_id,
            pointee_pointer_byte_size,
            pointee_pointer_alignment,
            subroutine_id,
        } = self;
        if !source.is_cpp()
            || !matches!(source.dwarf_version, 4 | 5)
            || source.address_size != 8
            || source.unit_offset >= MAX_DEBUG_INFO_BYTES
        {
            return Err(invalid("opaque vptr projection has unsupported source context"));
        }
        let ids = [record_id, member_id, pointer_id, pointee_pointer_id, subroutine_id];
        for (index, id) in ids.iter().enumerate() {
            if id.unit_offset != source.unit_offset
                || id.die_offset <= source.unit_offset
                || id.die_offset >= MAX_DEBUG_INFO_BYTES
                || ids[..index].contains(id)
            {
                return Err(invalid("opaque vptr projection requires distinct bounded same-CU role identities"));
            }
        }
        if *field_index != 0
            || *member_offset != 0
            || *record_alignment != 8
            || *record_byte_size < 8
            || *record_byte_size > u64::from(MAX_LAYOUT_SIZE)
            || !record_byte_size.is_multiple_of(8)
        {
            return Err(invalid("opaque vptr projection has unsupported record or member shape"));
        }
        let optional_facts = [
            member_byte_size,
            member_alignment,
            pointer_byte_size,
            pointer_alignment,
            pointee_pointer_byte_size,
            pointee_pointer_alignment,
        ];
        if optional_facts.into_iter().any(|fact| fact.is_some_and(|value| value != 8)) {
            return Err(invalid("opaque vptr projection has conflicting producer size or alignment"));
        }
        Ok(())
    }
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |number| number.to_string())
}

pub(crate) fn encode_projection_line(projections: &[DebugLayoutProjection]) -> Result<String, ApiError> {
    let projection = match projections {
        [] => return Ok("p0".to_owned()),
        [projection] => projection,
        _ => return Err(invalid("a record permits at most one opaque vptr projection")),
    };
    projection.validate_metadata()?;
    let DebugLayoutProjection::OpaqueVptr {
        field_index,
        record_id,
        member_id,
        source,
        record_byte_size,
        record_alignment,
        member_offset,
        member_byte_size,
        member_alignment,
        pointer_id,
        pointer_byte_size,
        pointer_alignment,
        pointee_pointer_id,
        pointee_pointer_byte_size,
        pointee_pointer_alignment,
        subroutine_id,
    } = projection;
    let line = format!(
        "p1 opaque_vptr {field_index} {} {} {} {} {} {} {record_byte_size} {record_alignment} \
         {member_offset} {} {} {} {} {} {} {} {} {}",
        source.unit_offset,
        source.language,
        source.dwarf_version,
        source.address_size,
        record_id.die_offset,
        member_id.die_offset,
        optional_number(*member_byte_size),
        optional_number(*member_alignment),
        pointer_id.die_offset,
        optional_number(*pointer_byte_size),
        optional_number(*pointer_alignment),
        pointee_pointer_id.die_offset,
        optional_number(*pointee_pointer_byte_size),
        optional_number(*pointee_pointer_alignment),
        subroutine_id.die_offset,
    );
    if line.len() > MAX_PROJECTION_LINE_BYTES {
        return Err(invalid("projection line byte limit exceeded"));
    }
    Ok(line)
}

fn unsigned_decimal(token: &str) -> Result<u64, ApiError> {
    if token.is_empty()
        || token.len() > 20
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("projection number is not canonical unsigned decimal"));
    }
    token.parse().map_err(|_| invalid("projection number overflows u64"))
}

struct ProjectionTokens<'a> {
    tokens: std::str::Split<'a, char>,
}

impl<'a> ProjectionTokens<'a> {
    fn next(&mut self) -> Result<&'a str, ApiError> {
        self.tokens.next().filter(|token| !token.is_empty()).ok_or_else(|| invalid("missing projection token"))
    }

    fn number(&mut self) -> Result<u64, ApiError> {
        unsigned_decimal(self.next()?)
    }

    fn optional(&mut self) -> Result<Option<u64>, ApiError> {
        match self.next()? {
            "-" => Ok(None),
            token => unsigned_decimal(token).map(Some),
        }
    }

    fn id(&mut self, unit_offset: u64) -> Result<DebugLayoutTypeId, ApiError> {
        Ok(DebugLayoutTypeId { unit_offset, die_offset: self.number()? })
    }

    fn finish(&mut self) -> Result<(), ApiError> {
        if self.tokens.next().is_some() {
            return Err(invalid("extra projection token"));
        }
        Ok(())
    }
}

pub(crate) fn decode_projection_line(line: &str) -> Result<Vec<DebugLayoutProjection>, ApiError> {
    if line.len() > MAX_PROJECTION_LINE_BYTES {
        return Err(invalid("projection line byte limit exceeded"));
    }
    if line.bytes().any(|byte| byte != b' ' && !byte.is_ascii_graphic()) {
        return Err(invalid("projection line must use ASCII tokens and spaces only"));
    }
    let mut tokens = ProjectionTokens { tokens: line.split(' ') };
    match tokens.next()? {
        "p0" => {
            tokens.finish()?;
            return Ok(Vec::new());
        }
        "p1" => {}
        _ => return Err(invalid("unknown projection line version")),
    }
    if tokens.next()? != "opaque_vptr" {
        return Err(invalid("unknown projection kind"));
    }
    let field_index = usize::try_from(tokens.number()?).map_err(|_| invalid("projection field index overflows"))?;
    let unit_offset = tokens.number()?;
    let source = DebugLayoutSource {
        unit_offset,
        language: u16::try_from(tokens.number()?).map_err(|_| invalid("projection language overflows"))?,
        dwarf_version: u16::try_from(tokens.number()?).map_err(|_| invalid("projection DWARF version overflows"))?,
        address_size: u8::try_from(tokens.number()?).map_err(|_| invalid("projection address size overflows"))?,
    };
    let projection = DebugLayoutProjection::OpaqueVptr {
        field_index,
        record_id: tokens.id(unit_offset)?,
        member_id: tokens.id(unit_offset)?,
        source,
        record_byte_size: tokens.number()?,
        record_alignment: tokens.number()?,
        member_offset: tokens.number()?,
        member_byte_size: tokens.optional()?,
        member_alignment: tokens.optional()?,
        pointer_id: tokens.id(unit_offset)?,
        pointer_byte_size: tokens.optional()?,
        pointer_alignment: tokens.optional()?,
        pointee_pointer_id: tokens.id(unit_offset)?,
        pointee_pointer_byte_size: tokens.optional()?,
        pointee_pointer_alignment: tokens.optional()?,
        subroutine_id: tokens.id(unit_offset)?,
    };
    tokens.finish()?;
    projection.validate_metadata()?;
    Ok(vec![projection])
}

pub(crate) fn validate_projections(
    layout: &PlainStructLayout,
    projections: &[DebugLayoutProjection],
) -> Result<(), ApiError> {
    layout.validate().map_err(|error| invalid(&error.to_string()))?;
    let projection = match projections {
        [] => return Ok(()),
        [projection] => projection,
        _ => return Err(invalid("a record permits at most one opaque vptr projection")),
    };
    projection.validate_metadata()?;
    let DebugLayoutProjection::OpaqueVptr { field_index, record_id, record_byte_size, record_alignment, .. } =
        projection;
    let prefix = format!("debug_layout_{:x}_{:x}", record_id.unit_offset, record_id.die_offset);
    if layout.name.strip_prefix(&prefix).is_none_or(|suffix| !suffix.is_empty() && !suffix.starts_with('_')) {
        return Err(invalid("opaque vptr projection record identity disagrees with the layout name"));
    }
    if *record_byte_size != u64::from(layout.size) || *record_alignment != u64::from(layout.alignment) {
        return Err(invalid("opaque vptr projection record extent disagrees with the consumer layout"));
    }
    let field = layout.fields.get(*field_index).ok_or_else(|| invalid("missing opaque vptr consumer field"))?;
    if field.name != "rampage_vptr" || field.offset != 0 || field.size != 8 {
        return Err(invalid("opaque vptr projection disagrees with the consumer field name, offset or width"));
    }
    if !matches!(&field.ty,
        LayoutType::Pointer { name, size: 8, alignment: 8, pointee }
            if name.is_empty()
                && pointee.name == "void"
                && pointee.kind == ScalarKind::Void
                && pointee.size == 0
                && pointee.alignment == 1)
    {
        return Err(invalid("opaque vptr consumer field must be the exact unnamed eight-byte void pointer"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rampage_decompiler::layout::{LayoutField, LayoutOrganization, LayoutScalar};

    use super::*;

    const UNKNOWN_FACTS: &str = "p1 opaque_vptr 0 16 4 5 8 32 40 16 8 0 - - 48 - - 56 - - 64";
    const PRESENT_FACTS: &str = "p1 opaque_vptr 0 16 4 5 8 32 40 16 8 0 8 8 48 8 8 56 8 8 64";

    fn id(die_offset: u64) -> DebugLayoutTypeId {
        DebugLayoutTypeId { unit_offset: 16, die_offset }
    }

    fn projection() -> DebugLayoutProjection {
        DebugLayoutProjection::OpaqueVptr {
            field_index: 0,
            record_id: id(32),
            member_id: id(40),
            source: DebugLayoutSource { unit_offset: 16, language: 4, dwarf_version: 5, address_size: 8 },
            record_byte_size: 16,
            record_alignment: 8,
            member_offset: 0,
            member_byte_size: None,
            member_alignment: None,
            pointer_id: id(48),
            pointer_byte_size: None,
            pointer_alignment: None,
            pointee_pointer_id: id(56),
            pointee_pointer_byte_size: None,
            pointee_pointer_alignment: None,
            subroutine_id: id(64),
        }
    }

    fn layout() -> PlainStructLayout {
        PlainStructLayout {
            name: "debug_layout_10_20_Widget".to_owned(),
            size: 16,
            alignment: 8,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: vec![LayoutField {
                name: "rampage_vptr".to_owned(),
                offset: 0,
                size: 8,
                ty: LayoutType::Pointer {
                    name: String::new(),
                    size: 8,
                    alignment: 8,
                    pointee: LayoutScalar { name: "void".to_owned(), kind: ScalarKind::Void, size: 0, alignment: 1 },
                },
            }],
        }
    }

    fn replace_token(line: &str, index: usize, value: &str) -> String {
        let mut tokens: Vec<_> = line.split(' ').collect();
        tokens[index] = value;
        tokens.join(" ")
    }

    fn assert_metadata_rejected(change: impl FnOnce(&mut DebugLayoutProjection)) {
        let mut candidate = projection();
        change(&mut candidate);
        assert!(encode_projection_line(std::slice::from_ref(&candidate)).is_err(), "{candidate:?}");
        assert!(validate_projections(&layout(), &[candidate]).is_err());
    }

    fn assert_layout_rejected(change: impl FnOnce(&mut PlainStructLayout)) {
        let mut candidate = layout();
        change(&mut candidate);
        assert!(validate_projections(&candidate, &[projection()]).is_err(), "{candidate:?}");
    }

    #[test]
    fn canonical_codec_preserves_unknown_and_present_producer_facts_without_promotion() {
        assert_eq!(encode_projection_line(&[]).unwrap(), "p0");
        assert!(decode_projection_line("p0").unwrap().is_empty());
        assert_eq!(encode_projection_line(&[projection()]).unwrap(), UNKNOWN_FACTS);
        assert_eq!(decode_projection_line(UNKNOWN_FACTS).unwrap(), vec![projection()]);
        let mut present = projection();
        let DebugLayoutProjection::OpaqueVptr {
            member_byte_size,
            member_alignment,
            pointer_byte_size,
            pointer_alignment,
            pointee_pointer_byte_size,
            pointee_pointer_alignment,
            ..
        } = &mut present;
        for fact in [
            member_byte_size,
            member_alignment,
            pointer_byte_size,
            pointer_alignment,
            pointee_pointer_byte_size,
            pointee_pointer_alignment,
        ] {
            *fact = Some(8);
        }
        assert_eq!(encode_projection_line(std::slice::from_ref(&present)).unwrap(), PRESENT_FACTS);
        assert_eq!(decode_projection_line(PRESENT_FACTS).unwrap(), vec![present]);
        for line in [UNKNOWN_FACTS, PRESENT_FACTS] {
            validate_projections(&layout(), &decode_projection_line(line).unwrap()).unwrap();
        }
        for index in [12, 13, 15, 16, 18, 19] {
            let mixed = replace_token(UNKNOWN_FACTS, index, "8");
            let decoded = decode_projection_line(&mixed).unwrap();
            assert_eq!(encode_projection_line(&decoded).unwrap(), mixed);
            assert_ne!(decoded, vec![projection()]);
        }
    }

    #[test]
    fn role_order_is_retained_without_assuming_monotonically_increasing_die_offsets() {
        let mut candidate = projection();
        let DebugLayoutProjection::OpaqueVptr { member_id, pointer_id, pointee_pointer_id, subroutine_id, .. } =
            &mut candidate;
        *member_id = id(64);
        *pointer_id = id(56);
        *pointee_pointer_id = id(48);
        *subroutine_id = id(40);
        let line = "p1 opaque_vptr 0 16 4 5 8 32 64 16 8 0 - - 56 - - 48 - - 40";
        assert_eq!(encode_projection_line(std::slice::from_ref(&candidate)).unwrap(), line);
        assert_eq!(decode_projection_line(line).unwrap(), vec![candidate]);
        validate_projections(&layout(), &decode_projection_line(line).unwrap()).unwrap();
    }

    #[test]
    fn grammar_rejects_noncanonical_framing_versions_kinds_and_token_counts() {
        for line in [
            "",
            "p2",
            "p01",
            "p0 p0",
            " p0",
            "p0 ",
            "p0\t",
            "p0\r",
            "p0\n",
            "p0\u{a0}",
            "p1",
            "p1 opaque_vptr",
            "p1 unknown",
        ] {
            assert!(decode_projection_line(line).is_err(), "{line:?}");
        }
        for candidate in [
            format!("{UNKNOWN_FACTS} 0"),
            format!("{UNKNOWN_FACTS} p0"),
            format!(" {UNKNOWN_FACTS}"),
            format!("{UNKNOWN_FACTS} "),
            UNKNOWN_FACTS.replacen(' ', "  ", 1),
            UNKNOWN_FACTS.replacen(' ', "\t", 1),
            UNKNOWN_FACTS.replacen(' ', "\r", 1),
            UNKNOWN_FACTS.replacen(' ', "\u{a0}", 1),
            UNKNOWN_FACTS.replace("opaque_vptr", "opaque_vptrs"),
        ] {
            assert!(decode_projection_line(&candidate).is_err(), "{candidate:?}");
        }
        for end in 0..UNKNOWN_FACTS.split(' ').count() {
            let truncated = UNKNOWN_FACTS.split(' ').take(end).collect::<Vec<_>>().join(" ");
            assert!(decode_projection_line(&truncated).is_err(), "{truncated:?}");
        }
    }

    #[test]
    fn decimal_parser_checks_canonical_form_u64_overflow_and_typed_narrowing() {
        assert_eq!(unsigned_decimal("0").unwrap(), 0);
        assert_eq!(unsigned_decimal("18446744073709551615").unwrap(), u64::MAX);
        for token in ["", "00", "08", "+8", "-8", "8.0", "0x8", "8e0", "８", "18446744073709551616"] {
            assert!(unsigned_decimal(token).is_err(), "{token:?}");
        }
        assert!(unsigned_decimal("100000000000000000000").is_err());
        for (index, value) in [
            (2, "00"),
            (3, "+16"),
            (4, "65536"),
            (5, "65536"),
            (6, "256"),
            (7, "18446744073709551616"),
            (9, "100000000000000000000"),
            (12, "none"),
            (13, "08"),
            (20, "-"),
        ] {
            assert!(decode_projection_line(&replace_token(UNKNOWN_FACTS, index, value)).is_err());
        }
    }

    #[test]
    fn oversized_lines_are_rejected_before_token_iteration() {
        for line in [
            "x".repeat(MAX_PROJECTION_LINE_BYTES + 1),
            format!("p0{}", " ".repeat(MAX_PROJECTION_LINE_BYTES)),
            format!("p1{}", " 0".repeat(MAX_PROJECTION_LINE_BYTES)),
        ] {
            let error = decode_projection_line(&line).unwrap_err().to_string();
            assert!(error.contains("projection line byte limit exceeded"), "{error}");
        }
        assert!(decode_projection_line(&" ".repeat(MAX_PROJECTION_LINE_BYTES)).is_err());
    }

    #[test]
    fn source_context_accepts_only_supported_cpp_versions_and_eight_byte_addresses() {
        for language in [4, 26, 33, 42] {
            for version in [4, 5] {
                let line = replace_token(UNKNOWN_FACTS, 4, &language.to_string());
                let line = replace_token(&line, 5, &version.to_string());
                let decoded = decode_projection_line(&line).unwrap();
                validate_projections(&layout(), &decoded).unwrap();
            }
        }
        for (index, value) in [(4, "2"), (4, "25"), (4, "65535"), (5, "3"), (5, "6"), (6, "4"), (6, "0")] {
            assert!(decode_projection_line(&replace_token(UNKNOWN_FACTS, index, value)).is_err());
        }
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { source, .. } = projection;
            source.unit_offset += 1;
        });
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { source, .. } = projection;
            source.language = 2;
        });
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { source, .. } = projection;
            source.dwarf_version = 3;
        });
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { source, .. } = projection;
            source.address_size = 4;
        });
    }

    #[test]
    fn metadata_rejects_foreign_cyclic_and_out_of_budget_role_identities() {
        for role in 0..5 {
            for invalid_id in [
                DebugLayoutTypeId { unit_offset: 17, die_offset: 80 },
                id(16),
                id(0),
                id(MAX_DEBUG_INFO_BYTES),
                id(u64::MAX),
            ] {
                assert_metadata_rejected(|projection| {
                    let DebugLayoutProjection::OpaqueVptr {
                        record_id,
                        member_id,
                        pointer_id,
                        pointee_pointer_id,
                        subroutine_id,
                        ..
                    } = projection;
                    let ids = [record_id, member_id, pointer_id, pointee_pointer_id, subroutine_id];
                    *ids.into_iter().nth(role).unwrap() = invalid_id;
                });
            }
        }
        for first in 0..5 {
            for second in first + 1..5 {
                assert_metadata_rejected(|projection| {
                    let DebugLayoutProjection::OpaqueVptr {
                        record_id,
                        member_id,
                        pointer_id,
                        pointee_pointer_id,
                        subroutine_id,
                        ..
                    } = projection;
                    let ids = [record_id, member_id, pointer_id, pointee_pointer_id, subroutine_id];
                    *ids[second] = *ids[first];
                });
            }
        }
        assert!(decode_projection_line(&replace_token(UNKNOWN_FACTS, 3, "131072")).is_err());
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { source, .. } = projection;
            source.unit_offset = MAX_DEBUG_INFO_BYTES;
        });
        let mut edge = projection();
        let DebugLayoutProjection::OpaqueVptr { subroutine_id, .. } = &mut edge;
        subroutine_id.die_offset = MAX_DEBUG_INFO_BYTES - 1;
        assert!(encode_projection_line(&[edge]).is_ok());
        let zero_unit = replace_token(UNKNOWN_FACTS, 3, "0");
        let mut zero_layout = layout();
        zero_layout.name = "debug_layout_0_20_Widget".to_owned();
        validate_projections(&zero_layout, &decode_projection_line(&zero_unit).unwrap()).unwrap();
    }

    #[test]
    fn metadata_rejects_wrong_field_record_shape_and_every_conflicting_optional_fact() {
        for (index, value) in [(2, "1"), (9, "0"), (9, "7"), (9, "9"), (9, "1048584"), (10, "4"), (11, "8")] {
            assert!(decode_projection_line(&replace_token(UNKNOWN_FACTS, index, value)).is_err());
        }
        for fact_index in 0..6 {
            for value in [0, 1, 4, 16, u64::MAX] {
                assert_metadata_rejected(|projection| {
                    let DebugLayoutProjection::OpaqueVptr {
                        member_byte_size,
                        member_alignment,
                        pointer_byte_size,
                        pointer_alignment,
                        pointee_pointer_byte_size,
                        pointee_pointer_alignment,
                        ..
                    } = projection;
                    let facts = [
                        member_byte_size,
                        member_alignment,
                        pointer_byte_size,
                        pointer_alignment,
                        pointee_pointer_byte_size,
                        pointee_pointer_alignment,
                    ];
                    *facts.into_iter().nth(fact_index).unwrap() = Some(value);
                });
            }
        }
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { field_index, .. } = projection;
            *field_index = usize::MAX;
        });
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { member_offset, .. } = projection;
            *member_offset = 8;
        });
        assert_metadata_rejected(|projection| {
            let DebugLayoutProjection::OpaqueVptr { record_alignment, .. } = projection;
            *record_alignment = 4;
        });
    }

    #[test]
    fn consumer_projection_requires_exact_name_offset_width_pointer_and_void_descriptor() {
        validate_projections(&layout(), &[projection()]).unwrap();
        assert_layout_rejected(|layout| layout.fields[0].name = "vptr".to_owned());
        assert_layout_rejected(|layout| layout.fields[0].offset = 8);
        assert_layout_rejected(|layout| layout.fields[0].size = 4);
        assert_layout_rejected(|layout| {
            layout.fields[0].ty = LayoutType::Scalar {
                scalar: LayoutScalar {
                    name: "uint8".to_owned(),
                    kind: ScalarKind::UnsignedInteger,
                    size: 8,
                    alignment: 8,
                },
            };
        });
        for property in 0..7 {
            assert_layout_rejected(|layout| {
                let LayoutType::Pointer { name, size, alignment, pointee } = &mut layout.fields[0].ty else {
                    panic!("fixture must have a pointer");
                };
                match property {
                    0 => *name = "alias".to_owned(),
                    1 => *size = 4,
                    2 => *alignment = 4,
                    3 => pointee.name = "not_void".to_owned(),
                    4 => {
                        pointee.kind = ScalarKind::UnsignedInteger;
                        pointee.size = 1;
                    }
                    5 => pointee.size = 1,
                    6 => pointee.alignment = 2,
                    _ => unreachable!(),
                }
            });
        }
    }

    #[test]
    fn consumer_record_extent_and_identity_prefix_are_bound_without_false_prefix_matches() {
        for name in ["debug_layout_10_20", "debug_layout_10_20_Widget", "debug_layout_10_20_"] {
            let mut candidate = layout();
            candidate.name = name.to_owned();
            validate_projections(&candidate, &[projection()]).unwrap();
        }
        for name in [
            "Widget",
            "debug_layout_10_200_Widget",
            "debug_layout_10_20Widget",
            "debug_layout_11_20_Widget",
            "debug_layout_10_21_Widget",
            "debug_layout_10_020_Widget",
        ] {
            assert_layout_rejected(|layout| layout.name = name.to_owned());
        }
        assert_layout_rejected(|layout| layout.size = 24);
        assert_layout_rejected(|layout| layout.alignment = 4);
        let mut changed = projection();
        let DebugLayoutProjection::OpaqueVptr { record_byte_size, .. } = &mut changed;
        *record_byte_size = 24;
        assert!(encode_projection_line(std::slice::from_ref(&changed)).is_ok());
        assert!(validate_projections(&layout(), &[changed]).is_err());
    }

    #[test]
    fn one_projection_limit_is_checked_by_both_encoder_and_layout_validator() {
        let projections = [projection(), projection()];
        assert!(encode_projection_line(&projections).is_err());
        assert!(validate_projections(&layout(), &projections).is_err());
    }

    #[test]
    fn empty_projection_lists_keep_ordinary_layout_validation_without_a_source_name_requirement() {
        let mut ordinary = layout();
        ordinary.name = "ordinary_record".to_owned();
        ordinary.fields[0].name = "ordinary_pointer".to_owned();
        validate_projections(&ordinary, &[]).unwrap();
        ordinary.fields[0].ty = LayoutType::Scalar {
            scalar: LayoutScalar { name: "uint8".to_owned(), kind: ScalarKind::UnsignedInteger, size: 8, alignment: 8 },
        };
        validate_projections(&ordinary, &[]).unwrap();
        ordinary.size = 0;
        assert!(validate_projections(&ordinary, &[]).is_err());
    }
}

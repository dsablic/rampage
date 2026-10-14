//! Blob signatures (II.23.2) rendered as ILAsm-style text (`int32 Combine<T1>(T1)`), and fixed/named arguments of
//! custom attribute values (II.23.3).
//!
//! Signatures are hostile input that can nest (a TypeSpec naming a TypeSpec) and fan out (generic arguments), so a
//! tiny blob could expand without bound. Every decode is capped in depth, nodes and text, and all decodes of one
//! image share a work budget charged for both the text rendered and the blob bytes read; past any cap the
//! signature is unreadable rather than partial.

use std::cell::Cell;

use super::heaps::compressed_length;
use super::tables::{self, Coded};
use super::{NamedArgument, NamedArgumentKind};

/// What a signature that cannot be decoded, or that exceeds a cap, renders as.
pub const UNREADABLE: &str = "<unreadable>";
const MAX_DEPTH: u32 = 32;
const MAX_NODES: u32 = 512;
pub(super) const MAX_TEXT: usize = 8192;
/// Array ranks and generic parameter counts above this are treated as corrupt rather than rendered.
pub(super) const MAX_ARITY: u32 = 64;
/// Text rendered plus blob bytes read across every signature of one image, so a file full of expanding or
/// re-referenced signatures stays cheap.
pub(super) const TOTAL_BUDGET: usize = 64 << 20;
/// Longest string or type-name argument kept from a custom attribute value.
const MAX_ARGUMENT_BYTES: usize = 1024;
const UNKNOWN_ENUM: &str = "enum underlying type is unknown (external or unsupported metadata)";

const ELEMENT_STRING: u8 = 0x0E;
const ELEMENT_SENTINEL: u8 = 0x41;
const FIELD_SIGNATURE: u8 = 0x06;
const PROPERTY_SIGNATURE: u8 = 0x08;
const LOCAL_SIGNATURE: u8 = 0x07;
const GENERIC_INSTANTIATION: u8 = 0x0A;
/// `ldloc` takes a 16-bit index (III.3.43), so a method has at most this many locals.
const MAX_LOCALS: u32 = 0xFFFF;
const SIGNATURE_GENERIC: u8 = 0x10;
const SIGNATURE_HAS_THIS: u8 = 0x20;
const SIGNATURE_EXPLICIT_THIS: u8 = 0x40;

/// Name lookups a signature needs from the tables.
pub(super) trait Resolve {
    /// `Namespace.Name` of a TypeDef or TypeRef row, or `None` when the row does not exist.
    fn type_name(&self, table: u8, row: u32) -> Option<String>;
    /// The signature blob of a TypeSpec row.
    fn type_spec(&self, row: u32) -> Option<&[u8]>;
    /// Only enums whose underlying integral type is verified in this image resolve.
    fn enum_underlying(&self, _table: u8, _row: u32) -> Option<u8> {
        None
    }
    fn named_enum_underlying(&self, _name: &str) -> Option<u8> {
        None
    }
}

/// Generic parameter names, `(number, name)` sorted by number, of the type and method a signature belongs to. A
/// `VAR` or `MVAR` without a name renders as ILAsm's `!n` or `!!n`.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Generics<'g> {
    pub(super) type_params: &'g [(u32, String)],
    pub(super) method_params: &'g [(u32, String)],
}

/// The name of generic parameter `number` from `params`, which is sorted by number.
fn generic_name(params: &[(u32, String)], number: u32, prefix: &str) -> String {
    match params.binary_search_by_key(&number, |&(number, _)| number) {
        Ok(index) => params[index].1.clone(),
        Err(_) => format!("{prefix}{number}"),
    }
}

/// What a custom attribute value can hold for a parameter of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Kind {
    /// A bare ELEMENT_TYPE (primitive, string, object, ...).
    Element(u8),
    /// `System.Type`, stored in an attribute value as the type's name.
    SystemType,
    Enum(u8, u32),
    NamedEnum(u8),
    Array(Box<Ty>),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ty {
    pub(super) text: String,
    pub(super) kind: Kind,
    shape: TypeShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeShape {
    Named,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MethodSig {
    has_this: bool,
    explicit_this: bool,
    convention: u8,
    generic_count: u32,
    ret: Ty,
    /// Parameter types; a vararg sentinel appears as a `...` entry of kind `Other`.
    pub(super) params: Vec<Ty>,
}

impl MethodSig {
    /// `[instance ][callconv ]ret name<generics>(params)`.
    pub(super) fn render(&self, name: &str, generics: &Generics) -> String {
        let mut text = String::new();
        if self.has_this {
            text.push_str("instance ");
        }
        if self.explicit_this {
            text.push_str("explicit ");
        }
        text.push_str(match self.convention {
            1 => "unmanaged cdecl ",
            2 => "unmanaged stdcall ",
            3 => "unmanaged thiscall ",
            4 => "unmanaged fastcall ",
            5 => "vararg ",
            _ => "",
        });
        text.push_str(&self.ret.text);
        text.push(' ');
        text.push_str(name);
        if self.generic_count > 0 {
            let names: Vec<String> =
                (0..self.generic_count).map(|number| generic_name(generics.method_params, number, "!!")).collect();
            text.push_str(&format!("<{}>", names.join(", ")));
        }
        let params: Vec<&str> = self.params.iter().map(|param| param.text.as_str()).collect();
        text.push_str(&format!("({})", params.join(", ")));
        text
    }
}

/// A decoded MemberRef or StandAloneMethod-style signature: a method, or a field's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MemberSig {
    Method(MethodSig),
    Field(Ty),
}

impl MemberSig {
    pub(super) fn render(&self, name: &str, generics: &Generics) -> String {
        match self {
            Self::Method(method) => method.render(name, generics),
            Self::Field(ty) => format!("{} {name}", ty.text),
        }
    }
}

struct Cursor<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Cursor<'b> {
    fn new(bytes: &'b [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn take(&mut self, count: usize) -> Option<&'b [u8]> {
        let bytes = self.bytes.get(self.at..self.at.checked_add(count)?)?;
        self.at += count;
        Some(bytes)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A compressed unsigned integer (II.23.2).
    fn compressed(&mut self) -> Option<u32> {
        let (value, used) = compressed_length(self.bytes.get(self.at..)?)?;
        self.at += used;
        u32::try_from(value).ok()
    }
}

/// One signature decode: its generic context, its own caps, and the image-wide work budget.
pub(super) struct Reader<'r> {
    resolve: &'r dyn Resolve,
    generics: Generics<'r>,
    budget: &'r Cell<usize>,
    nodes: u32,
    text: usize,
    attribute_error: Option<&'static str>,
    strict_types: bool,
}

#[derive(Clone, Copy)]
enum TypeContext {
    Type,
    PropertyResult,
    Parameter,
    Return,
    PointerTarget,
}

impl<'r> Reader<'r> {
    pub(super) fn new(resolve: &'r dyn Resolve, generics: Generics<'r>, budget: &'r Cell<usize>) -> Self {
        Self { resolve, generics, budget, nodes: 0, text: 0, attribute_error: None, strict_types: false }
    }

    /// A MethodDefSig or MethodRefSig (II.23.2.1, II.23.2.2).
    pub(super) fn method(&mut self, blob: &[u8]) -> Option<MethodSig> {
        self.read(blob, |reader, cursor| reader.method_at(cursor, 0))
    }

    /// A field's type from a FieldSig (II.23.2.4).
    pub(super) fn field(&mut self, blob: &[u8]) -> Option<Ty> {
        self.read(blob, |reader, cursor| {
            if cursor.byte()? != FIELD_SIGNATURE {
                return None;
            }
            reader.ty(cursor, 0)
        })
    }

    /// A PropertySig (II.23.2.5): PROPERTY, optionally HASTHIS, then its type and index parameters.
    pub(super) fn property(&mut self, blob: &[u8]) -> Option<MethodSig> {
        let previous = std::mem::replace(&mut self.strict_types, true);
        let property = self.read(blob, |reader, cursor| {
            let first = cursor.byte()?;
            if first != PROPERTY_SIGNATURE && first != PROPERTY_SIGNATURE | SIGNATURE_HAS_THIS {
                return None;
            }
            let count = cursor.compressed()?;
            let ret = reader.ty_at(cursor, 0, TypeContext::PropertyResult)?;
            let params =
                (0..count).map(|_| reader.ty_at(cursor, 0, TypeContext::Parameter)).collect::<Option<Vec<_>>>()?;
            if cursor.at != blob.len() {
                return None;
            }
            Some(MethodSig {
                has_this: first & SIGNATURE_HAS_THIS != 0,
                explicit_this: false,
                convention: 0,
                generic_count: 0,
                ret,
                params,
            })
        });
        self.strict_types = previous;
        property
    }

    /// A MemberRef signature, which is either a field or a method signature.
    pub(super) fn member(&mut self, blob: &[u8]) -> Option<MemberSig> {
        if blob.first() == Some(&FIELD_SIGNATURE) {
            self.field(blob).map(MemberSig::Field)
        } else {
            self.method(blob).map(MemberSig::Method)
        }
    }

    /// A TypeSpec blob (II.23.2.14), which is a single type.
    pub(super) fn type_spec(&mut self, blob: &[u8]) -> Option<Ty> {
        self.read(blob, |reader, cursor| reader.ty(cursor, 0))
    }

    /// EventType is a table coded index, not a blob; failed lookups still spend shared work.
    pub(super) fn event_type(&mut self, value: u32) -> Option<Ty> {
        self.spend(1)?;
        let previous = std::mem::replace(&mut self.strict_types, true);
        self.nodes += 1;
        let ty = (|| {
            if self.nodes > MAX_NODES || self.budget.get() == 0 {
                return None;
            }
            let ty = self.type_def_or_ref_value(value, 0)?;
            self.charge_type(ty)
        })();
        self.strict_types = previous;
        ty
    }

    /// The local variable types of a LocalVarSig (II.23.2.6). Each local is capped as one signature would be.
    pub(super) fn locals(&mut self, blob: &[u8]) -> Option<Vec<Ty>> {
        self.read(blob, |reader, cursor| {
            if cursor.byte()? != LOCAL_SIGNATURE {
                return None;
            }
            let count = cursor.compressed()?;
            if count > MAX_LOCALS {
                return None;
            }
            let mut locals = Vec::new();
            // Every local consumes at least one byte, so a declared count past the blob fails at its end.
            for _ in 0..count {
                (reader.nodes, reader.text) = (0, 0);
                locals.push(reader.ty(cursor, 0)?);
            }
            Some(locals)
        })
    }

    /// The type arguments of a MethodSpec instantiation (II.23.2.15).
    pub(super) fn method_spec(&mut self, blob: &[u8]) -> Option<Vec<Ty>> {
        self.read(blob, |reader, cursor| {
            if cursor.byte()? != GENERIC_INSTANTIATION {
                return None;
            }
            let count = cursor.compressed()?;
            if count == 0 || count > MAX_ARITY {
                return None;
            }
            (0..count).map(|_| reader.ty(cursor, 0)).collect()
        })
    }

    /// Runs `decode` over `blob` and charges the bytes it read to the image-wide budget, whether or not it
    /// succeeded: a TypeSpec is re-read at every reference, so bytes that render no text are still work.
    fn read<T>(
        &mut self,
        blob: &[u8],
        decode: impl for<'c> FnOnce(&mut Self, &mut Cursor<'c>) -> Option<T>,
    ) -> Option<T> {
        let mut cursor = Cursor::new(blob);
        let decoded = decode(self, &mut cursor);
        self.spend(cursor.at)?;
        decoded
    }

    /// Takes `amount` from the image-wide budget; once it cannot, the budget is spent for every later decode.
    fn spend(&mut self, amount: usize) -> Option<()> {
        let left = self.budget.get().checked_sub(amount);
        self.budget.set(left.unwrap_or(0));
        left.map(drop)
    }

    fn method_at(&mut self, cursor: &mut Cursor, depth: u32) -> Option<MethodSig> {
        let first = cursor.byte()?;
        let convention = first & 0x0F;
        // 0 DEFAULT, 1-4 unmanaged C/stdcall/thiscall/fastcall, 5 VARARG; the rest are not method signatures.
        if convention > 5 {
            return None;
        }
        if self.strict_types
            && (first & 0x80 != 0
                || first & SIGNATURE_EXPLICIT_THIS != 0 && first & SIGNATURE_HAS_THIS == 0
                || first & SIGNATURE_GENERIC != 0 && !matches!(convention, 0 | 5))
        {
            return None;
        }
        let generic_count = if first & SIGNATURE_GENERIC != 0 { cursor.compressed()? } else { 0 };
        if generic_count > MAX_ARITY || self.strict_types && first & SIGNATURE_GENERIC != 0 && generic_count == 0 {
            return None;
        }
        let count = cursor.compressed()?;
        let ret = self.ty_at(cursor, depth + 1, TypeContext::Return)?;
        let mut params = Vec::new();
        let mut sentinel = false;
        // Every parameter consumes at least one byte, so a huge declared count fails at the blob's end.
        for _ in 0..count {
            if cursor.peek() == Some(ELEMENT_SENTINEL) {
                cursor.byte()?;
                if self.strict_types && (convention != 5 || sentinel) {
                    return None;
                }
                sentinel = true;
                params.push(Ty { text: "...".to_owned(), kind: Kind::Other, shape: TypeShape::Other });
            }
            params.push(self.ty_at(cursor, depth + 1, TypeContext::Parameter)?);
        }
        Some(MethodSig {
            has_this: first & SIGNATURE_HAS_THIS != 0,
            explicit_this: first & SIGNATURE_EXPLICIT_THIS != 0,
            convention,
            generic_count,
            ret,
            params,
        })
    }

    /// Charges rendered text against this signature's cap and the image-wide budget.
    fn charge(&mut self, text: String, kind: Kind) -> Option<Ty> {
        self.charge_type(Ty { text, kind, shape: TypeShape::Other })
    }

    fn charge_type(&mut self, ty: Ty) -> Option<Ty> {
        self.text = self.text.saturating_add(ty.text.len());
        self.spend(ty.text.len())?;
        (self.text <= MAX_TEXT).then_some(ty)
    }

    /// One Type (II.23.2.12), including the BYREF, TYPEDBYREF, VOID and custom-modifier prefixes that RetType,
    /// Param and FieldSig allow around it.
    fn ty(&mut self, cursor: &mut Cursor, depth: u32) -> Option<Ty> {
        self.ty_at(cursor, depth, TypeContext::Type)
    }

    fn ty_at(&mut self, cursor: &mut Cursor, depth: u32, context: TypeContext) -> Option<Ty> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES || self.budget.get() == 0 {
            return None;
        }
        let element = cursor.byte()?;
        if self.strict_types {
            let valid = match element {
                0x01 => matches!(context, TypeContext::Return | TypeContext::PointerTarget),
                0x10 => matches!(context, TypeContext::PropertyResult | TypeContext::Return | TypeContext::Parameter),
                0x16 => matches!(context, TypeContext::Return | TypeContext::Parameter),
                0x45 => false,
                _ => true,
            };
            if !valid {
                return None;
            }
        }
        let primitive = match element {
            0x01 => Some("void"),
            0x02 => Some("bool"),
            0x03 => Some("char"),
            0x04 => Some("int8"),
            0x05 => Some("uint8"),
            0x06 => Some("int16"),
            0x07 => Some("uint16"),
            0x08 => Some("int32"),
            0x09 => Some("uint32"),
            0x0A => Some("int64"),
            0x0B => Some("uint64"),
            0x0C => Some("float32"),
            0x0D => Some("float64"),
            ELEMENT_STRING => Some("string"),
            0x16 => Some("typedref"),
            0x18 => Some("native int"),
            0x19 => Some("native uint"),
            0x1C => Some("object"),
            _ => None,
        };
        if let Some(name) = primitive {
            return self.charge(name.to_owned(), Kind::Element(element));
        }
        let text = match element {
            0x0F => format!("{}*", self.ty_at(cursor, depth + 1, TypeContext::PointerTarget)?.text),
            0x10 => format!("{}&", self.ty(cursor, depth + 1)?.text),
            0x11 | 0x12 => {
                let token_at = cursor.at;
                let mut ty = self.type_def_or_ref(cursor, depth)?;
                ty.kind = if element == 0x12 && ty.text == "System.Type" {
                    Kind::SystemType
                } else if element == 0x11 {
                    let mut token = Cursor::new(&cursor.bytes[token_at..cursor.at]);
                    let (table, row) = Coded::TypeDefOrRef.decode(token.compressed()?)?;
                    Kind::Enum(table, row)
                } else {
                    Kind::Other
                };
                return self.charge_type(ty);
            }
            0x13 => generic_name(self.generics.type_params, cursor.compressed()?, "!"),
            0x1E => generic_name(self.generics.method_params, cursor.compressed()?, "!!"),
            0x14 => {
                let element = self.ty(cursor, depth + 1)?;
                let rank = cursor.compressed()?;
                if rank == 0 || rank > MAX_ARITY {
                    return None;
                }
                // ArrayShape (II.23.2.13): at most `rank` sizes, then at most `rank` lower bounds, which the text
                // does not show.
                for _ in 0..2 {
                    let count = cursor.compressed()?;
                    if count > rank {
                        return None;
                    }
                    for _ in 0..count {
                        cursor.compressed()?;
                    }
                }
                let commas = if rank == 1 { "*".to_owned() } else { ",".repeat(rank as usize - 1) };
                format!("{}[{commas}]", element.text)
            }
            0x15 => {
                if !matches!(cursor.byte()?, 0x11 | 0x12) {
                    return None;
                }
                let definition = self.type_def_or_ref(cursor, depth)?;
                if self.strict_types && definition.shape != TypeShape::Named {
                    return None;
                }
                let count = cursor.compressed()?;
                if count == 0 || count > MAX_ARITY {
                    return None;
                }
                let mut arguments = Vec::new();
                for _ in 0..count {
                    arguments.push(self.ty(cursor, depth + 1)?.text);
                }
                format!("{}<{}>", without_arity(&definition.text), arguments.join(", "))
            }
            0x1B => {
                let method = self.method_at(cursor, depth + 1)?;
                format!("method {}", method.render("*", &Generics::default()))
            }
            0x1D => {
                let inner = self.ty(cursor, depth + 1)?;
                return self.charge(format!("{}[]", inner.text), Kind::Array(Box::new(inner)));
            }
            0x1F | 0x20 => {
                let modifier = self.type_def_or_ref(cursor, depth)?;
                let inner = self.ty_at(cursor, depth + 1, context)?;
                let keyword = if element == 0x1F { "modreq" } else { "modopt" };
                return self.charge(format!("{} {keyword}({})", inner.text, modifier.text), inner.kind);
            }
            0x45 => format!("{} pinned", self.ty(cursor, depth + 1)?.text),
            _ => return None,
        };
        self.charge(text, Kind::Other)
    }

    /// A TypeDefOrRefOrSpecEncoded token (II.23.2.8), resolved to a name or a rendered TypeSpec.
    fn type_def_or_ref(&mut self, cursor: &mut Cursor, depth: u32) -> Option<Ty> {
        self.type_def_or_ref_value(cursor.compressed()?, depth)
    }

    fn type_def_or_ref_value(&mut self, value: u32, depth: u32) -> Option<Ty> {
        let (table, row) = Coded::TypeDefOrRef.decode(value)?;
        if table == tables::TYPE_SPEC {
            let blob = self.resolve.type_spec(row)?;
            let ty = self.read(blob, |reader, cursor| {
                let ty = reader.ty(cursor, depth + 1)?;
                if reader.strict_types && cursor.at != blob.len() {
                    return None;
                }
                Some(ty)
            })?;
            return Some(ty);
        }
        self.resolve.type_name(table, row).map(|text| Ty { text, kind: Kind::Other, shape: TypeShape::Named })
    }
}

/// `List`1` as `List`: the generic arguments that follow say the arity.
fn without_arity(name: &str) -> &str {
    match name.rsplit_once('`') {
        Some((base, arity)) if !arity.is_empty() && arity.bytes().all(|byte| byte.is_ascii_digit()) => base,
        _ => name,
    }
}

pub(super) struct AttributeValue {
    pub(super) arguments: Option<Vec<String>>,
    pub(super) named_arguments: Option<Vec<NamedArgument>>,
    pub(super) error: Option<&'static str>,
}

impl Reader<'_> {
    /// Fixed and named values share the signature depth/node/text caps and image-wide work budget.
    pub(super) fn attribute_arguments(&mut self, params: &[Ty], value: &[u8]) -> AttributeValue {
        let mut cursor = Cursor::new(value);
        let mut arguments = (|| {
            if cursor.array::<2>()? != [1, 0] {
                return None;
            }
            params.iter().map(|param| self.argument(&mut cursor, param, 0)).collect::<Option<Vec<_>>>()
        })();
        if self.spend(cursor.at).is_none() {
            arguments = None;
        }
        let fixed_end = cursor.at;
        let mut named_arguments = arguments.as_ref().and_then(|_| self.named_arguments(&mut cursor));
        if self.spend(cursor.at - fixed_end).is_none() {
            named_arguments = None;
        }
        let error = if arguments.is_none() || named_arguments.is_none() {
            Some(self.attribute_error.unwrap_or("attribute value is malformed, unsupported or exceeds rendering caps"))
        } else {
            None
        };
        AttributeValue { arguments, named_arguments, error }
    }

    fn attribute_node(&mut self, depth: u32) -> Option<()> {
        self.nodes += 1;
        (depth <= MAX_DEPTH && self.nodes <= MAX_NODES && self.budget.get() > 0).then_some(())
    }

    fn argument(&mut self, cursor: &mut Cursor, ty: &Ty, depth: u32) -> Option<String> {
        self.attribute_node(depth)?;
        let text = match &ty.kind {
            Kind::Element(element) => primitive_argument(cursor, *element)?,
            Kind::SystemType => ser_string(cursor)?
                .map_or_else(|| "null".to_owned(), |name| format!("typeof({}){}", name.text, name.cut())),
            Kind::Enum(table, row) => {
                let Some(element) = self.resolve.enum_underlying(*table, *row) else {
                    self.attribute_error = Some(UNKNOWN_ENUM);
                    return None;
                };
                format!("{}({})", ty.text, primitive_argument(cursor, element)?)
            }
            Kind::NamedEnum(element) => format!("{}({})", ty.text, primitive_argument(cursor, *element)?),
            Kind::Array(inner) => {
                let supported = match inner.kind {
                    Kind::Element(element) => matches!(element, 0x02..=0x0E),
                    Kind::SystemType | Kind::NamedEnum(_) => true,
                    Kind::Enum(table, row) => {
                        let known = self.resolve.enum_underlying(table, row).is_some();
                        if !known {
                            self.attribute_error = Some(UNKNOWN_ENUM);
                        }
                        known
                    }
                    Kind::Array(_) | Kind::Other => false,
                };
                if !supported {
                    return None;
                }
                let count = i32::from_le_bytes(cursor.array()?);
                if count == -1 {
                    "null".to_owned()
                } else {
                    if count < 0 || count as u32 > MAX_NODES {
                        return None;
                    }
                    let elements =
                        (0..count).map(|_| self.argument(cursor, inner, depth + 1)).collect::<Option<Vec<_>>>()?;
                    format!("[{}]", elements.join(", "))
                }
            }
            Kind::Other => return None,
        };
        self.charge(text, Kind::Other).map(|ty| ty.text)
    }

    fn named_arguments(&mut self, cursor: &mut Cursor) -> Option<Vec<NamedArgument>> {
        let count = u16::from_le_bytes(cursor.array()?);
        if u32::from(count) > MAX_NODES {
            return None;
        }
        let mut arguments = Vec::new();
        for _ in 0..count {
            self.attribute_node(0)?;
            let kind = match cursor.byte()? {
                0x53 => NamedArgumentKind::Field,
                0x54 => NamedArgumentKind::Property,
                _ => return None,
            };
            let ty = self.serialized_type(cursor, 0)?;
            let name = exact_ser_string(cursor)?;
            self.charge(name.clone(), Kind::Other)?;
            let value = self.argument(cursor, &ty, 0)?;
            arguments.push(NamedArgument { kind, name, argument_type: ty.text, value });
        }
        (cursor.at == cursor.bytes.len()).then_some(arguments)
    }

    fn serialized_type(&mut self, cursor: &mut Cursor, depth: u32) -> Option<Ty> {
        self.attribute_node(depth)?;
        let element = cursor.byte()?;
        if element == 0x1D {
            let inner = self.serialized_type(cursor, depth + 1)?;
            if matches!(inner.kind, Kind::Array(_)) {
                return None;
            }
            return self.charge(format!("{}[]", inner.text), Kind::Array(Box::new(inner)));
        }
        if element == 0x55 {
            let name = exact_ser_string(cursor)?;
            let Some(underlying) = self.resolve.named_enum_underlying(&name) else {
                self.attribute_error = Some(UNKNOWN_ENUM);
                return None;
            };
            return self.charge(name, Kind::NamedEnum(underlying));
        }
        if element == 0x50 {
            return self.charge("System.Type".to_owned(), Kind::SystemType);
        }
        if !matches!(element, 0x02..=0x0E) {
            return None;
        }
        self.ty(&mut Cursor::new(&[element]), depth)
    }
}

fn primitive_argument(cursor: &mut Cursor, element: u8) -> Option<String> {
    Some(match element {
        0x02 => (cursor.byte()? != 0).to_string(),
        0x03 => {
            let unit = u16::from_le_bytes(cursor.array()?);
            char::from_u32(u32::from(unit)).map_or_else(|| format!("'\\u{{{unit:04x}}}'"), |c| format!("{c:?}"))
        }
        0x04 => i8::from_le_bytes(cursor.array()?).to_string(),
        0x05 => u8::from_le_bytes(cursor.array()?).to_string(),
        0x06 => i16::from_le_bytes(cursor.array()?).to_string(),
        0x07 => u16::from_le_bytes(cursor.array()?).to_string(),
        0x08 => i32::from_le_bytes(cursor.array()?).to_string(),
        0x09 => u32::from_le_bytes(cursor.array()?).to_string(),
        0x0A => i64::from_le_bytes(cursor.array()?).to_string(),
        0x0B => u64::from_le_bytes(cursor.array()?).to_string(),
        0x0C => f32::from_le_bytes(cursor.array()?).to_string(),
        0x0D => f64::from_le_bytes(cursor.array()?).to_string(),
        ELEMENT_STRING => {
            ser_string(cursor)?.map_or_else(|| "null".to_owned(), |text| format!("{:?}{}", text.text, text.cut()))
        }
        _ => return None,
    })
}

/// Identifiers must be complete and valid UTF-8; truncated or lossy text must not resolve a different enum.
fn exact_ser_string(cursor: &mut Cursor) -> Option<String> {
    let length = usize::try_from(cursor.compressed()?).ok()?;
    if length > MAX_ARGUMENT_BYTES {
        return None;
    }
    std::str::from_utf8(cursor.take(length)?).ok().map(str::to_owned)
}

/// The kept text of a SerString, and its full length in bytes when the text was cut.
struct SerString {
    text: String,
    cut_from: Option<usize>,
}

impl SerString {
    /// The truncation mark to append after the rendered text: empty when nothing was cut.
    fn cut(&self) -> String {
        self.cut_from.map_or_else(String::new, |length| format!("... ({length} bytes)"))
    }
}

/// A SerString: 0xFF for null, else a compressed length and UTF-8 bytes. Kept text is capped, and cut on a
/// character boundary so the cap never invents a replacement character.
fn ser_string(cursor: &mut Cursor) -> Option<Option<SerString>> {
    if cursor.peek()? == 0xFF {
        cursor.byte();
        return Some(None);
    }
    let length = usize::try_from(cursor.compressed()?).ok()?;
    let bytes = cursor.take(length)?;
    if length <= MAX_ARGUMENT_BYTES {
        return Some(Some(SerString { text: String::from_utf8_lossy(bytes).into_owned(), cut_from: None }));
    }
    let mut kept = &bytes[..MAX_ARGUMENT_BYTES];
    // A character split by the cap is incomplete rather than invalid: drop its leading bytes.
    if let Err(error) = std::str::from_utf8(kept)
        && error.error_len().is_none()
    {
        kept = &kept[..error.valid_up_to()];
    }
    Some(Some(SerString { text: String::from_utf8_lossy(kept).into_owned(), cut_from: Some(length) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TypeRef rows 1.. are `System.Object`, `System.Type`, `System.Collections.Generic.List`1`; TypeSpec rows
    /// are the given blobs.
    struct Fake(Vec<Vec<u8>>);

    impl Resolve for Fake {
        fn type_name(&self, table: u8, row: u32) -> Option<String> {
            let names = ["System.Object", "System.Type", "System.Collections.Generic.List`1"];
            (table == tables::TYPE_REF).then(|| names.get(row.checked_sub(1)? as usize).map(|name| name.to_string()))?
        }

        fn type_spec(&self, row: u32) -> Option<&[u8]> {
            self.0.get(row.checked_sub(1)? as usize).map(Vec::as_slice)
        }
    }

    const OBJECT: u8 = (1 << 2) | 1;
    const TYPE: u8 = (2 << 2) | 1;
    const LIST: u8 = (3 << 2) | 1;
    const SPEC1: u8 = (1 << 2) | 2;

    fn attribute_arguments(params: &[Ty], value: &[u8]) -> Option<Vec<String>> {
        let budget = Cell::new(TOTAL_BUDGET);
        Reader::new(&Fake(Vec::new()), Generics::default(), &budget).attribute_arguments(params, value).arguments
    }

    fn method(blob: &[u8], name: &str) -> String {
        method_with(&Fake(Vec::new()), Generics::default(), blob, name)
    }

    fn method_with(fake: &Fake, generics: Generics, blob: &[u8], name: &str) -> String {
        let budget = Cell::new(TOTAL_BUDGET);
        let mut reader = Reader::new(fake, generics, &budget);
        reader.method(blob).map_or_else(|| UNREADABLE.to_owned(), |sig| sig.render(name, &generics))
    }

    #[test]
    fn renders_method_signatures() {
        assert_eq!(method(&[0x00, 0x00, 0x01], "Main"), "void Main()");
        // Static generic Combine<T1>(T1) returning int32, with the parameter name from GenericParam.
        let names = [(0, "T1".to_owned())];
        let generics = Generics { type_params: &[], method_params: &names };
        assert_eq!(method_with(&Fake(Vec::new()), generics, &[0x10, 1, 1, 0x08, 0x1E, 0], "Combine"), {
            "int32 Combine<T1>(T1)"
        });
        assert_eq!(method(&[0x10, 2, 1, 0x1E, 1, 0x1E, 0], "M"), "!!1 M<!!0, !!1>(!!0)");
        let instance = [0x20, 3, 0x01, 0x12, OBJECT, 0x1D, 0x0E, 0x10, 0x08];
        assert_eq!(method(&instance, "Run"), "instance void Run(System.Object, string[], int32&)");
        let pointers = [0x02, 2, 0x18, 0x0F, 0x05, 0x14, 0x0D, 2, 0, 0];
        assert_eq!(method(&pointers, "f"), "unmanaged stdcall native int f(uint8*, float64[,])");
        let vararg = [0x05, 2, 0x01, 0x08, ELEMENT_SENTINEL, 0x0E];
        assert_eq!(method(&vararg, "printf"), "vararg void printf(int32, ..., string)");
        let modified = [0x00, 1, 0x01, 0x1F, OBJECT, 0x08];
        assert_eq!(method(&modified, "v"), "void v(int32 modreq(System.Object))");
        let function_pointer = [0x00, 1, 0x01, 0x1B, 0x00, 1, 0x08, 0x08];
        assert_eq!(method(&function_pointer, "call"), "void call(method int32 *(int32))");
        let typed = [0x00, 1, 0x16, 0x1D, 0x1C];
        assert_eq!(method(&typed, "t"), "typedref t(object[])");
    }

    #[test]
    fn resolves_generic_instances_and_type_specs() {
        // TypeSpec 1 is List<!0>; the field's owner names its first type parameter T.
        let fake = Fake(vec![vec![0x15, 0x12, LIST, 1, 0x13, 0]]);
        let names = [(0, "T".to_owned())];
        let generics = Generics { type_params: &names, method_params: &[] };
        let budget = Cell::new(TOTAL_BUDGET);
        let field = Reader::new(&fake, generics, &budget).field(&[0x06, 0x12, SPEC1]).unwrap();
        assert_eq!(field.text, "System.Collections.Generic.List<T>");
        let nested = [0x00, 0, 0x15, 0x12, LIST, 1, 0x15, 0x12, LIST, 1, 0x0E];
        assert_eq!(
            method(&nested, "Get"),
            "System.Collections.Generic.List<System.Collections.Generic.List<string>> Get()"
        );
        let spec = Reader::new(&fake, Generics::default(), &budget).type_spec(&[0x12, SPEC1]).unwrap();
        assert_eq!(spec.text, "System.Collections.Generic.List<!0>");
        let kinds = [(TYPE, Kind::SystemType), (OBJECT, Kind::Other)];
        for (class, kind) in kinds {
            let field = Reader::new(&fake, Generics::default(), &budget).field(&[0x06, 0x12, class]).unwrap();
            assert_eq!(field.kind, kind, "{}", field.text);
        }
    }

    #[test]
    fn malformed_signatures_are_unreadable() {
        let cases: [&[u8]; 14] = [
            &[],
            &[0x00],
            &[0x00, 1, 0x01],
            &[0x00, 5, 0x01, 0x08],
            &[0x07, 0, 0x01],
            &[0x00, 0, 0x99],
            &[0x00, 0, 0x12, (9 << 2) | 1],
            &[0x00, 0, 0x12, 0x03],
            &[0x00, 0, 0x12, SPEC1],
            &[0x00, 0, 0x14, 0x08, 0],
            &[0x00, 0, 0x15, 0x08, LIST, 1, 0x08],
            &[0x00, 0, 0x15, 0x12, LIST, 0],
            &[0x10, 0xC0, 0xFF, 0xFF, 0xFF, 0, 0x01],
            &[0x00, 0xDF, 0xFF, 0xFF, 0xFF, 0x01],
        ];
        for blob in cases {
            assert_eq!(method(blob, "m"), UNREADABLE, "{blob:02x?}");
        }
        let budget = Cell::new(TOTAL_BUDGET);
        assert_eq!(Reader::new(&Fake(Vec::new()), Generics::default(), &budget).field(&[0x00, 0x08]), None);
    }

    #[test]
    fn expanding_and_recursive_signatures_hit_their_caps() {
        // TypeSpec 1 names itself: depth runs out instead of the stack.
        let recursive = Fake(vec![vec![0x12, SPEC1]]);
        assert_eq!(method_with(&recursive, Generics::default(), &[0x00, 0, 0x12, SPEC1], "r"), UNREADABLE);
        // Each TypeSpec is a two-argument instance of the next: 2^10 leaves from 80 bytes of blob, within the
        // depth cap but past the node cap. Four levels still render.
        let next = |row: u8| ((row + 1) << 2) | 2;
        let mut specs: Vec<Vec<u8>> =
            (1..=10).map(|row| vec![0x15, 0x12, LIST, 2, 0x12, next(row), 0x12, next(row)]).collect();
        specs.push(vec![0x0E]);
        let fake = Fake(specs);
        let four_levels = method_with(&fake, Generics::default(), &[0x00, 0, 0x12, (7 << 2) | 2], "x");
        assert_eq!(four_levels.matches("string").count(), 16, "{four_levels}");
        assert_eq!(method_with(&fake, Generics::default(), &[0x00, 0, 0x12, SPEC1], "x"), UNREADABLE);
        // Pointers nested past the depth cap.
        let mut deep = vec![0x00, 0];
        deep.extend([0x0F; 40]);
        deep.push(0x08);
        assert_eq!(method(&deep, "p"), UNREADABLE);
        // `void` and the 3 bytes read leave 1 of 8.
        let budget = Cell::new(8);
        let mut reader = Reader::new(&fake, Generics::default(), &budget);
        assert!(reader.method(&[0x00, 0, 0x01]).is_some());
        assert!(reader.method(&[0x00, 0, 0x0E]).is_none(), "the shared budget is spent");
    }

    #[test]
    fn array_shapes_are_bounded_by_rank_and_bytes_read_are_charged() {
        // A rank-1 array declaring 1,000,000 sizes, all present: II.23.2.13 allows at most `rank`.
        let mut hostile = vec![0x00, 0, 0x14, 0x08, 1, 0xC0, 0x0F, 0x42, 0x40];
        hostile.resize(hostile.len() + 1_000_001, 0);
        let budget = Cell::new(TOTAL_BUDGET);
        assert!(Reader::new(&Fake(Vec::new()), Generics::default(), &budget).method(&hostile).is_none());
        let spent = TOTAL_BUDGET - budget.get();
        assert!(spent <= 16, "{spent} units of work for a rejected shape");

        // Rank 64 with every size and lower bound in 4-byte form: 70 bytes of text from 518 bytes of blob.
        let mut shape = vec![0x06, 0x14, 0x08, 64];
        for _ in 0..2 {
            shape.push(64);
            shape.extend([0xC0, 0, 0, 1].repeat(64));
        }
        let fake = Fake(Vec::new());
        let budget = Cell::new(TOTAL_BUDGET);
        let array = Reader::new(&fake, Generics::default(), &budget).field(&shape).unwrap();
        assert_eq!(array.text, format!("int32[{}]", ",".repeat(63)));
        // The element's own `int32` is charged as it renders, then the array's text and the blob's bytes.
        assert_eq!(TOTAL_BUDGET - budget.get(), "int32".len() + array.text.len() + shape.len());
        let budget = Cell::new(300);
        assert!(Reader::new(&fake, Generics::default(), &budget).field(&shape).is_none(), "bytes count as work");
    }

    #[test]
    fn decodes_fixed_attribute_arguments() {
        let ty = |kind| Ty { text: String::new(), kind, shape: TypeShape::Other };
        let params = [
            ty(Kind::Element(0x0E)),
            ty(Kind::Element(0x08)),
            ty(Kind::Element(0x02)),
            ty(Kind::SystemType),
            ty(Kind::Element(0x0E)),
            ty(Kind::Element(0x03)),
        ];
        let value = [1, 0, 2, b'h', b'i', 0xFE, 0xFF, 0xFF, 0xFF, 1, 3, b'I', b'n', b't', 0xFF, b'x', 0, 0, 0];
        let arguments = attribute_arguments(&params, &value).unwrap();
        assert_eq!(arguments, ["\"hi\"", "-2", "true", "typeof(Int)", "null", "'x'"]);
        assert_eq!(attribute_arguments(&[], &[1, 0, 0, 0]), Some(vec![]));
        // 1023 ASCII bytes then a 2-byte character straddling the 1024-byte cap, in a 1500-byte string.
        let mut long = vec![1, 0, 0x80 | (1500 >> 8) as u8, (1500 & 0xFF) as u8];
        long.extend([b'a'; 1023]);
        long.extend("é".as_bytes());
        long.extend([b'b'; 1500 - 1025]);
        let cut = attribute_arguments(&params[..1], &long).unwrap();
        assert_eq!(cut, [format!("\"{}\"... (1500 bytes)", "a".repeat(1023))]);
        long[4..].copy_from_slice(&[b'c'; 1500]);
        let cut = attribute_arguments(&params[3..4], &long).unwrap();
        assert_eq!(cut, [format!("typeof({})... (1500 bytes)", "c".repeat(1024))]);
        assert_eq!(attribute_arguments(&[], &[0, 1]), None, "no prolog");
        assert_eq!(attribute_arguments(&params[1..2], &[1, 0, 1, 2]), None, "truncated int32");
        assert_eq!(attribute_arguments(&params[..1], &[1, 0, 9, b'a']), None, "string past the blob");
        assert_eq!(attribute_arguments(&[ty(Kind::Other)], &[1, 0, 0, 0, 0, 0]), None, "enum or array");
        assert_eq!(attribute_arguments(&[ty(Kind::Element(0x1C))], &[1, 0, 0x08, 1, 0, 0, 0]), None, "boxed");
    }

    #[test]
    fn property_signatures_use_the_owner_generics_and_signature_caps() {
        let fake = Fake(Vec::new());
        let names = [(0, "T".to_owned())];
        let generics = Generics { type_params: &names, method_params: &[] };
        let budget = Cell::new(TOTAL_BUDGET);
        let property = Reader::new(&fake, generics, &budget).property(&[0x28, 1, 0x13, 0, 0x13, 0]).unwrap();
        assert_eq!(property.render("Item", &generics), "instance T Item(T)");

        let mut many = vec![0x28, 0x82, 0x00, 0x08];
        many.extend([0x08; 512]);
        assert!(Reader::new(&fake, generics, &budget).property(&many).is_none(), "node cap includes the result type");
        let recursive = Fake(vec![vec![0x12, SPEC1]]);
        assert!(Reader::new(&recursive, generics, &budget).property(&[0x28, 0, 0x12, SPEC1]).is_none());
        let tiny_budget = Cell::new(8);
        assert!(Reader::new(&fake, generics, &tiny_budget).property(&[0x28, 0, 0x08]).is_some());
        assert!(Reader::new(&fake, generics, &tiny_budget).property(&[0x28, 0, 0x08]).is_none());
    }

    #[test]
    fn attribute_arrays_share_node_text_and_image_budgets() {
        let fake = Fake(Vec::new());
        let budget = Cell::new(TOTAL_BUDGET);
        let params =
            Reader::new(&fake, Generics::default(), &budget).method(&[0x20, 1, 0x01, 0x1D, 0x08]).unwrap().params;
        let array = |count: u32| {
            let mut value = vec![1, 0];
            value.extend(count.to_le_bytes());
            value.extend(vec![0; count as usize * 4]);
            value.extend([0, 0]);
            value
        };
        let decoded =
            Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &array(MAX_NODES - 1));
        assert!(decoded.error.is_none());
        let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &array(MAX_NODES));
        assert!(decoded.arguments.is_none() && decoded.named_arguments.is_none(), "array elements consume nodes");

        let params =
            Reader::new(&fake, Generics::default(), &budget).method(&[0x20, 1, 0x01, 0x1D, 0x0E]).unwrap().params;
        let mut long_array = vec![1, 0, 4, 0, 0, 0];
        for _ in 0..4 {
            long_array.extend([0x84, 0]);
            long_array.extend([b'x'; 1024]);
        }
        long_array.extend([0, 0]);
        let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &long_array);
        assert!(decoded.arguments.is_none(), "individually bounded strings must also obey the total text cap");
        assert!(budget.get() > 0, "per-attribute caps do not spend the entire image budget");

        let params = [Ty { text: "string".to_owned(), kind: Kind::Element(ELEMENT_STRING), shape: TypeShape::Other }];
        let mut long = vec![1, 0, 0xA7, 0x10]; // 10,000 UTF-8 bytes, kept text fits the per-string cap.
        long.extend([b'x'; 10_000]);
        long.extend([0, 0]);
        let budget = Cell::new(2000);
        let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &long);
        assert!(decoded.arguments.is_none(), "skipped string bytes still cost image-wide work");
        assert_eq!(budget.get(), 0);
    }

    #[test]
    fn named_argument_budget_failures_preserve_fully_charged_fixed_arguments() {
        let fake = Fake(Vec::new());
        let params = [Ty { text: "int32".to_owned(), kind: Kind::Element(0x08), shape: TypeShape::Other }];
        let value = [1, 0, 42, 0, 0, 0, 1, 0, 0x54, 0x08, 1, b'X', 0, 0, 0, 0];
        for (available, fixed_available, named_available) in
            [(7, false, false), (8, true, false), (14, true, false), (20, true, false), (25, true, true)]
        {
            let budget = Cell::new(available);
            let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &value);
            assert_eq!(decoded.arguments, fixed_available.then(|| vec!["42".to_owned()]), "budget {available}");
            assert_eq!(decoded.named_arguments.is_some(), named_available, "budget {available}");
            assert_eq!(decoded.error.is_none(), named_available, "budget {available}");
            assert_eq!(budget.get(), 0);
            if let Some(named) = decoded.named_arguments {
                assert_eq!((named[0].name.as_str(), named[0].value.as_str()), ("X", "0"));
            }
            let later = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&params, &value);
            assert!(later.arguments.is_none(), "preserving charged values must not replenish the shared budget");
        }
    }

    #[test]
    fn property_type_specs_and_custom_modifiers_cannot_hide_invalid_void_contexts() {
        let fake = Fake(vec![vec![0x1D, 0x01]]);
        let budget = Cell::new(TOTAL_BUDGET);
        for blob in [
            vec![0x28, 0, 0x12, SPEC1],
            vec![0x28, 0, 0x1F, OBJECT, 0x1D, 0x01],
            vec![0x28, 0, 0x1D, 0x20, OBJECT, 0x01],
            vec![0x28, 0, 0x1B, 0x00, 0, 0x1D, 0x01],
            vec![0x28, 0, 0x1B, 0x00, 1, 0x01, 0x01],
        ] {
            assert!(Reader::new(&fake, Generics::default(), &budget).property(&blob).is_none(), "{blob:02x?}");
        }
        let pointer =
            Reader::new(&fake, Generics::default(), &budget).property(&[0x28, 0, 0x0F, 0x20, OBJECT, 0x01]).unwrap();
        assert_eq!(pointer.render("P", &Generics::default()), "instance void modopt(System.Object)* P()");
        let mut reader = Reader::new(&fake, Generics::default(), &budget);
        assert!(reader.property(&[0x28, 0, 0x1D, 0x01]).is_none());
        assert!(
            reader.method(&[0x00, 0, 0x01]).is_some(),
            "the property-only grammar mode must be restored on failure"
        );
    }

    #[test]
    fn ref_return_properties_share_signature_budgets_without_admitting_void_references() {
        let fake = Fake(Vec::new());
        for (available, readable) in [(14, false), (15, true)] {
            let budget = Cell::new(available);
            let property = Reader::new(&fake, Generics::default(), &budget).property(&[0x28, 0, 0x10, 0x08]);
            assert_eq!(property.is_some(), readable);
            if let Some(property) = property {
                assert_eq!(property.render("P", &Generics::default()), "instance int32& P()");
            }
            assert_eq!(budget.get(), 0);
            assert!(Reader::new(&fake, Generics::default(), &budget).property(&[0x28, 0, 0x10, 0x08]).is_none());
        }
        let budget = Cell::new(TOTAL_BUDGET);
        for blob in [
            vec![0x28, 0, 0x10, 0x01],
            vec![0x28, 0, 0x20, OBJECT, 0x10, 0x01],
            vec![0x28, 0, 0x10, 0x1F, OBJECT, 0x01],
        ] {
            assert!(Reader::new(&fake, Generics::default(), &budget).property(&blob).is_none(), "{blob:02x?}");
        }
    }

    #[test]
    fn property_type_spec_references_require_complete_nested_blobs_and_charge_failed_work() {
        let property = [0x28, 0, 0x12, SPEC1];
        let valid = Fake(vec![vec![0x1D, 0x08]]);
        let budget = Cell::new(TOTAL_BUDGET);
        let decoded = Reader::new(&valid, Generics::default(), &budget).property(&property).unwrap();
        assert_eq!(decoded.render("P", &Generics::default()), "instance int32[] P()");

        for trailing in [0x01, 0x08, 0xFF] {
            let invalid = Fake(vec![vec![0x1D, 0x08, trailing]]);
            let budget = Cell::new(TOTAL_BUDGET);
            assert!(Reader::new(&invalid, Generics::default(), &budget).property(&property).is_none());
            let prefix_cost = "int32".len() + "int32[]".len() + 2 + property.len();
            assert_eq!(TOTAL_BUDGET - budget.get(), prefix_cost, "failed nested decoding still charges read work");
            let budget = Cell::new(prefix_cost - 1);
            assert!(Reader::new(&invalid, Generics::default(), &budget).property(&property).is_none());
            assert_eq!(budget.get(), 0);
            assert!(Reader::new(&invalid, Generics::default(), &budget).property(&[0x28, 0, 0x08]).is_none());

            let indirect = Fake(vec![vec![0x12, (2 << 2) | 2], vec![0x1D, 0x08, trailing]]);
            let budget = Cell::new(TOTAL_BUDGET);
            assert!(Reader::new(&indirect, Generics::default(), &budget).property(&property).is_none());
            assert!(
                Reader::new(&invalid, Generics::default(), &budget).method(&[0x00, 0, 0x12, SPEC1]).is_some(),
                "complete TypeSpec consumption is scoped to strict property decoding"
            );
        }
    }

    #[test]
    fn event_generic_definition_failures_charge_alias_rendering_and_restore_legacy_parsing() {
        let fake = Fake(vec![vec![0x15, 0x12, (2 << 2) | 2, 1, 0x08], vec![0x1D, 0x08]]);
        let cost = 1 + 3 + 2 + "int32".len() + "int32[]".len();
        let budget = Cell::new(TOTAL_BUDGET);
        let mut reader = Reader::new(&fake, Generics::default(), &budget);
        assert!(reader.event_type(u32::from(SPEC1)).is_none());
        assert_eq!(TOTAL_BUDGET - budget.get(), cost, "failed definitions charge both nested bytes and text");
        assert!(
            reader.method(&[0, 0, 0x15, 0x12, (2 << 2) | 2, 1, 0x08]).is_some(),
            "legacy method decoding is unchanged"
        );

        let property = [0x28, 0, 0x12, SPEC1];
        let budget = Cell::new(TOTAL_BUDGET);
        assert!(Reader::new(&fake, Generics::default(), &budget).property(&property).is_none());
        assert_eq!(TOTAL_BUDGET - budget.get(), cost - 1 + property.len());
        for available in [cost - 1, cost] {
            let budget = Cell::new(available);
            assert!(Reader::new(&fake, Generics::default(), &budget).event_type(u32::from(SPEC1)).is_none());
            assert_eq!(budget.get(), 0);
            assert!(Reader::new(&fake, Generics::default(), &budget).method(&[0, 0, 0x01]).is_none());
        }
    }

    #[test]
    fn event_function_pointer_failures_charge_consumed_headers_and_sentinels() {
        for (blob, cost) in [
            (vec![0x1B, 0x00, 1, 0x01, 0x41, 0x08], 1 + 5 + "void".len()),
            (vec![0x1B, 0x80, 0, 0x01], 3),
            (vec![0x1B, 0x40, 0, 0x01], 3),
            (vec![0x1B, 0x05, 2, 0x01, 0x41, 0x08, 0x41, 0x0E], 1 + 7 + "void".len() + "int32".len()),
            (vec![0x1B, 0x11, 1, 0, 0x01], 3),
            (vec![0x1B, 0x10, 0, 0, 0x01], 4),
        ] {
            let fake = Fake(vec![blob.clone()]);
            let budget = Cell::new(TOTAL_BUDGET);
            let mut reader = Reader::new(&fake, Generics::default(), &budget);
            assert!(reader.event_type(u32::from(SPEC1)).is_none(), "{blob:02x?}");
            assert_eq!(TOTAL_BUDGET - budget.get(), cost, "{blob:02x?}: consumed work is fully charged");
            assert!(reader.method(&blob[1..]).is_some(), "strict grammar is scoped to the event/property context");

            let budget = Cell::new(cost - 1);
            assert!(Reader::new(&fake, Generics::default(), &budget).event_type(u32::from(SPEC1)).is_none());
            assert_eq!(budget.get(), 0);
            assert!(Reader::new(&fake, Generics::default(), &budget).method(&[0, 0, 0x01]).is_none());
        }
    }

    #[test]
    fn named_attribute_types_counts_and_identifiers_are_not_guessed() {
        let fake = Fake(Vec::new());
        let budget = Cell::new(TOTAL_BUDGET);
        let malformed = [
            vec![1, 0, 0xFF, 0xFF],
            vec![1, 0, 1, 0, 0x55, 0x08, 0, 0, 0, 0, 0],
            vec![1, 0, 1, 0, 0x54, 0x51, 0, 0, 0, 0, 0],
            vec![1, 0, 1, 0, 0x54, 0x08, 0xFF, 0, 0, 0, 0],
            vec![1, 0, 1, 0, 0x54, 0x08, 1, 0xFF, 0, 0, 0, 0],
        ];
        for value in malformed {
            let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&[], &value);
            assert_eq!(decoded.arguments, Some(vec![]), "fixed values remain available");
            assert!(decoded.named_arguments.is_none() && decoded.error.is_some(), "{value:02x?}");
        }
        let mut nested = vec![1, 0, 1, 0, 0x54];
        nested.extend([0x1D; MAX_DEPTH as usize + 2]);
        nested.extend([0x08, 0, 0, 0, 0, 0]);
        let decoded = Reader::new(&fake, Generics::default(), &budget).attribute_arguments(&[], &nested);
        assert!(decoded.named_arguments.is_none(), "deep serialized type nesting is bounded");
        let params =
            Reader::new(&fake, Generics::default(), &budget).method(&[0x20, 1, 0x01, 0x1D, 0x1D, 0x08]).unwrap().params;
        let decoded = Reader::new(&fake, Generics::default(), &budget)
            .attribute_arguments(&params, &[1, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0]);
        assert!(decoded.arguments.is_none(), "jagged arrays are not valid custom attribute array types");
    }

    #[test]
    fn decodes_locals_and_method_instantiations() {
        let fake = Fake(Vec::new());
        let names = [(0, "T".to_owned())];
        let generics = Generics { type_params: &[], method_params: &names };
        let budget = Cell::new(TOTAL_BUDGET);
        let texts = |types: Option<Vec<Ty>>| types.map(|types| types.into_iter().map(|ty| ty.text).collect::<Vec<_>>());
        // int32, a pinned byref to T, a typedref, an object with a custom modifier.
        let blob = [0x07, 4, 0x08, 0x45, 0x10, 0x1E, 0, 0x16, 0x20, OBJECT, 0x1C];
        let locals = texts(Reader::new(&fake, generics, &budget).locals(&blob));
        assert_eq!(locals.unwrap(), ["int32", "T& pinned", "typedref", "object modopt(System.Object)"]);
        assert_eq!(texts(Reader::new(&fake, generics, &budget).locals(&[0x07, 0])), Some(vec![]));
        for malformed in [&[0x06, 1, 0x08][..], &[0x07, 3, 0x08], &[0x07, 0xC0, 0x01, 0, 0, 0x08], &[]] {
            assert_eq!(texts(Reader::new(&fake, generics, &budget).locals(malformed)), None, "{malformed:02x?}");
        }
        // Each local has its own node cap: 600 locals are more nodes than one signature may have.
        let mut many = vec![0x07, 0x82, 0x58];
        many.extend([0x08; 600]);
        assert_eq!(Reader::new(&fake, generics, &budget).locals(&many).map(|locals| locals.len()), Some(600));

        let instantiation = texts(Reader::new(&fake, generics, &budget).method_spec(&[0x0A, 2, 0x08, 0x1D, 0x0E]));
        assert_eq!(instantiation.unwrap(), ["int32", "string[]"]);
        for malformed in [&[0x0A, 0][..], &[0x0A, 2, 0x08], &[0x07, 1, 0x08], &[0x0A, 0x41, 0x08]] {
            let decoded = texts(Reader::new(&fake, generics, &budget).method_spec(malformed));
            assert_eq!(decoded, None, "{malformed:02x?}");
        }
    }

    #[test]
    fn strips_generic_arity() {
        assert_eq!(without_arity("List`1"), "List");
        assert_eq!(without_arity("Odd`"), "Odd`");
        assert_eq!(without_arity("Plain"), "Plain");
    }
}

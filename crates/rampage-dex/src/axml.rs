//! Android binary XML (AXML), as compiled `AndroidManifest.xml` files use: the string pool (UTF-8 or UTF-16), the
//! resource map, namespaces, elements and typed attribute values. Hostile files are expected: every chunk is checked
//! against its parent, string lengths against the pool, nesting depth and node count are capped, and decoded text
//! is charged to a budget so that one huge string referenced many times cannot exhaust memory.

use serde::Serialize;

use crate::error::{DexError, Result, malformed};
use crate::read::{u16_at, u32_at};

/// Caps on one binary XML document.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_file_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    /// UTF-16 units of one string.
    pub max_string_units: usize,
    /// Characters of text decoded across the whole document.
    pub max_text: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 16 << 20,
            max_depth: 64,
            max_nodes: 200_000,
            max_string_units: 1 << 16,
            max_text: 32 << 20,
        }
    }
}

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// An attribute's typed value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Value {
    String(String),
    Int(i64),
    Bool(bool),
    /// A resource reference `@0x7f010001`.
    Reference(u32),
    /// A theme attribute reference `?0x01010000`.
    Attribute(u32),
    Float(f32),
    /// Any other typed value: its data type and raw data.
    Other {
        data_type: u8,
        data: u32,
    },
    Null,
}

impl Value {
    pub fn text(&self) -> String {
        match self {
            Value::String(text) => text.clone(),
            Value::Int(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Reference(id) => format!("@{id:#010x}"),
            Value::Attribute(id) => format!("?{id:#010x}"),
            Value::Float(value) => value.to_string(),
            Value::Other { data_type, data } => format!("({data_type:#x}){data:#x}"),
            Value::Null => "null".to_owned(),
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            Value::String(text) => text.parse().ok(),
            Value::Int(value) => Some(*value != 0),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(value) => Some(*value),
            Value::String(text) => text.trim().parse().ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Attribute {
    /// The attribute name, from the string pool or, when that is empty, the resource map's attribute id.
    pub name: String,
    /// Whether the attribute is in the `android:` namespace.
    pub android: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<u32>,
    pub value: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Element {
    pub name: String,
    pub line: u32,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    /// The value of attribute `name`, preferring the `android:` one.
    pub fn attr(&self, name: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .filter(|attribute| attribute.name == name)
            .max_by_key(|attribute| attribute.android)
            .map(|attribute| &attribute.value)
    }

    /// The value of attribute `name` as text, cut to [`crate::dex::MAX_NAME_BYTES`].
    pub fn attr_text(&self, name: &str) -> Option<String> {
        self.attr(name).map(|value| crate::dex::cut(&value.text()))
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }
}

/// A decoded document: the root element and anything worth saying about how it was read.
#[derive(Debug, Clone)]
pub struct Document {
    pub root: Element,
    pub warnings: Vec<String>,
}

/// Framework attribute ids for the names obfuscators blank in the string pool, so that the resource map still
/// names them. Values from the platform's `public.xml`.
fn attribute_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0001 => "label",
        0x0101_0002 => "icon",
        0x0101_0003 => "name",
        0x0101_0006 => "permission",
        0x0101_000e => "enabled",
        0x0101_000f => "debuggable",
        0x0101_0010 => "exported",
        0x0101_0011 => "process",
        0x0101_0018 => "authorities",
        0x0101_001c => "priority",
        0x0101_020c => "minSdkVersion",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0271 => "maxSdkVersion",
        _ => return None,
    })
}

struct Pool<'a> {
    data: &'a [u8],
    /// The pool chunk's offset in `data` and its size.
    start: usize,
    end: usize,
    count: usize,
    strings_start: usize,
    utf8: bool,
}

impl Pool<'_> {
    fn length(&self, at: &mut usize, wide: bool) -> Option<usize> {
        if wide {
            let first = usize::from(u16_at(self.data, *at)?);
            *at += 2;
            if first & 0x8000 != 0 {
                let second = usize::from(u16_at(self.data, *at)?);
                *at += 2;
                return Some(((first & 0x7fff) << 16) | second);
            }
            Some(first)
        } else {
            let first = usize::from(*self.data.get(*at)?);
            *at += 1;
            if first & 0x80 != 0 {
                let second = usize::from(*self.data.get(*at)?);
                *at += 1;
                return Some(((first & 0x7f) << 8) | second);
            }
            Some(first)
        }
    }

    fn get(&self, index: u32, limits: &Limits, budget: &mut usize) -> Result<String> {
        let index = index as usize;
        if index >= self.count {
            return Err(malformed(format!("string {index} is past the pool's {} strings", self.count)));
        }
        let offset = u32_at(self.data, self.start + 28 + index * 4).unwrap_or(u32::MAX) as usize;
        let mut at = self.start.saturating_add(self.strings_start).saturating_add(offset);
        if at >= self.end {
            return Err(malformed(format!("string {index} starts outside its pool")));
        }
        let bad = || malformed(format!("string {index} runs past its pool"));
        let text = if self.utf8 {
            let _units = self.length(&mut at, false).ok_or_else(bad)?;
            let bytes = self.length(&mut at, false).ok_or_else(bad)?;
            if bytes > limits.max_string_units * 3 {
                return Err(DexError::Limit(format!("string {index} of {bytes} bytes")));
            }
            let slice = self.data.get(at..at + bytes).filter(|_| at + bytes <= self.end).ok_or_else(bad)?;
            String::from_utf8_lossy(slice).into_owned()
        } else {
            let units = self.length(&mut at, true).ok_or_else(bad)?;
            if units > limits.max_string_units {
                return Err(DexError::Limit(format!("string {index} of {units} UTF-16 units")));
            }
            let slice = self.data.get(at..at + units * 2).filter(|_| at + units * 2 <= self.end).ok_or_else(bad)?;
            let units: Vec<u16> = slice.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
            String::from_utf16_lossy(&units)
        };
        if text.len() > *budget {
            return Err(DexError::Limit(format!("more than {} characters of text decoded", limits.max_text)));
        }
        *budget -= text.len();
        Ok(text)
    }
}

/// Warnings one document keeps; the rest are counted.
const MAX_WARNINGS: usize = 16;

#[derive(Default)]
struct Warnings {
    kept: Vec<String>,
    dropped: usize,
}

impl Warnings {
    fn add(&mut self, text: String) {
        if self.kept.len() < MAX_WARNINGS {
            self.kept.push(text);
        } else {
            self.dropped += 1;
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.dropped > 0 {
            self.kept.push(format!("{} more warnings", self.dropped));
        }
        self.kept
    }
}

/// A string that could not be read reads as empty, unless a limit refused it.
fn lenient(error: DexError) -> Result<String> {
    match error {
        DexError::Limit(_) => Err(error),
        _ => Ok(String::new()),
    }
}

/// Whether `data` starts like a binary XML document.
pub fn is_axml(data: &[u8]) -> bool {
    u16_at(data, 0) == Some(0x0003) && u16_at(data, 2) == Some(8)
}

/// Decodes a binary XML document.
pub fn parse(data: &[u8]) -> Result<Document> {
    parse_with(data, Limits::default())
}

pub fn parse_with(data: &[u8], limits: Limits) -> Result<Document> {
    if data.len() > limits.max_file_bytes {
        return Err(DexError::Limit(format!("{} bytes of binary XML", data.len())));
    }
    if !is_axml(data) {
        return Err(malformed("no binary XML header"));
    }
    let declared = u32_at(data, 4).unwrap_or(0) as usize;
    let mut warnings = Warnings::default();
    let end = if declared > data.len() || declared < 8 {
        warnings.add(format!("header declares {declared} bytes; the file has {}", data.len()));
        data.len()
    } else {
        declared
    };
    let mut pool: Option<Pool<'_>> = None;
    let mut resource_map: Vec<u32> = Vec::new();
    let mut stack: Vec<Element> = vec![Element { name: "#document".to_owned(), ..Element::default() }];
    let mut nodes = 0usize;
    let mut budget = limits.max_text;
    let mut android_prefixes: Vec<u32> = Vec::new();
    let mut at = 8usize;
    while at + 8 <= end {
        let kind = u16_at(data, at).unwrap_or(0);
        let header_size = usize::from(u16_at(data, at + 2).unwrap_or(0));
        let size = u32_at(data, at + 4).unwrap_or(0) as usize;
        if size < 8 || header_size < 8 || header_size > size || at + size > end {
            warnings.add(format!("chunk {kind:#06x} at {at:#x} declares {size} bytes; reading stops"));
            break;
        }
        let chunk = &data[at..at + size];
        match kind {
            0x0001 => {
                if pool.is_some() {
                    warnings.add("a second string pool is ignored".to_owned());
                } else {
                    if size < 28 {
                        return Err(malformed("string pool header is truncated"));
                    }
                    let count = u32_at(chunk, 8).unwrap_or(0) as usize;
                    let flags = u32_at(chunk, 16).unwrap_or(0);
                    let strings_start = u32_at(chunk, 20).unwrap_or(0) as usize;
                    if count.saturating_mul(4).saturating_add(28) > size || strings_start > size {
                        return Err(malformed(format!("string pool declares {count} strings, more than fit")));
                    }
                    pool =
                        Some(Pool { data, start: at, end: at + size, count, strings_start, utf8: flags & 0x100 != 0 });
                }
            }
            0x0180 => {
                resource_map =
                    chunk[header_size..].as_chunks::<4>().0.iter().map(|word| u32::from_le_bytes(*word)).collect();
            }
            0x0100..=0x0104 => {
                nodes += 1;
                if nodes > limits.max_nodes {
                    return Err(DexError::Limit(format!("more than {} XML nodes", limits.max_nodes)));
                }
                let pool = pool.as_ref().ok_or_else(|| malformed("XML node before the string pool"))?;
                let line = u32_at(chunk, 8).unwrap_or(0);
                let ext = header_size;
                let word = |offset: usize| {
                    u32_at(chunk, ext + offset).ok_or_else(|| malformed(format!("node at {at:#x} is truncated")))
                };
                match kind {
                    0x0100 => {
                        let uri = word(4)?;
                        if pool.get(uri, &limits, &mut budget).is_ok_and(|uri| uri == ANDROID_NS) {
                            android_prefixes.push(uri);
                        }
                    }
                    0x0102 => {
                        if stack.len() > limits.max_depth {
                            return Err(DexError::Limit(format!("elements nested deeper than {}", limits.max_depth)));
                        }
                        let name = pool.get(word(4)?, &limits, &mut budget)?;
                        let attribute_start = usize::from(u16_at(chunk, ext + 8).unwrap_or(0));
                        let attribute_size = usize::from(u16_at(chunk, ext + 10).unwrap_or(0));
                        let count = usize::from(u16_at(chunk, ext + 12).unwrap_or(0));
                        if attribute_size < 20 || ext + attribute_start + count * attribute_size > size {
                            return Err(malformed(format!(
                                "element `{name}` declares {count} attributes, more than fit"
                            )));
                        }
                        let mut attributes = Vec::with_capacity(count);
                        for index in 0..count {
                            let base = ext + attribute_start + index * attribute_size;
                            let field = |offset| u32_at(chunk, base + offset).unwrap_or(u32::MAX);
                            let (namespace, name_idx, raw) = (field(0), field(4), field(8));
                            let data_type = chunk[base + 15];
                            let value_data = field(16);
                            let resource_id = resource_map.get(name_idx as usize).copied();
                            let pooled = pool.get(name_idx, &limits, &mut budget).or_else(lenient)?;
                            let name = if pooled.is_empty() {
                                resource_id.and_then(attribute_name).map_or_else(
                                    || resource_id.map_or_else(|| "?".to_owned(), |id| format!("attr_{id:#010x}")),
                                    str::to_owned,
                                )
                            } else {
                                pooled
                            };
                            let value = match data_type {
                                0x00 => Value::Null,
                                0x01 => Value::Reference(value_data),
                                0x02 => Value::Attribute(value_data),
                                0x03 => Value::String(
                                    pool.get(if raw != u32::MAX { raw } else { value_data }, &limits, &mut budget)
                                        .or_else(lenient)?,
                                ),
                                0x04 => Value::Float(f32::from_bits(value_data)),
                                0x10 => Value::Int(i64::from(value_data as i32)),
                                0x11 => Value::Int(i64::from(value_data)),
                                0x12 => Value::Bool(value_data != 0),
                                _ if raw != u32::MAX => {
                                    Value::String(pool.get(raw, &limits, &mut budget).or_else(lenient)?)
                                }
                                _ => Value::Other { data_type, data: value_data },
                            };
                            let android = namespace != u32::MAX
                                && (android_prefixes.contains(&namespace)
                                    || resource_id.is_some_and(|id| id >> 24 == 0x01));
                            attributes.push(Attribute { name, android, resource_id, value });
                        }
                        stack.push(Element { name, line, attributes, children: Vec::new() });
                    }
                    0x0103 => {
                        if stack.len() > 1 {
                            let element = stack.pop().unwrap();
                            stack.last_mut().unwrap().children.push(element);
                        } else {
                            warnings.add(format!("unbalanced end element at {at:#x}"));
                        }
                    }
                    _ => {}
                }
            }
            0x0003 => warnings.add("nested binary XML document is ignored".to_owned()),
            _ => {}
        }
        at += size;
    }
    while stack.len() > 1 {
        let element = stack.pop().unwrap();
        warnings.add(format!("element `{}` is never closed", element.name));
        stack.last_mut().unwrap().children.push(element);
    }
    let mut document = stack.pop().unwrap();
    let root = if document.children.len() == 1 {
        document.children.pop().unwrap()
    } else {
        return Err(malformed(format!("{} root elements", document.children.len())));
    };
    Ok(Document { root, warnings: warnings.finish() })
}

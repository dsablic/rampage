//! A bounded CMSIS-SVD reader: device → peripherals → registers (clusters flattened) → bit fields, with
//! `derivedFrom`, `dim` arrays, inherited register properties and enumerated values. The XML reader expands no
//! entity beyond the predefined and character references and processes no DTD; every count, size and nesting
//! depth is capped, so a hostile file is refused rather than exhausting memory.

use std::collections::{BTreeMap, HashMap};

use quick_xml::events::Event;
use serde::{Deserialize, Serialize};

/// Largest SVD file read.
pub(crate) const MAX_SVD_BYTES: u64 = 64 << 20;
const MAX_ELEMENTS: usize = 4_000_000;
const MAX_DEPTH: usize = 64;
const MAX_PERIPHERALS: usize = 4096;
const MAX_REGISTERS: usize = 131_072;
const MAX_FIELDS: usize = 256;
const MAX_VALUES: usize = 256;
/// Fields plus their enumerated values across the device, every copy counted.
const MAX_FIELD_ITEMS: usize = 1 << 20;
const MAX_DIM: u64 = 4096;
const MAX_DERIVATION: usize = 16;
const MAX_CLUSTER_DEPTH: usize = 16;
const MAX_NAME: usize = 64;
const MAX_DESCRIPTION: usize = 96;

/// One peripheral of a device, with its registers flattened to offsets from its base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peripheral {
    pub device: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub base: u64,
    pub registers: Vec<Register>,
}

/// A register: clusters are flattened into its name (`CH0_CR`), and register arrays whose elements are
/// contiguous keep C subscripts (`RELOAD[2]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub name: String,
    pub offset: u64,
    pub bits: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<BitField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitField {
    pub name: String,
    pub lsb: u32,
    pub width: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Enumerated values, `(name, value)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<(String, u64)>,
}

impl Register {
    pub fn bytes(&self) -> u64 {
        u64::from(self.bits.div_ceil(8)).max(1)
    }
}

impl Peripheral {
    /// Bytes from the base to the end of the last register.
    pub fn span(&self) -> u64 {
        self.registers.iter().map(|register| register.offset + register.bytes()).max().unwrap_or(0)
    }
}

/// A parsed device and what the reader left out.
#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub peripherals: Vec<Peripheral>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------------------------------------------
// Element tree

#[derive(Debug, Default)]
struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
    text: String,
}

impl Element {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(key, _)| key == name).map(|(_, value)| value.trim())
    }

    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.trim()).filter(|text| !text.is_empty())
    }
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or_default().to_owned()
}

fn parse_tree(text: &str) -> Result<Element, String> {
    let mut reader = quick_xml::Reader::from_str(text);
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut elements = 0usize;
    loop {
        let event = reader.read_event().map_err(|error| format!("malformed XML: {error}"))?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() > MAX_DEPTH {
                    return Err(format!("SVD exceeds {MAX_ELEMENTS} elements or {MAX_DEPTH} levels of nesting"));
                }
                let mut attributes = Vec::new();
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(|error| format!("malformed XML attribute: {error}"))?;
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|error| format!("malformed XML attribute value: {error}"))?;
                    attributes.push((local(attribute.key.as_ref()), value.into_owned()));
                }
                let element = Element { name: local(start.name().as_ref()), attributes, ..Element::default() };
                if empty {
                    stack.last_mut().expect("document").children.push(element);
                } else {
                    stack.push(element);
                }
            }
            Event::End(_) => {
                let mut element = stack.pop().expect("quick-xml matches end tags");
                if !element.children.is_empty() && element.text.trim().is_empty() {
                    element.text = String::new();
                }
                stack.last_mut().ok_or("unbalanced XML end tag")?.children.push(element);
            }
            // Container elements' whitespace is dropped; only leaves' text is read.
            Event::Text(text) => stack.last_mut().expect("document").text.push_str(&text.xml10_content()),
            Event::CData(data) => stack.last_mut().expect("document").text.push_str(&data.xml10_content()),
            Event::GeneralRef(reference) => {
                let text = &mut stack.last_mut().expect("document").text;
                if let Some(character) = reference.resolve_char_ref().map_err(|error| error.to_string())? {
                    text.push(character);
                } else {
                    let name = reference.xml10_content();
                    text.push(match name.as_ref() {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "apos" => '\'',
                        "quot" => '"',
                        _ => return Err(format!("unsupported XML entity `&{name};` (no entities are expanded)")),
                    });
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    if stack.len() != 1 {
        return Err("XML document ends inside an element".into());
    }
    let mut document = stack.pop().expect("document");
    if document.children.len() != 1 {
        return Err("XML document must have exactly one root element".into());
    }
    Ok(document.children.pop().expect("one root"))
}

// ---------------------------------------------------------------------------------------------------------------
// Values

/// An SVD `scaledNonNegativeInteger`: decimal, `0x` hex, `#` binary, with an optional k/M/G/T scale.
pub(crate) fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, scale) = match text.chars().last()? {
        'k' | 'K' => (&text[..text.len() - 1], 1u64 << 10),
        'm' | 'M' => (&text[..text.len() - 1], 1 << 20),
        'g' | 'G' => (&text[..text.len() - 1], 1 << 30),
        't' | 'T' => (&text[..text.len() - 1], 1 << 40),
        _ => (text, 1),
    };
    let value = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(binary) = digits.strip_prefix('#').or_else(|| digits.strip_prefix("0b")) {
        u64::from_str_radix(binary, 2).ok()?
    } else {
        digits.parse().ok()?
    };
    value.checked_mul(scale)
}

fn clip(text: &str, limit: usize) -> String {
    let words: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if words.chars().count() <= limit {
        return words;
    }
    let mut clipped: String = words.chars().take(limit - 1).collect();
    clipped.push('…');
    clipped
}

fn description(element: &Element) -> Option<String> {
    element.text_of("description").map(|text| clip(text, MAX_DESCRIPTION)).filter(|text| !text.is_empty())
}

/// A name usable as a C identifier: other characters become `_`, and a leading digit gets a `_` before it.
pub(crate) fn identifier(text: &str) -> String {
    let mut name: String = text
        .trim()
        .chars()
        .take(MAX_NAME)
        .map(|character| if character.is_ascii_alphanumeric() || character == '_' { character } else { '_' })
        .collect();
    if name.is_empty() || name.starts_with(|character: char| character.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

/// Register properties inherited from device to peripheral to cluster to register.
#[derive(Debug, Clone, Default)]
struct Properties {
    bits: Option<u32>,
    access: Option<String>,
    reset: Option<u64>,
}

impl Properties {
    fn over(&self, element: &Element) -> Properties {
        Properties {
            bits: element.text_of("size").and_then(number).and_then(|bits| u32::try_from(bits).ok()).or(self.bits),
            access: element.text_of("access").map(str::to_owned).or_else(|| self.access.clone()),
            reset: element.text_of("resetValue").and_then(number).or(self.reset),
        }
    }
}

/// The names and offsets of a `dim` element's instances: `[%s]` names keep a C subscript when the elements are
/// contiguous (`stride` = element size), otherwise `%s` takes each `dimIndex` value (default 0..dim).
fn instances(element: &Element, name: &str, size: Option<u64>) -> Result<Vec<(String, u64)>, String> {
    let Some(dim) = element.text_of("dim") else {
        return Ok(vec![(name.replace("[%s]", "").replace("%s", ""), 0)]);
    };
    let count = number(dim)
        .filter(|count| (1..=MAX_DIM).contains(count))
        .ok_or_else(|| format!("{name}: dim {dim:?} is not 1..={MAX_DIM}"))?;
    let stride = element
        .text_of("dimIncrement")
        .and_then(number)
        .ok_or_else(|| format!("{name}: dim without a dimIncrement"))?;
    let indices: Vec<String> = match element.text_of("dimIndex") {
        Some(list) if list.contains('-') && !list.contains(',') => {
            let (first, last) = list.split_once('-').expect("contains '-'");
            match (first.trim().parse::<u64>(), last.trim().parse::<u64>()) {
                (Ok(first), Ok(last)) if last >= first && last - first < MAX_DIM => {
                    (first..=last).map(|index| index.to_string()).collect()
                }
                _ => {
                    let (first, last) = (first.trim().chars().next(), last.trim().chars().next());
                    match (first, last) {
                        (Some(first), Some(last)) if first.is_ascii_uppercase() && last >= first => {
                            (first..=last).map(String::from).collect()
                        }
                        _ => return Err(format!("{name}: unreadable dimIndex {list:?}")),
                    }
                }
            }
        }
        Some(list) => list.split(',').map(|index| index.trim().to_owned()).collect(),
        None => (0..count).map(|index| index.to_string()).collect(),
    };
    let array = name.contains("[%s]");
    let contiguous = size.is_some_and(|size| size == stride);
    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count {
        let offset = index.checked_mul(stride).ok_or_else(|| format!("{name}: dim offsets overflow"))?;
        let instance = if array && contiguous {
            name.replace("[%s]", &format!("[{index}]"))
        } else if array {
            name.replace("[%s]", &index.to_string())
        } else {
            let label = indices.get(index as usize).cloned().unwrap_or_else(|| index.to_string());
            name.replace("%s", &label)
        };
        result.push((instance, offset));
    }
    Ok(result)
}

/// A display name for a flattened register: `[n]` subscripts kept, everything else made an identifier.
fn register_name(text: &str) -> String {
    match text.find('[') {
        Some(open) if text.ends_with(']') && text[open + 1..text.len() - 1].bytes().all(|b| b.is_ascii_digit()) => {
            format!("{}{}", identifier(&text[..open]), &text[open..])
        }
        _ => identifier(text),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Device

struct Reader<'a> {
    warnings: Vec<String>,
    /// Registers, peripherals and fields-plus-enumerated-values produced so far, `dim` copies included.
    registers: usize,
    peripheral_count: usize,
    items: usize,
    /// A device-wide limit was passed: the file is refused, not just the element.
    fatal: Option<String>,
    peripherals: HashMap<&'a str, &'a Element>,
}

/// The fields and enumerated values a list of fields holds, as charged against [`MAX_FIELD_ITEMS`].
fn field_items(fields: &[BitField]) -> usize {
    fields.iter().map(|field| 1 + field.values.len()).sum()
}

/// Reads an SVD document.
pub fn parse(text: &str) -> Result<Device, String> {
    let root = parse_tree(text)?;
    if root.name != "device" {
        return Err(format!("not a CMSIS-SVD file: the root element is <{}>, not <device>", root.name));
    }
    let device = root.text_of("name").map(identifier).unwrap_or_else(|| "device".to_owned());
    let defaults = Properties::default().over(&root);
    let list = root.child("peripherals").ok_or("the SVD has no <peripherals>")?;
    let mut reader = Reader {
        warnings: Vec::new(),
        registers: 0,
        peripheral_count: 0,
        items: 0,
        fatal: None,
        peripherals: HashMap::new(),
    };
    for element in list.children("peripheral") {
        if let Some(name) = element.text_of("name") {
            reader.peripherals.entry(name).or_insert(element);
        }
    }
    let mut peripherals = Vec::new();
    for element in list.children("peripheral") {
        let found = reader.peripheral(&device, element, &defaults);
        if let Some(error) = reader.fatal.take() {
            return Err(error);
        }
        match found {
            Ok(mut found) => peripherals.append(&mut found),
            Err(error) => reader.warnings.push(error),
        }
    }
    Ok(Device { name: device, peripherals, warnings: reader.warnings })
}

impl<'a> Reader<'a> {
    /// Refuses the whole file: a device-wide limit was passed.
    fn refuse(&mut self, message: String) -> String {
        self.fatal.get_or_insert(message).clone()
    }

    /// Counts `count` more of something whose total may not pass `limit`.
    fn charge(
        &mut self,
        which: fn(&mut Self) -> &mut usize,
        count: usize,
        limit: usize,
        what: &str,
    ) -> Result<(), String> {
        let total = which(self).checked_add(count).filter(|&total| total <= limit);
        match total {
            Some(total) => {
                *which(self) = total;
                Ok(())
            }
            None => Err(self.refuse(format!("the SVD has more than {limit} {what}"))),
        }
    }

    /// The chain of elements `element` derives from, itself first.
    fn chain(&self, element: &'a Element) -> Result<Vec<&'a Element>, String> {
        let mut chain = vec![element];
        let mut current = element;
        while let Some(base) = current.attribute("derivedFrom") {
            // A dotted path names a peripheral's element; its last component names a sibling.
            let base = base.rsplit('.').next().unwrap_or(base);
            let next = *self.peripherals.get(base).ok_or_else(|| format!("derivedFrom {base:?} is not defined"))?;
            if chain.len() > MAX_DERIVATION || chain.iter().any(|seen| std::ptr::eq(*seen, next)) {
                return Err(format!("derivedFrom {base:?} is circular or deeper than {MAX_DERIVATION}"));
            }
            chain.push(next);
            current = next;
        }
        Ok(chain)
    }

    /// The register or cluster a dotted `derivedFrom` path names in another peripheral: `PERIPHERAL.REGISTER` or
    /// `PERIPHERAL.CLUSTER.REGISTER`, through that peripheral's own or derived registers.
    fn find_path(&self, path: &str) -> Option<&'a Element> {
        let mut parts = path.split('.');
        let peripheral = *self.peripherals.get(parts.next()?)?;
        let chain = self.chain(peripheral).ok()?;
        let mut container = chain.iter().find_map(|element| element.child("registers"))?;
        let mut found = None;
        for part in parts {
            let next = container.children.iter().find(|child| {
                (child.name == "register" || child.name == "cluster") && child.text_of("name") == Some(part)
            })?;
            container = next;
            found = Some(next);
        }
        found
    }

    fn peripheral(
        &mut self,
        device: &str,
        element: &'a Element,
        defaults: &Properties,
    ) -> Result<Vec<Peripheral>, String> {
        let raw_name = element.text_of("name").ok_or("a peripheral has no name")?;
        let chain = self.chain(element).map_err(|error| format!("peripheral {raw_name}: {error}"))?;
        let first = |name: &str| chain.iter().find_map(|element| element.text_of(name));
        let base = element
            .text_of("baseAddress")
            .and_then(number)
            .ok_or_else(|| format!("peripheral {raw_name}: missing or unreadable baseAddress"))?;
        let mut properties = defaults.clone();
        for element in chain.iter().rev() {
            properties = properties.over(element);
        }
        let instances = instances(element, raw_name, None)?;
        // A peripheral array copies every register: charge the copies before making any.
        self.charge(|reader| &mut reader.peripheral_count, instances.len(), MAX_PERIPHERALS, "peripherals")?;
        let registers_element = chain.iter().find_map(|element| element.child("registers"));
        let mut registers = Vec::new();
        if let Some(block) = registers_element {
            self.walk(block, "", 0, &properties, 0, &mut registers).map_err(|error| format!("{raw_name}: {error}"))?;
        }
        registers.sort_by_key(|register| register.offset);
        let copies = instances.len() - 1;
        let items: usize = registers.iter().map(|register| field_items(&register.fields)).sum();
        self.charge(
            |reader| &mut reader.registers,
            copies.saturating_mul(registers.len()),
            MAX_REGISTERS,
            "registers",
        )?;
        self.charge(
            |reader| &mut reader.items,
            copies.saturating_mul(items),
            MAX_FIELD_ITEMS,
            "fields and enumerated values",
        )?;
        let template = Peripheral {
            device: device.to_owned(),
            name: String::new(),
            group: first("groupName").map(identifier),
            description: chain.iter().find_map(|element| description(element)),
            base,
            registers,
        };
        let mut result = Vec::with_capacity(instances.len());
        for (name, offset) in instances {
            let base = base.checked_add(offset).ok_or_else(|| format!("peripheral {name}: address overflows"))?;
            if template.registers.iter().any(|register| {
                register.offset.checked_add(register.bytes()).and_then(|end| base.checked_add(end)).is_none()
            }) {
                return Err(format!("peripheral {name}: a register address overflows"));
            }
            result.push(Peripheral { name: identifier(&name), base, ..template.clone() });
        }
        Ok(result)
    }

    /// Flattens the registers and clusters of `container` into `out`, at `offset` from the peripheral base, with
    /// names prefixed by `prefix`.
    fn walk(
        &mut self,
        container: &'a Element,
        prefix: &str,
        offset: u64,
        properties: &Properties,
        depth: usize,
        out: &mut Vec<Register>,
    ) -> Result<(), String> {
        if depth > MAX_CLUSTER_DEPTH {
            return Err(format!("clusters nest deeper than {MAX_CLUSTER_DEPTH}"));
        }
        let siblings: BTreeMap<&str, &'a Element> = container
            .children
            .iter()
            .filter(|child| child.name == "register" || child.name == "cluster")
            .filter_map(|child| child.text_of("name").map(|name| (name, child)))
            .collect();
        for child in &container.children {
            if child.name != "register" && child.name != "cluster" {
                continue;
            }
            let Some(name) = child.text_of("name") else {
                self.warnings.push(format!("{prefix}: a {} has no name; skipped", child.name));
                continue;
            };
            // derivedFrom on a register or cluster names a sibling, or with a dotted path an element of another
            // peripheral.
            let mut chain = vec![child];
            let mut current = child;
            while let Some(base) = current.attribute("derivedFrom") {
                let next = if base.contains('.') { self.find_path(base) } else { siblings.get(base).copied() };
                match next {
                    Some(next)
                        if chain.len() <= MAX_DERIVATION && !chain.iter().any(|seen| std::ptr::eq(*seen, next)) =>
                    {
                        chain.push(next);
                        current = next;
                    }
                    _ => {
                        self.warnings.push(format!("{prefix}{name}: derivedFrom {base:?} not resolved"));
                        break;
                    }
                }
            }
            let mut own = properties.clone();
            for element in chain.iter().rev() {
                own = own.over(element);
            }
            let Some(local_offset) = chain.iter().find_map(|element| element.text_of("addressOffset")).and_then(number)
            else {
                self.warnings.push(format!("{prefix}{name}: no addressOffset; skipped"));
                continue;
            };
            let base = offset.checked_add(local_offset).ok_or("register offsets overflow")?;
            if child.name == "cluster" {
                for (instance, step) in instances(child, name, None)? {
                    let at = base.checked_add(step).ok_or("cluster offsets overflow")?;
                    let nested = format!("{prefix}{}_", identifier(&instance));
                    let body = chain
                        .iter()
                        .find(|element| element.child("register").is_some() || element.child("cluster").is_some());
                    if let Some(body) = body {
                        self.walk(body, &nested, at, &own, depth + 1, out)?;
                    }
                }
                continue;
            }
            let bits = own.bits.unwrap_or(32);
            if !(1..=64).contains(&bits) {
                self.warnings.push(format!("{prefix}{name}: size {bits} bits is not 1..=64; skipped"));
                continue;
            }
            let size = u64::from(bits.div_ceil(8));
            let fields = match chain.iter().find_map(|element| element.child("fields")) {
                Some(fields) => self.fields(fields, bits)?,
                None => Vec::new(),
            };
            let description = chain.iter().find_map(|element| description(element));
            let instances = instances(child, name, Some(size))?;
            self.charge(|reader| &mut reader.registers, instances.len(), MAX_REGISTERS, "registers")?;
            // `fields` charged the first copy's fields; every further copy clones them.
            let copies = (instances.len() - 1).saturating_mul(field_items(&fields));
            self.charge(|reader| &mut reader.items, copies, MAX_FIELD_ITEMS, "fields and enumerated values")?;
            for (instance, step) in instances {
                out.push(Register {
                    name: format!("{prefix}{}", register_name(&instance)),
                    offset: base.checked_add(step).ok_or("register offsets overflow")?,
                    bits,
                    access: own.access.clone(),
                    reset: own.reset,
                    description: description.clone(),
                    fields: fields.clone(),
                });
            }
        }
        Ok(())
    }

    fn fields(&mut self, container: &Element, bits: u32) -> Result<Vec<BitField>, String> {
        let mut result: Vec<BitField> = Vec::new();
        let siblings: BTreeMap<&str, &Element> =
            container.children("field").filter_map(|child| child.text_of("name").map(|name| (name, child))).collect();
        let bits = u64::from(bits);
        // Inside the register: lsb and width at most 64, and their sum within the register's bits.
        let inside = |lsb: u64, width: u64| width >= 1 && lsb.checked_add(width).is_some_and(|end| end <= bits);
        for element in container.children("field") {
            let Some(name) = element.text_of("name") else { continue };
            let base = element.attribute("derivedFrom").and_then(|base| siblings.get(base.rsplit('.').next()?));
            let text = |key: &str| element.text_of(key).or_else(|| base.and_then(|base| base.text_of(key)));
            let span = |lsb: u64, msb: u64| msb.checked_sub(lsb).and_then(|difference| difference.checked_add(1));
            let position = if let (Some(offset), Some(width)) = (text("bitOffset"), text("bitWidth")) {
                number(offset).zip(number(width))
            } else if let (Some(lsb), Some(msb)) = (text("lsb"), text("msb")) {
                number(lsb).zip(number(msb)).and_then(|(lsb, msb)| Some((lsb, span(lsb, msb)?)))
            } else if let Some(range) = text("bitRange") {
                range
                    .trim()
                    .strip_prefix('[')
                    .and_then(|range| range.strip_suffix(']'))
                    .and_then(|range| range.split_once(':'))
                    .and_then(|(msb, lsb)| number(lsb).zip(number(msb)))
                    .and_then(|(lsb, msb)| Some((lsb, span(lsb, msb)?)))
            } else {
                None
            };
            let Some((lsb, width)) = position.filter(|&(lsb, width)| lsb <= 64 && width <= 64 && inside(lsb, width))
            else {
                self.warnings.push(format!("field {name}: bit position missing or outside the register; skipped"));
                continue;
            };
            let mut values = Vec::new();
            let enumerated =
                element.child("enumeratedValues").or_else(|| base.and_then(|base| base.child("enumeratedValues")));
            for value in enumerated.into_iter().flat_map(|list| list.children("enumeratedValue")) {
                if values.len() >= MAX_VALUES {
                    break;
                }
                // isDefault entries and values with don't-care bits (`#1x0`) name no single value.
                if let (Some(label), Some(parsed)) = (value.text_of("name"), value.text_of("value").and_then(number)) {
                    values.push((identifier(label), parsed));
                }
            }
            let field_description = description(element).or_else(|| base.and_then(|base| description(base)));
            for (instance, step) in instances(element, name, Some(width)).unwrap_or_default() {
                let Some(lsb) = lsb.checked_add(step).filter(|&lsb| inside(lsb, width)) else {
                    self.warnings.push(format!("field {instance}: outside the register; skipped"));
                    continue;
                };
                if result.len() >= MAX_FIELDS {
                    continue;
                }
                self.charge(
                    |reader| &mut reader.items,
                    1 + values.len(),
                    MAX_FIELD_ITEMS,
                    "fields and enumerated values",
                )?;
                result.push(BitField {
                    name: identifier(&instance),
                    lsb: lsb as u32,
                    width: width as u32,
                    description: field_description.clone(),
                    values: values.clone(),
                });
            }
        }
        result.sort_by_key(|field| field.lsb);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

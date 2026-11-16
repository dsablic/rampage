//! Writers for synthetic fixtures (feature `testkit`): a DEX writer producing valid files with sorted id tables, a
//! correct map_list, checksum and signature. Tests patch its output to make hostile variants.

use std::collections::{BTreeMap, BTreeSet};

use sha1::{Digest, Sha1};

/// One code unit of a method body, or a symbolic reference resolved to its index when the file is written.
#[derive(Debug, Clone)]
pub enum Unit {
    Raw(u16),
    /// A 16-bit string index.
    String(String),
    /// A 32-bit string index in two units (const-string/jumbo).
    StringJumbo(String),
    Type(String),
    Field(FieldKey),
    Method(MethodKey),
    Proto(String, Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldKey {
    pub class: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodKey {
    pub class: String,
    pub name: String,
    pub ret: String,
    pub params: Vec<String>,
}

impl MethodKey {
    pub fn new(class: &str, name: &str, ret: &str, params: &[&str]) -> Self {
        Self {
            class: class.to_owned(),
            name: name.to_owned(),
            ret: ret.to_owned(),
            params: params.iter().map(|param| (*param).to_owned()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrySpec {
    pub start: u32,
    pub count: u16,
    pub catches: Vec<(String, u32)>,
    pub catch_all: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Code {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub units: Vec<Unit>,
    pub tries: Vec<TrySpec>,
}

#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub key: MethodKey,
    pub access: u32,
    pub code: Option<Code>,
}

#[derive(Debug, Clone)]
pub struct ClassSpec {
    pub name: String,
    pub access: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub fields: Vec<(FieldKey, u32, bool)>,
    pub methods: Vec<MethodSpec>,
}

impl ClassSpec {
    pub fn new(name: &str, superclass: &str) -> Self {
        Self {
            name: name.to_owned(),
            access: 1,
            superclass: Some(superclass.to_owned()),
            interfaces: Vec::new(),
            source_file: None,
            fields: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Adds a method; `access` 0x8 (static), 0x2 (private) or 0x10000 (constructor) makes it direct.
    pub fn method(mut self, name: &str, ret: &str, params: &[&str], access: u32, code: Option<Code>) -> Self {
        self.methods.push(MethodSpec { key: MethodKey::new(&self.name, name, ret, params), access, code });
        self
    }

    pub fn field(mut self, name: &str, kind: &str, access: u32) -> Self {
        let key = FieldKey { class: self.name.clone(), name: name.to_owned(), kind: kind.to_owned() };
        self.fields.push((key, access, access & 0x8 != 0));
        self
    }
}

fn shorty(kind: &str) -> char {
    match kind.as_bytes()[0] {
        b'L' | b'[' => 'L',
        byte => byte as char,
    }
}

fn uleb(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn sleb(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn mutf8(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        match unit {
            0x01..=0x7f => out.push(unit as u8),
            0x00 | 0x80..=0x7ff => {
                out.push(0xc0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
    out
}

fn align(out: &mut Vec<u8>, to: usize) {
    while !out.len().is_multiple_of(to) {
        out.push(0);
    }
}

fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Recomputes the SHA-1 signature and Adler-32 checksum of a DEX file in place.
pub fn fix_checksums(dex: &mut [u8]) {
    let digest = Sha1::digest(&dex[32..]);
    dex[12..32].copy_from_slice(&digest);
    let checksum = crate::read::adler32(&dex[12..]);
    put32(dex, 8, checksum);
}

/// Writes a DEX file (version `version`, 35 through 41) defining `classes`.
pub fn write_dex(classes: &[ClassSpec], version: u16) -> Vec<u8> {
    let mut strings: BTreeSet<String> = BTreeSet::new();
    let mut types: BTreeSet<String> = BTreeSet::new();
    let mut protos: BTreeSet<(String, Vec<String>)> = BTreeSet::new();
    let mut fields: BTreeSet<FieldKey> = BTreeSet::new();
    let mut methods: BTreeSet<MethodKey> = BTreeSet::new();
    let add_type = |types: &mut BTreeSet<String>, strings: &mut BTreeSet<String>, kind: &str| {
        types.insert(kind.to_owned());
        strings.insert(kind.to_owned());
    };
    let add_proto = |protos: &mut BTreeSet<(String, Vec<String>)>, ret: &str, params: &[String]| {
        protos.insert((ret.to_owned(), params.to_vec()));
    };
    let add_method = |key: &MethodKey,
                      strings: &mut BTreeSet<String>,
                      types: &mut BTreeSet<String>,
                      protos: &mut BTreeSet<(String, Vec<String>)>,
                      methods: &mut BTreeSet<MethodKey>| {
        add_type(types, strings, &key.class);
        add_type(types, strings, &key.ret);
        for param in &key.params {
            add_type(types, strings, param);
        }
        strings.insert(key.name.clone());
        add_proto(protos, &key.ret, &key.params);
        methods.insert(key.clone());
    };
    for class in classes {
        add_type(&mut types, &mut strings, &class.name);
        if let Some(superclass) = &class.superclass {
            add_type(&mut types, &mut strings, superclass);
        }
        for interface in &class.interfaces {
            add_type(&mut types, &mut strings, interface);
        }
        if let Some(source) = &class.source_file {
            strings.insert(source.clone());
        }
        for (key, _, _) in &class.fields {
            add_type(&mut types, &mut strings, &key.class);
            add_type(&mut types, &mut strings, &key.kind);
            strings.insert(key.name.clone());
            fields.insert(key.clone());
        }
        for method in &class.methods {
            add_method(&method.key, &mut strings, &mut types, &mut protos, &mut methods);
            for unit in method.code.iter().flat_map(|code| &code.units) {
                match unit {
                    Unit::String(text) | Unit::StringJumbo(text) => {
                        strings.insert(text.clone());
                    }
                    Unit::Type(kind) => add_type(&mut types, &mut strings, kind),
                    Unit::Field(key) => {
                        add_type(&mut types, &mut strings, &key.class);
                        add_type(&mut types, &mut strings, &key.kind);
                        strings.insert(key.name.clone());
                        fields.insert(key.clone());
                    }
                    Unit::Method(key) => add_method(key, &mut strings, &mut types, &mut protos, &mut methods),
                    Unit::Proto(ret, params) => {
                        add_type(&mut types, &mut strings, ret);
                        for param in params {
                            add_type(&mut types, &mut strings, param);
                        }
                        add_proto(&mut protos, ret, params);
                    }
                    Unit::Raw(_) => {}
                }
            }
            for spec in method.code.iter().flat_map(|code| &code.tries) {
                for (kind, _) in &spec.catches {
                    add_type(&mut types, &mut strings, kind);
                }
            }
        }
    }
    for (ret, params) in &protos {
        let short: String = std::iter::once(ret).chain(params).map(|kind| shorty(kind)).collect();
        strings.insert(short);
    }
    let string_list: Vec<String> = strings.into_iter().collect();
    let string_index: BTreeMap<&str, u32> =
        string_list.iter().enumerate().map(|(index, text)| (text.as_str(), index as u32)).collect();
    // Type ids sort by their string index, which BTreeSet order of the same strings already gives.
    let type_list: Vec<String> = types.into_iter().collect();
    let type_index: BTreeMap<&str, u32> =
        type_list.iter().enumerate().map(|(index, text)| (text.as_str(), index as u32)).collect();
    let mut proto_list: Vec<(String, Vec<String>)> = protos.into_iter().collect();
    proto_list.sort_by_key(|(ret, params)| {
        (type_index[ret.as_str()], params.iter().map(|param| type_index[param.as_str()]).collect::<Vec<_>>())
    });
    let proto_index: BTreeMap<(String, Vec<String>), u32> =
        proto_list.iter().enumerate().map(|(index, proto)| (proto.clone(), index as u32)).collect();
    let mut field_list: Vec<FieldKey> = fields.into_iter().collect();
    field_list.sort_by_key(|key| {
        (type_index[key.class.as_str()], string_index[key.name.as_str()], type_index[key.kind.as_str()])
    });
    let field_index: BTreeMap<FieldKey, u32> =
        field_list.iter().enumerate().map(|(index, key)| (key.clone(), index as u32)).collect();
    let mut method_list: Vec<MethodKey> = methods.into_iter().collect();
    method_list.sort_by_key(|key| {
        (
            type_index[key.class.as_str()],
            string_index[key.name.as_str()],
            proto_index[&(key.ret.clone(), key.params.clone())],
        )
    });
    let method_index: BTreeMap<MethodKey, u32> =
        method_list.iter().enumerate().map(|(index, key)| (key.clone(), index as u32)).collect();

    let header_size = if version >= 41 { 0x78 } else { 0x70 };
    let mut out = vec![0u8; header_size];
    let string_ids_off = out.len();
    out.resize(out.len() + string_list.len() * 4, 0);
    let type_ids_off = out.len();
    for kind in &type_list {
        out.extend_from_slice(&string_index[kind.as_str()].to_le_bytes());
    }
    let proto_ids_off = out.len();
    out.resize(out.len() + proto_list.len() * 12, 0);
    let field_ids_off = out.len();
    for key in &field_list {
        out.extend_from_slice(&(type_index[key.class.as_str()] as u16).to_le_bytes());
        out.extend_from_slice(&(type_index[key.kind.as_str()] as u16).to_le_bytes());
        out.extend_from_slice(&string_index[key.name.as_str()].to_le_bytes());
    }
    let method_ids_off = out.len();
    for key in &method_list {
        out.extend_from_slice(&(type_index[key.class.as_str()] as u16).to_le_bytes());
        out.extend_from_slice(&(proto_index[&(key.ret.clone(), key.params.clone())] as u16).to_le_bytes());
        out.extend_from_slice(&string_index[key.name.as_str()].to_le_bytes());
    }
    let class_defs_off = out.len();
    out.resize(out.len() + classes.len() * 32, 0);
    let data_off = out.len();

    // Type lists: proto parameters and interfaces.
    let mut type_lists: BTreeMap<Vec<String>, u32> = BTreeMap::new();
    let type_lists_off = out.len();
    let mut type_list_count = 0;
    let wanted_lists = proto_list
        .iter()
        .map(|(_, params)| params.clone())
        .chain(classes.iter().map(|class| class.interfaces.clone()))
        .filter(|list| !list.is_empty());
    for list in wanted_lists {
        if type_lists.contains_key(&list) {
            continue;
        }
        align(&mut out, 4);
        type_lists.insert(list.clone(), out.len() as u32);
        type_list_count += 1;
        out.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for kind in &list {
            out.extend_from_slice(&(type_index[kind.as_str()] as u16).to_le_bytes());
        }
    }
    for (index, (ret, params)) in proto_list.iter().enumerate() {
        let short: String = std::iter::once(ret).chain(params).map(|kind| shorty(kind)).collect();
        let at = proto_ids_off + index * 12;
        put32(&mut out, at, string_index[short.as_str()]);
        put32(&mut out, at + 4, type_index[ret.as_str()]);
        put32(&mut out, at + 8, if params.is_empty() { 0 } else { type_lists[params] });
    }
    let string_data_off = out.len();
    for (index, text) in string_list.iter().enumerate() {
        let here = out.len() as u32;
        put32(&mut out, string_ids_off + index * 4, here);
        uleb(&mut out, text.encode_utf16().count() as u32);
        out.extend_from_slice(&mutf8(text));
        out.push(0);
    }
    align(&mut out, 4);
    let code_off = out.len();
    let mut code_count = 0;
    let mut code_offsets: BTreeMap<MethodKey, u32> = BTreeMap::new();
    for class in classes {
        for method in &class.methods {
            let Some(code) = &method.code else { continue };
            align(&mut out, 4);
            code_offsets.insert(method.key.clone(), out.len() as u32);
            code_count += 1;
            let mut units: Vec<u16> = Vec::new();
            for unit in &code.units {
                match unit {
                    Unit::Raw(value) => units.push(*value),
                    Unit::String(text) => units.push(string_index[text.as_str()] as u16),
                    Unit::StringJumbo(text) => {
                        let index = string_index[text.as_str()];
                        units.push(index as u16);
                        units.push((index >> 16) as u16);
                    }
                    Unit::Type(kind) => units.push(type_index[kind.as_str()] as u16),
                    Unit::Field(key) => units.push(field_index[key] as u16),
                    Unit::Method(key) => units.push(method_index[key] as u16),
                    Unit::Proto(ret, params) => units.push(proto_index[&(ret.clone(), params.clone())] as u16),
                }
            }
            for value in [code.registers, code.ins, code.outs, code.tries.len() as u16] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(units.len() as u32).to_le_bytes());
            for unit in &units {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            if !code.tries.is_empty() {
                if units.len() % 2 == 1 {
                    out.extend_from_slice(&[0, 0]);
                }
                let mut handlers = Vec::new();
                uleb(&mut handlers, code.tries.len() as u32);
                let mut offsets = Vec::new();
                for spec in &code.tries {
                    offsets.push(handlers.len() as u16);
                    let count = spec.catches.len() as i32;
                    sleb(&mut handlers, if spec.catch_all.is_some() { -count } else { count });
                    for (kind, address) in &spec.catches {
                        uleb(&mut handlers, type_index[kind.as_str()]);
                        uleb(&mut handlers, *address);
                    }
                    if let Some(address) = spec.catch_all {
                        uleb(&mut handlers, address);
                    }
                }
                for (spec, offset) in code.tries.iter().zip(offsets) {
                    out.extend_from_slice(&spec.start.to_le_bytes());
                    out.extend_from_slice(&spec.count.to_le_bytes());
                    out.extend_from_slice(&offset.to_le_bytes());
                }
                out.extend_from_slice(&handlers);
            }
        }
    }
    let class_data_off = out.len();
    let mut class_data_count = 0;
    for (index, class) in classes.iter().enumerate() {
        let at = class_defs_off + index * 32;
        put32(&mut out, at, type_index[class.name.as_str()]);
        put32(&mut out, at + 4, class.access);
        put32(&mut out, at + 8, class.superclass.as_ref().map_or(u32::MAX, |name| type_index[name.as_str()]));
        put32(&mut out, at + 12, if class.interfaces.is_empty() { 0 } else { type_lists[&class.interfaces] });
        put32(&mut out, at + 16, class.source_file.as_ref().map_or(u32::MAX, |name| string_index[name.as_str()]));
        if class.fields.is_empty() && class.methods.is_empty() {
            continue;
        }
        let here = out.len() as u32;
        put32(&mut out, at + 24, here);
        class_data_count += 1;
        let mut statics: Vec<_> = class.fields.iter().filter(|field| field.2).collect();
        let mut instance: Vec<_> = class.fields.iter().filter(|field| !field.2).collect();
        statics.sort_by_key(|field| field_index[&field.0]);
        instance.sort_by_key(|field| field_index[&field.0]);
        let mut direct: Vec<_> =
            class.methods.iter().filter(|method| method.access & (0x8 | 0x2 | 0x1_0000) != 0).collect();
        let mut virtuals: Vec<_> =
            class.methods.iter().filter(|method| method.access & (0x8 | 0x2 | 0x1_0000) == 0).collect();
        direct.sort_by_key(|method| method_index[&method.key]);
        virtuals.sort_by_key(|method| method_index[&method.key]);
        for count in [statics.len(), instance.len(), direct.len(), virtuals.len()] {
            uleb(&mut out, count as u32);
        }
        for list in [&statics, &instance] {
            let mut previous = 0;
            for (key, access, _) in list.iter().copied() {
                let index = field_index[key];
                uleb(&mut out, index - previous);
                uleb(&mut out, *access);
                previous = index;
            }
        }
        for list in [&direct, &virtuals] {
            let mut previous = 0;
            for method in list.iter() {
                let index = method_index[&method.key];
                uleb(&mut out, index - previous);
                uleb(&mut out, method.access);
                uleb(&mut out, code_offsets.get(&method.key).copied().unwrap_or(0));
                previous = index;
            }
        }
    }
    align(&mut out, 4);
    let map_off = out.len();
    let mut map: Vec<(u16, u32, usize)> = vec![
        (0x0000, 1, 0),
        (0x0001, string_list.len() as u32, string_ids_off),
        (0x0002, type_list.len() as u32, type_ids_off),
        (0x0003, proto_list.len() as u32, proto_ids_off),
        (0x0004, field_list.len() as u32, field_ids_off),
        (0x0005, method_list.len() as u32, method_ids_off),
        (0x0006, classes.len() as u32, class_defs_off),
        (0x1001, type_list_count, type_lists_off),
        (0x2002, string_list.len() as u32, string_data_off),
        (0x2001, code_count, code_off),
        (0x2000, class_data_count, class_data_off),
        (0x1000, 1, map_off),
    ];
    map.retain(|&(_, count, _)| count > 0);
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (code, count, offset) in &map {
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(*offset as u32).to_le_bytes());
    }
    let file_size = out.len();
    out[..8].copy_from_slice(format!("dex\n0{version:02}\0").as_bytes());
    let table = |out: &mut Vec<u8>, at: usize, count: usize, offset: usize| {
        put32(out, at, count as u32);
        put32(out, at + 4, if count == 0 { 0 } else { offset as u32 });
    };
    put32(&mut out, 0x20, file_size as u32);
    put32(&mut out, 0x24, header_size as u32);
    put32(&mut out, 0x28, 0x1234_5678);
    put32(&mut out, 0x34, map_off as u32);
    table(&mut out, 0x38, string_list.len(), string_ids_off);
    table(&mut out, 0x40, type_list.len(), type_ids_off);
    table(&mut out, 0x48, proto_list.len(), proto_ids_off);
    table(&mut out, 0x50, field_list.len(), field_ids_off);
    table(&mut out, 0x58, method_list.len(), method_ids_off);
    table(&mut out, 0x60, classes.len(), class_defs_off);
    table(&mut out, 0x68, file_size - data_off, data_off);
    if version >= 41 {
        put32(&mut out, 0x70, file_size as u32);
        put32(&mut out, 0x74, 0);
    }
    fix_checksums(&mut out);
    out
}

/// The class every sample uses for the capture code.
pub const CAPTURE_CLASS: &str = "Lcom/example/recorder/Capture;";
/// The receiver the sample manifest registers for `BOOT_COMPLETED`.
pub const BOOT_RECEIVER_CLASS: &str = "Lcom/example/recorder/BootReceiver;";
/// The URL the sample's `start` method loads with const-string.
pub const SAMPLE_URL: &str = "https://telemetry.example.com/upload";

/// The sample classes: `Capture` (constructor; `start` creating an `AudioRecord`, calling `startRecording` and
/// loading [`SAMPLE_URL`]; native `nativeEncode([B)I`; `dispatch(I)I` with a packed switch; `guarded()V` with a
/// try/catch; `send(String)V`) and a `BootReceiver` whose `onReceive` calls `Capture.guarded`.
pub fn sample_classes() -> Vec<ClassSpec> {
    let object = "Ljava/lang/Object;";
    let audio = "Landroid/media/AudioRecord;";
    let raw = Unit::Raw;
    let start = Code {
        registers: 3,
        ins: 1,
        outs: 1,
        units: vec![
            raw(0x0022),
            Unit::Type(audio.to_owned()),
            raw(0x106e),
            Unit::Method(MethodKey::new(audio, "startRecording", "V", &[])),
            raw(0x0000),
            raw(0x011a),
            Unit::String(SAMPLE_URL.to_owned()),
            raw(0x1071),
            Unit::Method(MethodKey::new(CAPTURE_CLASS, "send", "V", &["Ljava/lang/String;"])),
            raw(0x0001),
            raw(0x000e),
        ],
        tries: Vec::new(),
    };
    let init = Code {
        registers: 1,
        ins: 1,
        outs: 1,
        units: vec![raw(0x1070), Unit::Method(MethodKey::new(object, "<init>", "V", &[])), raw(0x0000), raw(0x000e)],
        tries: Vec::new(),
    };
    let dispatch = Code {
        registers: 2,
        ins: 1,
        outs: 0,
        units: vec![
            raw(0x012b),
            raw(8),
            raw(0),
            raw(0x0012),
            raw(0x000f),
            raw(0x1012),
            raw(0x000f),
            raw(0x0000),
            raw(0x0100),
            raw(1),
            raw(0x10),
            raw(0),
            raw(5),
            raw(0),
        ],
        tries: Vec::new(),
    };
    let guarded = Code {
        registers: 1,
        ins: 0,
        outs: 0,
        units: vec![
            raw(0x0071),
            Unit::Method(MethodKey::new("Ljava/lang/System;", "nanoTime", "J", &[])),
            raw(0x0000),
            raw(0x000e),
            raw(0x000d),
            raw(0x000e),
        ],
        tries: vec![TrySpec {
            start: 0,
            count: 3,
            catches: vec![("Ljava/io/IOException;".to_owned(), 4)],
            catch_all: None,
        }],
    };
    let send = Code { registers: 1, ins: 1, outs: 0, units: vec![raw(0x000e)], tries: Vec::new() };
    let mut capture = ClassSpec::new(CAPTURE_CLASS, object)
        .method("<init>", "V", &[], 0x1_0001, Some(init))
        .method("start", "V", &[], 0x1, Some(start))
        .method("nativeEncode", "I", &["[B"], 0x101, None)
        .method("dispatch", "I", &["I"], 0x9, Some(dispatch))
        .method("guarded", "V", &[], 0x9, Some(guarded))
        .method("send", "V", &["Ljava/lang/String;"], 0x9, Some(send))
        .field("label", "Ljava/lang/String;", 0x2)
        .field("COUNT", "I", 0x19);
    capture.source_file = Some("Capture.java".to_owned());
    let on_receive = Code {
        registers: 3,
        ins: 3,
        outs: 0,
        units: vec![raw(0x0071), Unit::Method(MethodKey::new(CAPTURE_CLASS, "guarded", "V", &[])), raw(0), raw(0x000e)],
        tries: Vec::new(),
    };
    let receiver = ClassSpec::new(BOOT_RECEIVER_CLASS, "Landroid/content/BroadcastReceiver;").method(
        "onReceive",
        "V",
        &["Landroid/content/Context;", "Landroid/content/Intent;"],
        0x1,
        Some(on_receive),
    );
    vec![capture, receiver]
}

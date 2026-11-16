//! `dex_code`: the Dalvik bytecode of one method of an APK or DEX file, smali style, with every string, type,
//! field, method, proto, call-site and method-handle reference resolved to text, try ranges with their handlers,
//! and payloads (packed-switch, sparse-switch, fill-array-data). Paged by instruction.

use std::path::PathBuf;

use rampage_dex::dex::{Dex, EncodedMethod, Member, access_names, descriptor_of};
use rampage_dex::insn::disassemble;
use serde_json::{Value, json};

use crate::android::{Opened, open};

const DEFAULT_LIMIT: usize = 200;
pub const MAX_CODE_PAGE: usize = 1000;
const PAGE_BYTES: usize = 40_000;
const MAX_CANDIDATES: usize = 20;

pub struct DexCodeQuery {
    pub path: PathBuf,
    /// `Lpkg/Class;->name(params)ret`, `Lpkg/Class;->name`, `pkg.Class.name`, `pkg.Class.name(params)ret`, a
    /// method index (`12`, in the first DEX file) or `classes2.dex:12`.
    pub method: String,
    /// Instructions to skip.
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    /// Start at the instruction holding this code-unit address (`:0012`, `0x12` or `18`).
    pub at: Option<String>,
}

/// A defined method found by a selector.
struct Found<'a> {
    dex_path: &'a str,
    dex: &'a Dex,
    method: EncodedMethod,
}

fn parse_address(text: &str) -> Result<u32, String> {
    let trimmed = text.trim().trim_start_matches(':');
    let parsed = match trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None if text.trim().starts_with(':') => u32::from_str_radix(trimmed, 16),
        None => trimmed.parse(),
    };
    parsed.map_err(|_| format!("`{text}` is not a code address (:0012, 0x12 or 18)"))
}

/// Splits a selector into (class descriptor, method name, optional `(params)ret`).
fn split_selector(selector: &str) -> Option<(String, String, Option<String>)> {
    let (head, signature) = match selector.find('(') {
        Some(at) => (&selector[..at], Some(selector[at..].to_owned())),
        None => (selector, None),
    };
    let (class, name) = if let Some((class, name)) = head.split_once("->") {
        (class.to_owned(), name.to_owned())
    } else if let Some((class, name)) = head.split_once("::") {
        (class.to_owned(), name.to_owned())
    } else {
        let (class, name) = head.rsplit_once('.')?;
        (class.to_owned(), name.to_owned())
    };
    (!class.is_empty() && !name.is_empty()).then(|| (descriptor_of(class.trim()), name.trim().to_owned(), signature))
}

/// Every defined method of every parsed DEX file, with its file.
fn defined<'a>(opened: &'a Opened) -> Vec<Found<'a>> {
    let mut found = Vec::new();
    for (dex_path, dex) in opened.parsed() {
        let mut budget = dex.limits.max_members;
        for index in 0..dex.class_count() {
            let Ok(class) = dex.class_def(index) else { continue };
            let Ok(data) = dex.class_data(&class, &mut budget) else { continue };
            found.extend(data.methods().map(|method| Found { dex_path, dex, method: *method }));
        }
    }
    found
}

fn find<'a>(opened: &'a Opened, selector: &str) -> Result<Found<'a>, String> {
    let all = defined(opened);
    let first = opened.parsed().next().map(|(path, _)| path);
    let indexed = if let Ok(index) = selector.trim().parse::<u32>() {
        Some((first, index))
    } else {
        selector.rsplit_once(':').and_then(|(file, index)| {
            let index = index.trim().parse::<u32>().ok()?;
            file.trim().ends_with(".dex").then(|| (Some(file.trim()), index))
        })
    };
    if let Some((dex_path, index)) = indexed {
        return all
            .into_iter()
            .find(|found| Some(found.dex_path) == dex_path && found.method.method_idx == index)
            .ok_or_else(|| format!("no method with index {index} is defined in {}", dex_path.unwrap_or("the file")));
    }
    let (class, name, signature) = split_selector(selector).ok_or_else(|| {
        format!("`{selector}` names no method (Lpkg/Class;->name(params)ret, pkg.Class.name or an index)")
    })?;
    let mut candidates: Vec<Found<'a>> = all
        .into_iter()
        .filter(|found| {
            let Ok(class_idx) = found.dex.method_class_idx(found.method.method_idx) else { return false };
            if found.dex.type_text(class_idx) != class {
                return false;
            }
            let Ok(method) = found.dex.method(found.method.method_idx) else { return false };
            method.name == name && signature.as_ref().is_none_or(|signature| method.proto.descriptor() == *signature)
        })
        .collect();
    match candidates.len() {
        0 => {
            Err(format!("no method `{name}` is defined on {class} in this file; dex_metadata list methods shows them"))
        }
        1 => Ok(candidates.pop().unwrap()),
        count => {
            let names: Vec<String> = candidates
                .iter()
                .take(MAX_CANDIDATES)
                .map(|found| {
                    format!(
                        "{}:{} {}",
                        found.dex_path,
                        found.method.method_idx,
                        found.dex.method_text(found.method.method_idx)
                    )
                })
                .collect();
            Err(format!("`{selector}` matches {count} overloads; give the signature or an index: {}", names.join("; ")))
        }
    }
}

pub fn dex_code(query: &DexCodeQuery) -> Result<Value, String> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_CODE_PAGE).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_CODE_PAGE}"));
    }
    if query.method.len() > 4096 {
        return Err("method selector longer than 4096 bytes".to_owned());
    }
    let opened = open(&query.path, false)?;
    let found = find(&opened, &query.method)?;
    let dex = found.dex;
    let mut out = json!({
        "path": query.path,
        "dex": found.dex_path,
        "index": found.method.method_idx,
        "method": dex.method_text(found.method.method_idx),
        "access": access_names(found.method.access, Member::Method),
    });
    if found.method.code_off == 0 {
        out["body"] = Value::Null;
        out["note"] = json!(if found.method.access & rampage_dex::dex::ACC_NATIVE != 0 {
            "native method: its code is in a native library (dex_metadata native_libs, jni)"
        } else {
            "abstract or interface method: no body"
        });
        return Ok(out);
    }
    let code = dex.code_item(found.method.code_off).map_err(|error| format!("{}: {error}", out["method"]))?;
    let insns = disassemble(dex, &code.insns);
    let start = match &query.at {
        Some(at) => {
            let address = parse_address(at)?;
            if address as usize >= code.insns.len() {
                return Err(format!(":{address:04x} is past the end of the {}-unit body", code.insns.len()));
            }
            insns.partition_point(|insn| insn.address <= address).saturating_sub(1)
        }
        None => query.offset.unwrap_or(0),
    };
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let mut byte_capped = false;
    for insn in insns.iter().skip(start).take(limit) {
        let mut row = json!({"address": format!("{:04x}", insn.address), "op": insn.mnemonic, "args": insn.operands});
        if let Some(reference) = &insn.reference {
            row["ref"] = json!({"kind": reference.kind, "index": reference.index});
        }
        let size = row.to_string().len() + 1;
        if bytes + size > PAGE_BYTES && !rows.is_empty() {
            byte_capped = true;
            break;
        }
        bytes += size;
        rows.push(row);
    }
    let end = start + rows.len();
    let tries: Vec<Value> = code
        .tries
        .iter()
        .map(|range| {
            let handlers: Vec<Value> = range
                .handlers
                .iter()
                .map(|handler| {
                    json!({
                        "type": handler.type_idx.map_or_else(|| "<any>".to_owned(), |index| dex.type_text(index)),
                        "handler": format!(":{:04x}", handler.address),
                    })
                })
                .collect();
            json!({
                "start": format!(":{:04x}", range.start),
                "end": format!(":{:04x}", range.start + u32::from(range.count)),
                "handlers": handlers,
            })
        })
        .collect();
    out["registers"] = json!(code.registers);
    out["ins"] = json!(code.ins);
    out["outs"] = json!(code.outs);
    out["code_units"] = json!(code.insns.len());
    out["tries"] = json!(tries);
    out["instructions_total"] = json!(insns.len());
    out["offset"] = json!(start);
    out["instructions"] = json!(rows);
    out["next_offset"] = json!((end < insns.len()).then_some(end));
    out["byte_capped"] = json!(byte_capped);
    Ok(out)
}

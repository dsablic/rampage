//! Collects system register names (for MRS/MSR) and system operation names (DC, IC, AT, TLBI, ...) keyed by
//! their `op0:op1:CRn:CRm:op2` encoding.

use std::collections::BTreeSet;
use std::fmt::Write;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::str_of;

pub struct Registers {
    /// (op0:op1:CRn:CRm:op2, name) for registers readable with MRS.
    pub system_registers: BTreeSet<(u16, String)>,
    /// (op0:op1:CRn:CRm:op2, name) for registers writable with MSR.
    writable_registers: BTreeSet<(u16, String)>,
    /// (op1:CRm:op2, name) for PSTATE fields written with MSR (immediate); CRm bits the field leaves open are
    /// expanded.
    pstate_fields: BTreeSet<(u16, String)>,
    /// (op1:CRn:CRm:op2, kind, name) for system instructions.
    pub system_operations: BTreeSet<(u16, String, String)>,
}

/// (field, width) in key order.
const KEY_FIELDS: [(&str, u32); 5] = [("op0", 2), ("op1", 3), ("CRn", 4), ("CRm", 4), ("op2", 3)];

pub fn collect(registers: &Value) -> Result<Registers> {
    let mut result = Registers {
        system_registers: BTreeSet::new(),
        writable_registers: BTreeSet::new(),
        pstate_fields: BTreeSet::new(),
        system_operations: BTreeSet::new(),
    };
    for register in registers.as_array().context("registers")? {
        if register["state"] != "AArch64" {
            continue;
        }
        for accessor in register["accessors"].as_array().into_iter().flatten() {
            let kind = str_of(&accessor["name"]).trim_start_matches("A64.");
            let indexes = match accessor["_type"].as_str() {
                Some("Accessors.SystemAccessorArray") => {
                    let range = accessor["indexes"].get(0).context("array indexes")?;
                    let start = range["start"].as_u64().context("index start")?;
                    let width = range["width"].as_u64().context("index width")?;
                    let variable = str_of(&accessor["index_variable"]).to_owned();
                    (start..start + width).map(|i| Some((variable.clone(), i))).collect()
                }
                _ => vec![None],
            };
            for encoding in accessor["encoding"].as_array().into_iter().flatten() {
                for index in &indexes {
                    let Some(name) = encoding["asmvalue"].as_str() else { continue };
                    let name = match index {
                        Some((variable, i)) => name.replace(&format!("<{variable}>"), &i.to_string()),
                        None => name.to_owned(),
                    };
                    // Generic encodings such as S1_<op1>_<Cn>_<Cm>_<op2> carry no name.
                    if name.contains('<') {
                        continue;
                    }
                    let Some(keys) = expand(&encoding["encodings"], index.as_ref())? else { continue };
                    result.add(kind, &name, &keys);
                }
            }
        }
    }
    Ok(result)
}

impl Registers {
    fn add(&mut self, kind: &str, name: &str, keys: &[u16]) {
        for &key in keys {
            match kind {
                "MRS" | "MRRS" => {
                    self.system_registers.insert((key, name.to_owned()));
                }
                "MSRregister" | "MSRRregister" => {
                    self.writable_registers.insert((key, name.to_owned()));
                }
                "MSRimmediate" => {
                    let op1 = (key >> 11) & 0x7;
                    let crm = (key >> 3) & 0xf;
                    let op2 = key & 0x7;
                    self.pstate_fields.insert(((op1 << 7) | (crm << 3) | op2, name.to_owned()));
                }
                _ => {
                    // Drop op0 (always 01 for system instructions).
                    self.system_operations.insert((key & 0x3fff, kind.to_owned(), name.to_owned()));
                }
            }
        }
    }

    pub fn emit(&self, out: &mut String) -> std::fmt::Result {
        let table = |out: &mut String, doc: &str, name: &str, rows: &BTreeSet<(u16, String)>| -> std::fmt::Result {
            writeln!(out, "/// {doc}")?;
            writeln!(out, "pub static {name}: [(u16, &str); {}] = [", rows.len())?;
            for (key, value) in rows {
                writeln!(out, "    ({key:#06x}, {value:?}),")?;
            }
            writeln!(out, "];")?;
            writeln!(out)
        };
        table(
            out,
            "System registers readable with MRS, by op0:op1:CRn:CRm:op2.",
            "MRS_REGISTERS",
            &self.system_registers,
        )?;
        table(
            out,
            "System registers writable with MSR, by op0:op1:CRn:CRm:op2.",
            "MSR_REGISTERS",
            &self.writable_registers,
        )?;
        table(out, "PSTATE fields for MSR (immediate), by op1:CRm:op2.", "PSTATE_FIELDS", &self.pstate_fields)?;
        writeln!(out, "/// System instructions by op1:CRn:CRm:op2.")?;
        writeln!(out, "pub static SYSTEM_OPERATIONS: [(u16, SysKind, &str); {}] = [", self.system_operations.len())?;
        for (key, kind, name) in &self.system_operations {
            writeln!(out, "    ({key:#06x}, SysKind::{}, {name:?}),", kind_variant(kind))?;
        }
        writeln!(out, "];")
    }
}

fn kind_variant(kind: &str) -> String {
    let mut variant = String::new();
    for (i, c) in kind.chars().enumerate() {
        if i == 0 { variant.extend(c.to_uppercase()) } else { variant.extend(c.to_lowercase()) }
    }
    variant
}

/// Expands an accessor's field values into every concrete 16-bit key they match. Returns `None` for
/// encodings that depend on an unbound variable.
fn expand(encodings: &Value, index: Option<&(String, u64)>) -> Result<Option<Vec<u16>>> {
    let mut keys = vec![0u16];
    for (field, width) in KEY_FIELDS {
        let Some(value) = encodings.get(field) else {
            // A missing field (CRm in a few PSTATE encodings) matches any value.
            keys = keys.iter().flat_map(|&k| (0..1u16 << width).map(move |v| (k << width) | v)).collect();
            continue;
        };
        let Some(patterns) = field_patterns(value, width, index)? else { return Ok(None) };
        let mut next = Vec::new();
        for &key in &keys {
            for pattern in &patterns {
                for v in pattern_values(pattern) {
                    next.push((key << width) | v);
                }
            }
        }
        keys = next;
    }
    Ok(Some(keys))
}

fn field_patterns(value: &Value, width: u32, index: Option<&(String, u64)>) -> Result<Option<Vec<String>>> {
    let text = str_of(&value["value"]);
    let pattern = match str_of(&value["_type"]) {
        "Values.Value" => text.trim_matches('\'').to_owned(),
        "Values.Group" => {
            let mut bits = String::new();
            for part in text.split(':') {
                if part.starts_with('\'') {
                    bits.push_str(part.trim_matches('\''));
                } else {
                    let Some(bit) = index_bits(part, index)? else { return Ok(None) };
                    bits.push_str(&bit);
                }
            }
            bits
        }
        "Values.EquationValue" => {
            let Some((variable, i)) = index else { return Ok(None) };
            if text != variable {
                return Ok(None);
            }
            let range = &value["slice"][0];
            let start = range["start"].as_u64().context("slice start")?;
            let slice_width = range["width"].as_u64().context("slice width")?;
            let bits = (i >> start) & ((1 << slice_width) - 1);
            format!("{bits:0width$b}", width = slice_width as usize)
        }
        other => bail!("unexpected register field value {other}"),
    };
    if pattern.len() != width as usize {
        bail!("register field pattern {pattern:?} is not {width} bits");
    }
    Ok(Some(vec![pattern]))
}

/// Resolves `p[3]` or `p[3:1]` against the array index.
fn index_bits(part: &str, index: Option<&(String, u64)>) -> Result<Option<String>> {
    let Some((variable, i)) = index else { return Ok(None) };
    let Some(rest) = part.strip_prefix(variable.as_str()) else { return Ok(None) };
    let inner = rest.trim_start_matches('[').trim_end_matches(']');
    let (high, low) = match inner.split_once(':') {
        Some((high, low)) => (high.parse::<u32>()?, low.parse::<u32>()?),
        None => {
            let bit = inner.parse::<u32>()?;
            (bit, bit)
        }
    };
    let width = (high - low + 1) as usize;
    let bits = (i >> low) & ((1 << width) - 1);
    Ok(Some(format!("{bits:0width$b}")))
}

fn pattern_values(pattern: &str) -> Vec<u16> {
    let mut values = vec![0u16];
    for bit in pattern.chars() {
        values = match bit {
            '0' => values.iter().map(|v| v << 1).collect(),
            '1' => values.iter().map(|v| (v << 1) | 1).collect(),
            _ => values.iter().flat_map(|v| [v << 1, (v << 1) | 1]).collect(),
        };
    }
    values
}

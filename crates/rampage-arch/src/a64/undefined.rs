//! Encodings the specification's decode tables accept but its decode pseudocode (absent from the open-source
//! release) makes UNDEFINED. Only base-ISA rules that matter for telling code from data are listed.

use std::sync::LazyLock;

use super::Decoded;
use super::spec::ENCODINGS;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    None,
    /// CPY*: destination, source and size registers distinct; only the size may be XZR.
    MemoryCopy,
    /// SET*: destination, size and source registers distinct; the destination is not XZR.
    MemorySet,
    /// CASP and RCWCASP: register pairs start at even registers.
    EvenPairs,
    /// SBFM/BFM/UBFM, EXTR and logical shifted register: 32-bit forms take 5-bit amounts.
    Width32 {
        field: &'static str,
    },
    /// Add/subtract shifted register: ROR is reserved, and 32-bit forms take 5-bit amounts.
    AddSubShift,
    /// Load/store register offset: option<1> must be set.
    RegisterOffset,
}

static RULES: LazyLock<Vec<Rule>> =
    LazyLock::new(|| ENCODINGS.iter().map(|encoding| rule_for(encoding.name)).collect());

fn rule_for(name: &str) -> Rule {
    let group = name.split_once('_').map_or("", |(_, group)| group);
    if group.ends_with("CPY_memcms") {
        Rule::MemoryCopy
    } else if group.ends_with("SET_memcms") || group.ends_with("memset_go") {
        Rule::MemorySet
    } else if group.contains("comswappr") {
        Rule::EvenPairs
    } else if group == "32M_bitfield" || group == "32_extract" {
        Rule::Width32 { field: "imms" }
    } else if group == "32_log_shift" {
        Rule::Width32 { field: "imm6" }
    } else if group.ends_with("addsub_shift") {
        Rule::AddSubShift
    } else if group.ends_with("ldst_regoff") {
        Rule::RegisterOffset
    } else {
        Rule::None
    }
}

pub fn is_undefined(decoded: &Decoded) -> bool {
    let index = (decoded.encoding as *const _ as usize - ENCODINGS.as_ptr() as usize) / size_of_val(&ENCODINGS[0]);
    let field = |name| decoded.field(name).unwrap_or(0);
    match RULES[index] {
        Rule::None => false,
        Rule::MemoryCopy => {
            let (d, s, n) = (field("Rd"), field("Rs"), field("Rn"));
            d == s || d == n || s == n || d == 31 || s == 31
        }
        Rule::MemorySet => {
            let (d, s, n) = (field("Rd"), field("Rs"), field("Rn"));
            d == n || d == s || s == n && s != 31 || d == 31
        }
        Rule::EvenPairs => field("Rs") & 1 == 1 || field("Rt") & 1 == 1,
        Rule::Width32 { field: name } => field(name) >= 32 || field("immr") >= 32,
        Rule::AddSubShift => field("shift") == 3 || field("sf") == 0 && field("imm6") >= 32,
        Rule::RegisterOffset => field("option") & 0b010 == 0,
    }
}

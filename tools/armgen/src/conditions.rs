//! Compiles the specification's condition ASTs into Rust boolean expressions over the instruction word `w`.
//!
//! Feature checks (`IsFeatureImplemented`) are treated as true: a disassembler decodes every extension.

use std::collections::HashMap;
use std::fmt::Write;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::{Scope, pattern_of, str_of};

#[derive(Default)]
pub struct Conditions {
    /// Index 0 is the always-true condition.
    codes: Vec<String>,
    ids: HashMap<String, usize>,
}

enum Expr {
    Bool(String),
    /// An unsigned bit vector of known width.
    Bits(String, u32),
    Int(String),
    /// A bit-pattern literal such as `'01x'`, matched rather than evaluated.
    Pattern(String),
    /// A system operation kind such as `Sys_DC`.
    SysKind(String),
}

impl Conditions {
    pub fn len(&self) -> usize {
        self.codes.len().max(1)
    }

    /// Compiles a decode condition, returning `None` when it is trivially true.
    pub fn compile_decode(&mut self, ast: &Value, scope: &Scope) -> Result<Option<String>> {
        if ast.is_null() {
            return Ok(None);
        }
        match compile(ast, scope)? {
            Expr::Bool(code) if code == "true" => Ok(None),
            Expr::Bool(code) => Ok(Some(code)),
            _ => bail!("condition is not boolean: {ast}"),
        }
    }

    /// Returns the id of the conjunction of `parts`, sharing ids between identical conditions.
    pub fn intern(&mut self, parts: &[String]) -> usize {
        if self.codes.is_empty() {
            self.codes.push("true".to_owned());
            self.ids.insert("true".to_owned(), 0);
        }
        if parts.is_empty() {
            return 0;
        }
        let code = parts.iter().map(|part| format!("({part})")).collect::<Vec<_>>().join(" && ");
        if let Some(&id) = self.ids.get(&code) {
            return id;
        }
        self.codes.push(code.clone());
        self.ids.insert(code, self.codes.len() - 1);
        self.codes.len() - 1
    }

    pub fn emit(&self, out: &mut String) -> std::fmt::Result {
        writeln!(out, "/// Evaluates decode condition `id` against instruction word `w`.")?;
        writeln!(out, "#[allow(clippy::all, unused_parens)]")?;
        writeln!(out, "pub fn condition(id: u16, w: u32, state: State) -> bool {{")?;
        writeln!(out, "    let _ = state;")?;
        writeln!(out, "    let w = w as u64;")?;
        writeln!(out, "    match id {{")?;
        for (id, code) in self.codes.iter().enumerate().skip(1) {
            writeln!(out, "        {id} => {code},")?;
        }
        writeln!(out, "        _ => true,")?;
        writeln!(out, "    }}")?;
        writeln!(out, "}}")
    }
}

fn field_code(scope: &Scope, name: &str) -> Option<Expr> {
    let field = scope.get(name)?;
    let mask = (1u64 << field.width) - 1;
    Some(Expr::Bits(format!("((w >> {}) & {mask:#x})", field.start), field.width))
}

fn compile(ast: &Value, scope: &Scope) -> Result<Expr> {
    match str_of(&ast["_type"]) {
        "AST.Bool" => Ok(Expr::Bool(ast["value"].as_bool().unwrap_or(false).to_string())),
        "AST.Integer" => Ok(Expr::Int(ast["value"].to_string())),
        "Values.Value" => {
            let pattern = pattern_of(ast)?;
            if pattern.contains('x') {
                Ok(Expr::Pattern(pattern))
            } else {
                let value = u64::from_str_radix(&pattern, 2)?;
                Ok(Expr::Bits(format!("{value:#x}"), pattern.len() as u32))
            }
        }
        "AST.Identifier" => {
            let name = str_of(&ast["value"]);
            if let Some(expr) = field_code(scope, name) {
                return Ok(expr);
            }
            if name.starts_with("Sys_") || name.starts_with("Sysl_") {
                return Ok(Expr::SysKind(sys_kind(name)?));
            }
            bail!("unknown identifier {name}")
        }
        "AST.UnaryOp" => match (str_of(&ast["op"]), compile(&ast["expr"], scope)?) {
            ("!", Expr::Bool(code)) => Ok(Expr::Bool(negate(&code))),
            ("NOT", Expr::Bits(code, width)) => {
                Ok(Expr::Bits(format!("(!{code} & {:#x})", (1u64 << width) - 1), width))
            }
            (op, _) => bail!("unsupported unary {op}"),
        },
        "AST.BinaryOp" => binary(ast, scope),
        "AST.SquareOp" => {
            let Expr::Bits(var, _) = compile(&ast["var"], scope)? else { bail!("slice of non-bits") };
            let arguments = ast["arguments"].as_array().map(Vec::as_slice).unwrap_or_default();
            let [index] = arguments else { bail!("unsupported slice {ast}") };
            // A single bit `x[3]`, or a range `x[5:3]`.
            let (high, low) = match str_of(&index["_type"]) {
                "AST.Slice" => (index["left"]["value"].as_u64(), index["right"]["value"].as_u64()),
                _ => (index["value"].as_u64(), index["value"].as_u64()),
            };
            let (Some(high), Some(low)) = (high, low) else {
                // A computed index, such as `registers[UInt(Rn)]`.
                let index = match compile(index, scope)? {
                    Expr::Int(code) | Expr::Bits(code, _) => code,
                    _ => bail!("slice index {index}"),
                };
                return Ok(Expr::Bits(format!("(({var} >> ({index})) & 1)"), 1));
            };
            let width = (high - low + 1) as u32;
            let mask = if width == 1 { "1".to_owned() } else { format!("{:#x}", (1u64 << width) - 1) };
            Ok(Expr::Bits(format!("(({var} >> {low}) & {mask})"), width))
        }
        "AST.Function" => function(ast, scope),
        other => bail!("unsupported AST node {other}: {ast}"),
    }
}

fn negate(code: &str) -> String {
    match code {
        "true" => "false".to_owned(),
        "false" => "true".to_owned(),
        _ => format!("!({code})"),
    }
}

fn pattern_match(code: &str, width: u32, pattern: &str) -> Result<String> {
    if pattern.len() != width as usize {
        bail!("pattern {pattern:?} compared with {width}-bit value");
    }
    let (mut mask, mut value) = (0u64, 0u64);
    for (i, bit) in pattern.chars().enumerate() {
        let position = width as usize - 1 - i;
        match bit {
            '0' => mask |= 1 << position,
            '1' => {
                mask |= 1 << position;
                value |= 1 << position;
            }
            _ => {}
        }
    }
    Ok(format!("(({code} & {mask:#x}) == {value:#x})"))
}

fn binary(ast: &Value, scope: &Scope) -> Result<Expr> {
    let op = str_of(&ast["op"]);
    if op == "IN" {
        let Expr::Bits(code, width) = compile(&ast["left"], scope)? else { bail!("IN on non-bits") };
        let mut alternatives = Vec::new();
        for value in ast["right"]["values"].as_array().into_iter().flatten() {
            alternatives.push(pattern_match(&code, width, &pattern_of(value)?)?);
        }
        return Ok(Expr::Bool(format!("({})", alternatives.join(" || "))));
    }
    let left = compile(&ast["left"], scope)?;
    let right = compile(&ast["right"], scope)?;
    let code = match (op, left, right) {
        ("&&", Expr::Bool(a), Expr::Bool(b)) => match (a.as_str(), b.as_str()) {
            ("true", _) => b,
            (_, "true") => a,
            _ => format!("({a} && {b})"),
        },
        ("||", Expr::Bool(a), Expr::Bool(b)) => {
            if a == "true" || b == "true" {
                "true".to_owned()
            } else {
                format!("({a} || {b})")
            }
        }
        ("==" | "!=", Expr::Bits(code, width), Expr::Pattern(pattern)) => {
            let matched = pattern_match(&code, width, &pattern)?;
            if op == "==" { matched } else { negate(&matched) }
        }
        ("==" | "!=", Expr::SysKind(a), Expr::SysKind(b)) => format!("({a} {op} {b})"),
        ("::", Expr::Bits(a, wa), Expr::Bits(b, wb)) => {
            return Ok(Expr::Bits(format!("(({a} << {wb}) | {b})"), wa + wb));
        }
        ("XOR" | "EOR" | "AND" | "OR", Expr::Bits(a, wa), Expr::Bits(b, wb)) if wa == wb => {
            let operator = match op {
                "AND" => "&",
                "OR" => "|",
                _ => "^",
            };
            return Ok(Expr::Bits(format!("({a} {operator} {b})"), wa));
        }
        ("+", Expr::Int(a), Expr::Int(b)) => return Ok(Expr::Int(format!("({a} + {b})"))),
        ("+" | "-" | "*" | "MOD" | "DIV", a, b)
            if matches!(a, Expr::Int(_) | Expr::Bits(..)) && matches!(b, Expr::Int(_) | Expr::Bits(..)) =>
        {
            let operator = match op {
                "MOD" => "%",
                "DIV" => "/",
                other => other,
            };
            return Ok(Expr::Int(format!("({} {operator} {})", numeric(a)?, numeric(b)?)));
        }
        ("==" | "!=" | "<" | ">" | "<=" | ">=", a, b) => {
            let a = numeric(a)?;
            let b = numeric(b)?;
            format!("({a} {op} {b})")
        }
        (op, _, _) => bail!("unsupported binary {op}: {ast}"),
    };
    Ok(Expr::Bool(code))
}

/// Integers and bit vectors compare as unsigned numbers.
fn numeric(expr: Expr) -> Result<String> {
    match expr {
        Expr::Int(code) | Expr::Bits(code, _) => Ok(format!("({code} as i64)")),
        _ => bail!("comparison of non-numeric values"),
    }
}

fn sys_kind(name: &str) -> Result<String> {
    let kind = name.trim_start_matches("Sysl_").trim_start_matches("Sys_");
    let variant = match kind {
        "AT" => "At",
        "BRB" => "Brb",
        "DC" => "Dc",
        "GIC" => "Gic",
        "GICR" => "Gicr",
        "GSB" => "Gsb",
        "IC" => "Ic",
        "PLBI" => "Plbi",
        "TLBI" => "Tlbi",
        "TLBIP" => "Tlbip",
        other => bail!("unknown system operation kind {other}"),
    };
    Ok(format!("Some(SysKind::{variant})"))
}

fn function(ast: &Value, scope: &Scope) -> Result<Expr> {
    let name = str_of(&ast["name"]);
    let arguments: Vec<&Value> = ast["arguments"].as_array().into_iter().flatten().collect();
    if name == "IsFeatureImplemented" {
        return Ok(Expr::Bool("true".to_owned()));
    }
    if name == "InITBlock" {
        return Ok(Expr::Bool("state.in_it_block".to_owned()));
    }
    let mut compiled = Vec::new();
    for argument in &arguments {
        compiled.push(compile(argument, scope)?);
    }
    let bits = |expr: &Expr| -> Result<(String, u32)> {
        match expr {
            Expr::Bits(code, width) => Ok((code.clone(), *width)),
            _ => bail!("{name} expects bit vectors"),
        }
    };
    let bit_args = || -> Result<Vec<String>> { compiled.iter().map(|e| bits(e).map(|(code, _)| code)).collect() };
    Ok(match name {
        "UInt" => Expr::Int(bits(&compiled[0])?.0),
        "SInt" => {
            let (code, width) = bits(&compiled[0])?;
            Expr::Int(format!("sign_extend({code}, {width})"))
        }
        "T32ExpandImm" => Expr::Bits(format!("t32_expand_imm({})", bits(&compiled[0])?.0), 32),
        // Whether another (shorter) encoding of the instruction can hold this value; aliases that must name
        // their encoding explicitly (MOVW, B.W) are preferred then.
        "A32EncodingExists" | "T32EncodingExists" => {
            let (code, width) = bits(&compiled[0])?;
            let helper = if name == "A32EncodingExists" { "a32_encoding_exists" } else { "t32_encoding_exists" };
            Expr::Bool(format!("{helper}({code}, {width})"))
        }
        "BitCount" => Expr::Int(format!("({}).count_ones()", bits(&compiled[0])?.0)),
        "IsZero" => Expr::Bool(format!("({} == 0)", bits(&compiled[0])?.0)),
        "IsOnes" => {
            let (code, width) = bits(&compiled[0])?;
            Expr::Bool(format!("({code} == {:#x})", (1u64 << width) - 1))
        }
        "MoveWidePreferred" => Expr::Bool(format!("move_wide_preferred({})", bit_args()?.join(", "))),
        "BFXPreferred" => Expr::Bool(format!("bfx_preferred({})", bit_args()?.join(", "))),
        "SVEMoveMaskPreferred" => Expr::Bool(format!("sve_move_mask_preferred({})", bit_args()?.join(", "))),
        "SysOp" => Expr::SysKind(format!("sys_op({})", bit_args()?.join(", "))),
        "SysOp128" => Expr::SysKind(format!("sys_op128({})", bit_args()?.join(", "))),
        "SysLOp" => Expr::SysKind(format!("sysl_op({})", bit_args()?.join(", "))),
        other => bail!("unsupported function {other}"),
    })
}

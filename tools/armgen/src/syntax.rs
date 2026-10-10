//! Flattens the assembly grammar of an instruction into a token tree that a disassembler can render: literal
//! text, operands (the grammar's displayed placeholders such as `<Xd|SP>`), optional groups and alternatives.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use crate::{Field, str_of};

#[derive(Clone, PartialEq, Debug)]
enum Token {
    Text(String),
    Operand(usize),
    Optional(Vec<Token>),
    Choice(Vec<Vec<Token>>),
}

struct Operand {
    name: String,
    fields: Vec<usize>,
    choices: Vec<String>,
}

struct Flattener<'a> {
    rules: &'a Map<String, Value>,
    encoded_in: BTreeMap<String, Vec<String>>,
    fields: &'a [Field],
    operands: Vec<Operand>,
    /// Rules being expanded, to reject recursive grammar.
    active: Vec<String>,
    /// How many displayed operands are being expanded.
    displays: usize,
}

/// Returns Rust source for a `Syntax` value describing the assembly syntax of `node`.
pub fn emit(rules: &Map<String, Value>, node: &Value, fields: &[Field]) -> Result<String> {
    let mut encoded_in = BTreeMap::new();
    if let Some(map) = node["_meta"]["encoded_in"].as_object() {
        for (placeholder, sources) in map {
            // Usually plain field names; T32 branch offsets also compute bits (`NOT(J1 EOR S)`), so take every
            // identifier inside, once.
            let mut names = Vec::new();
            for source in sources.as_array().into_iter().flatten() {
                identifiers(source, &mut names);
            }
            encoded_in.insert(placeholder.clone(), names);
        }
    }
    let mut flattener = Flattener { rules, encoded_in, fields, operands: Vec::new(), active: Vec::new(), displays: 0 };
    let symbols = node["assembly"]["symbols"].as_array().context("assembly symbols")?;
    let tokens = flattener.symbols(symbols)?;
    let operands: Vec<String> = flattener
        .operands
        .iter()
        .map(|operand| format!("op({:?}, &{:?}, &{:?})", operand.name, operand.fields, operand.choices))
        .collect();
    Ok(format!("syn({}, &[{}])", tokens_code(&tokens), operands.join(", ")))
}

/// The identifiers in an expression, in order, without repeats.
fn identifiers(ast: &Value, names: &mut Vec<String>) {
    match ast {
        Value::Object(map) if map.get("_type").and_then(Value::as_str) == Some("AST.Identifier") => {
            let name = str_of(&ast["value"]).to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Value::Object(map) => map.values().for_each(|value| identifiers(value, names)),
        Value::Array(items) => items.iter().for_each(|item| identifiers(item, names)),
        _ => {}
    }
}

fn tokens_code(tokens: &[Token]) -> String {
    let parts: Vec<String> = tokens
        .iter()
        .map(|token| match token {
            Token::Text(text) => format!("T({text:?})"),
            Token::Operand(index) => format!("O({index})"),
            Token::Optional(inner) => format!("Opt({})", tokens_code(inner)),
            Token::Choice(alternatives) => {
                let alternatives: Vec<String> = alternatives.iter().map(|a| tokens_code(a)).collect();
                format!("Alt(&[{}])", alternatives.join(", "))
            }
        })
        .collect();
    format!("&[{}]", parts.join(", "))
}

fn push(tokens: &mut Vec<Token>, token: Token) {
    if let (Some(Token::Text(previous)), Token::Text(text)) = (tokens.last_mut(), &token) {
        previous.push_str(text);
        return;
    }
    tokens.push(token);
}

/// Plain text of a token sequence, with operands shown by name; used to list an operand's legal values.
fn plain(tokens: &[Token], operands: &[Operand]) -> String {
    let mut text = String::new();
    for token in tokens {
        match token {
            Token::Text(t) => text.push_str(t),
            Token::Operand(index) => text.push_str(&operands[*index].name),
            Token::Optional(inner) => {
                text.push('[');
                text.push_str(&plain(inner, operands));
                text.push(']');
            }
            Token::Choice(alternatives) => {
                let alternatives: Vec<String> = alternatives.iter().map(|a| plain(a, operands)).collect();
                text.push_str(&alternatives.join("|"));
            }
        }
    }
    text
}

impl Flattener<'_> {
    fn symbols(&mut self, symbols: &[Value]) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        for symbol in symbols {
            for token in self.symbol(symbol)? {
                push(&mut tokens, token);
            }
        }
        Ok(tokens)
    }

    fn assembly(&mut self, assembly: &Value) -> Result<Vec<Token>> {
        match assembly["symbols"].as_array() {
            Some(symbols) => self.symbols(symbols),
            None => Ok(Vec::new()),
        }
    }

    fn operand(&mut self, name: &str, choices: Vec<String>) -> Result<Token> {
        if let Some(index) = self.operands.iter().position(|operand| operand.name == name) {
            return Ok(Token::Operand(index));
        }
        let mut fields = Vec::new();
        for field_name in self.encoded_in.get(name).into_iter().flatten() {
            let index = self
                .fields
                .iter()
                .position(|field| &field.name == field_name)
                .with_context(|| format!("operand {name} is encoded in unknown field {field_name}"))?;
            fields.push(index);
        }
        self.operands.push(Operand { name: name.to_owned(), fields, choices });
        Ok(Token::Operand(self.operands.len() - 1))
    }

    fn symbol(&mut self, symbol: &Value) -> Result<Vec<Token>> {
        match str_of(&symbol["_type"]) {
            "Instruction.Symbols.Literal" => Ok(vec![Token::Text(str_of(&symbol["value"]).to_owned())]),
            "Instruction.Symbols.RuleReference" => self.rule(str_of(&symbol["rule_id"])),
            other => bail!("unexpected symbol type {other}"),
        }
    }

    fn rule(&mut self, id: &str) -> Result<Vec<Token>> {
        if self.active.iter().any(|active| active == id) {
            // Recursive rules (SME tile lists) only occur inside displayed operands, whose expansion merely
            // documents their legal values.
            if self.displays == 0 {
                bail!("recursive assembly rule {id} (via {})", self.active.join(" > "));
            }
            return Ok(vec![Token::Text("...".to_owned())]);
        }
        self.active.push(id.to_owned());
        let result = self.expand_rule(id);
        self.active.pop();
        result
    }

    fn expand_rule(&mut self, id: &str) -> Result<Vec<Token>> {
        let rule = self.rules.get(id).with_context(|| format!("unknown rule {id}"))?;
        let display = rule["display"].as_str();
        match str_of(&rule["_type"]) {
            "Instruction.Rules.Token" => match rule["default"].as_str() {
                // Assemblers accept any whitespace; a single space reads best.
                Some(text) if text.trim().is_empty() => Ok(vec![Token::Text(" ".to_owned())]),
                Some(text) => Ok(vec![Token::Text(text.to_owned())]),
                None => Ok(vec![self.operand(&format!("<{id}>"), Vec::new())?]),
            },
            _ if display == Some("#") => Ok(vec![Token::Text("#".to_owned())]),
            "Instruction.Rules.Rule" => {
                if let Some(name) = display {
                    return Ok(vec![self.operand(name, Vec::new())?]);
                }
                if rule["symbols"].is_null() {
                    return Ok(Vec::new());
                }
                self.assembly(&rule["symbols"])
            }
            "Instruction.Rules.Choice" => {
                let operand_count = self.operands.len();
                let mut alternatives = Vec::new();
                let mut has_empty = false;
                self.displays += usize::from(display.is_some());
                for choice in rule["choices"].as_array().into_iter().flatten() {
                    let tokens = if choice.is_null() { Vec::new() } else { self.assembly(choice)? };
                    if tokens.is_empty() {
                        has_empty = true;
                    } else if !alternatives.contains(&tokens) {
                        alternatives.push(tokens);
                    }
                }
                self.displays -= usize::from(display.is_some());
                if let Some(name) = display {
                    // The operand stands for the whole choice; its alternatives document the legal values.
                    // Flattening them may have registered nested operands, which are discarded again.
                    let choices = alternatives.iter().map(|a| plain(a, &self.operands)).collect();
                    self.operands.truncate(operand_count);
                    let operand = self.operand(name, choices)?;
                    return Ok(vec![operand]);
                }
                let body = match alternatives.len() {
                    0 => return Ok(Vec::new()),
                    1 => alternatives.pop().unwrap_or_default(),
                    _ => vec![Token::Choice(alternatives)],
                };
                // An optional `#` before an immediate (`{#}<imm>`) is always printed, as LLVM does.
                if has_empty && body == [Token::Text("#".to_owned())] {
                    return Ok(body);
                }
                Ok(if has_empty { vec![Token::Optional(body)] } else { body })
            }
            other => bail!("unexpected rule type {other}"),
        }
    }
}

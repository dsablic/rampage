//! Integer expressions a `computes` claim states a function's result as (`x*3+1`), evaluated at a fixed bit width.
//!
//! C operators with C precedence (`* / % + - << >> < <= > >= == != & ^ | && ||`, unary `- ~ !`, parentheses),
//! decimal and 0x literals, and functions for what C spells with signed types: `sdiv srem sar slt sle sgt sge smin
//! smax`, and `min max rotl rotr ite(c, a, b)`. Arithmetic wraps at the width; `/ % >> < <= > >=` are unsigned. An
//! input that makes the expression undefined in C (division by zero, a shift by the width or more, signed overflow of
//! `sdiv`) is not a sample.

use std::collections::BTreeSet;

const MAX_LENGTH: usize = 512;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Number(u64),
    Variable(usize),
    Unary(char, Box<Node>),
    Binary(&'static str, Box<Node>, Box<Node>),
    Call(&'static str, Vec<Node>),
}

/// Why an expression has no value for one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Undefined;

#[derive(Debug, Clone)]
pub(crate) struct Expression {
    root: Node,
    /// Variable names, by the index [`Node::Variable`] holds.
    pub names: Vec<String>,
}

const FUNCTIONS: [(&str, usize); 13] = [
    ("sdiv", 2),
    ("srem", 2),
    ("sar", 2),
    ("slt", 2),
    ("sle", 2),
    ("sgt", 2),
    ("sge", 2),
    ("smin", 2),
    ("smax", 2),
    ("min", 2),
    ("max", 2),
    ("rotl", 2),
    ("rotr", 2),
];

/// Binary operators by precedence level, loosest first.
const LEVELS: [&[&str]; 10] = [
    &["||"],
    &["&&"],
    &["|"],
    &["^"],
    &["&"],
    &["==", "!="],
    &["<=", ">=", "<", ">"],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/", "%"],
];

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    names: Vec<String>,
    depth: usize,
}

impl Parser<'_> {
    fn skip(&mut self) {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip();
        if self.text[self.at..].starts_with(token.as_bytes()) {
            // `<` is not the start of `<<` or `<=`, nor `&` of `&&`.
            let next = self.text.get(self.at + token.len()).copied();
            let longer = matches!(
                (token, next),
                ("<" | ">", Some(b'<' | b'>' | b'=')) | ("&", Some(b'&')) | ("|", Some(b'|')) | ("!", Some(b'='))
            );
            if !longer {
                self.at += token.len();
                return true;
            }
        }
        false
    }

    fn error(&self, what: &str) -> String {
        format!("expression: {what} at character {}", self.at + 1)
    }

    fn binary(&mut self, level: usize) -> Result<Node, String> {
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        'outer: loop {
            for &operator in LEVELS[level] {
                if self.eat(operator) {
                    let right = self.binary(level + 1)?;
                    left = Node::Binary(operator, Box::new(left), Box::new(right));
                    continue 'outer;
                }
            }
            return Ok(left);
        }
    }

    fn unary(&mut self) -> Result<Node, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.error("nesting too deep"));
        }
        let node = if self.eat("-") {
            Node::Unary('-', Box::new(self.unary()?))
        } else if self.eat("~") {
            Node::Unary('~', Box::new(self.unary()?))
        } else if self.eat("!") {
            Node::Unary('!', Box::new(self.unary()?))
        } else {
            self.primary()?
        };
        self.depth -= 1;
        Ok(node)
    }

    fn primary(&mut self) -> Result<Node, String> {
        self.skip();
        if self.eat("(") {
            let node = self.binary(0)?;
            if !self.eat(")") {
                return Err(self.error("expected )"));
            }
            return Ok(node);
        }
        let start = self.at;
        while self.text.get(self.at).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_') {
            self.at += 1;
        }
        let word = std::str::from_utf8(&self.text[start..self.at]).expect("ASCII");
        if word.is_empty() {
            return Err(self.error("expected a number, name or ("));
        }
        if word.as_bytes()[0].is_ascii_digit() {
            let clean = word.replace('_', "");
            let value = match clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => clean.parse(),
            };
            return value.map(Node::Number).map_err(|_| self.error(&format!("bad number {word:?}")));
        }
        if word == "ite" || FUNCTIONS.iter().any(|(name, _)| *name == word) {
            let (name, arity) =
                FUNCTIONS.iter().copied().chain([("ite", 3)]).find(|(name, _)| *name == word).expect("listed");
            if !self.eat("(") {
                return Err(self.error(&format!("{name} takes ({arity} arguments)")));
            }
            let mut arguments = vec![self.binary(0)?];
            while self.eat(",") {
                arguments.push(self.binary(0)?);
            }
            if !self.eat(")") || arguments.len() != arity {
                return Err(self.error(&format!("{name} takes {arity} arguments")));
            }
            return Ok(Node::Call(name, arguments));
        }
        let index = match self.names.iter().position(|name| name == word) {
            Some(index) => index,
            None => {
                self.names.push(word.to_owned());
                self.names.len() - 1
            }
        };
        Ok(Node::Variable(index))
    }
}

impl Expression {
    /// Parses `text`. Its variables are bound to arguments by `params` when given; otherwise in the order `arg0, arg1,
    /// ...` names them, or else alphabetically.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_LENGTH || !text.is_ascii() {
            return Err(format!("an expression is at most {MAX_LENGTH} ASCII characters"));
        }
        let mut parser = Parser { text: text.as_bytes(), at: 0, names: Vec::new(), depth: 0 };
        let root = parser.binary(0)?;
        parser.skip();
        if parser.at != text.len() {
            return Err(parser.error("unexpected text"));
        }
        Ok(Self { root, names: parser.names })
    }

    /// The variables' names in default argument order.
    pub fn default_order(&self) -> Vec<String> {
        let numbered = |name: &str| name.strip_prefix("arg").and_then(|digits| digits.parse::<usize>().ok());
        let mut names: Vec<String> = self.names.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
        if names.iter().all(|name| numbered(name).is_some()) {
            names.sort_by_key(|name| numbered(name));
        }
        names
    }

    /// The value for `values` (by variable index) at `bits` (8..=64).
    pub fn evaluate(&self, values: &[u64], bits: u32) -> Result<u64, Undefined> {
        let mask = if bits == 64 { u64::MAX } else { (1 << bits) - 1 };
        let signed = |value: u64| -> i64 {
            let shift = 64 - bits;
            ((value << shift) as i64) >> shift
        };
        fn walk(
            node: &Node,
            values: &[u64],
            bits: u32,
            mask: u64,
            signed: &dyn Fn(u64) -> i64,
        ) -> Result<u64, Undefined> {
            let go = |node: &Node| walk(node, values, bits, mask, signed);
            let value = match node {
                Node::Number(value) => *value,
                Node::Variable(index) => values.get(*index).copied().ok_or(Undefined)?,
                Node::Unary(operator, inner) => {
                    let inner = go(inner)?;
                    match operator {
                        '-' => inner.wrapping_neg(),
                        '~' => !inner,
                        _ => u64::from(inner & mask == 0),
                    }
                }
                Node::Binary(operator, left, right) => {
                    let (a, b) = (go(left)? & mask, go(right)? & mask);
                    match *operator {
                        "+" => a.wrapping_add(b),
                        "-" => a.wrapping_sub(b),
                        "*" => a.wrapping_mul(b),
                        "/" => a.checked_div(b).ok_or(Undefined)?,
                        "%" => a.checked_rem(b).ok_or(Undefined)?,
                        "<<" if b >= u64::from(bits) => return Err(Undefined),
                        "<<" => a << b,
                        ">>" if b >= u64::from(bits) => return Err(Undefined),
                        ">>" => a >> b,
                        "&" => a & b,
                        "|" => a | b,
                        "^" => a ^ b,
                        "<" => u64::from(a < b),
                        "<=" => u64::from(a <= b),
                        ">" => u64::from(a > b),
                        ">=" => u64::from(a >= b),
                        "==" => u64::from(a == b),
                        "!=" => u64::from(a != b),
                        "&&" => u64::from(a != 0 && b != 0),
                        _ => u64::from(a != 0 || b != 0),
                    }
                }
                Node::Call(name, arguments) => {
                    let values: Vec<u64> =
                        arguments.iter().map(|node| go(node).map(|value| value & mask)).collect::<Result<_, _>>()?;
                    let (a, b) = (values[0], values.get(1).copied().unwrap_or(0));
                    let (sa, sb) = (signed(a), signed(b));
                    let minimum = signed(1u64 << (bits - 1));
                    match *name {
                        "sdiv" if b == 0 || (sa == minimum && sb == -1) => return Err(Undefined),
                        "sdiv" => sa.wrapping_div(sb) as u64,
                        "srem" if b == 0 || (sa == minimum && sb == -1) => return Err(Undefined),
                        "srem" => sa.wrapping_rem(sb) as u64,
                        "sar" if b >= u64::from(bits) => return Err(Undefined),
                        "sar" => (sa >> b) as u64,
                        "slt" => u64::from(sa < sb),
                        "sle" => u64::from(sa <= sb),
                        "sgt" => u64::from(sa > sb),
                        "sge" => u64::from(sa >= sb),
                        "smin" => sa.min(sb) as u64,
                        "smax" => sa.max(sb) as u64,
                        "min" => a.min(b),
                        "max" => a.max(b),
                        "rotl" | "rotr" => {
                            let count = (b % u64::from(bits)) as u32;
                            if count == 0 {
                                a
                            } else if *name == "rotl" {
                                (a << count) | (a >> (bits - count))
                            } else {
                                (a >> count) | (a << (bits - count))
                            }
                        }
                        _ => {
                            if a != 0 {
                                b
                            } else {
                                values[2]
                            }
                        }
                    }
                }
            };
            Ok(value & mask)
        }
        walk(&self.root, values, bits, mask, &signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str, values: &[u64], bits: u32) -> Result<u64, Undefined> {
        Expression::parse(text).unwrap().evaluate(values, bits)
    }

    #[test]
    fn precedence_and_wrapping_follow_c() {
        assert_eq!(value("x*3+1", &[5], 32), Ok(16));
        assert_eq!(value("1 + 2 * 3 << 1", &[], 32), Ok(14));
        assert_eq!(value("a*3+b-c", &[0xffff_ffff, 2, 1], 32), Ok(0xffff_fffe));
        assert_eq!(value("-x", &[1], 16), Ok(0xffff));
        assert_eq!(value("~0 >> 28", &[], 32), Ok(0xf));
        assert_eq!(value("x < 3 && x != 0", &[2], 32), Ok(1));
        assert_eq!(value("x & 3 == 3", &[1], 32), Ok(1), "== binds tighter than &, as in C");
        assert_eq!(value("(x & 3) == 3", &[1], 32), Ok(0));
    }

    #[test]
    fn signed_functions_use_the_width() {
        assert_eq!(value("sdiv(x, 2)", &[0xffff_fffd], 32), Ok(0xffff_ffff));
        assert_eq!(value("x / 2", &[0xffff_fffd], 32), Ok(0x7fff_fffe));
        assert_eq!(value("sar(x, 4)", &[0x8000_0000], 32), Ok(0xf800_0000));
        assert_eq!(value("slt(x, 0)", &[0x80], 8), Ok(1));
        assert_eq!(value("rotl(x, 8)", &[0x1234_5678], 32), Ok(0x3456_7812));
        assert_eq!(value("ite(x > 1, 10, 20)", &[0], 32), Ok(20));
    }

    #[test]
    fn undefined_inputs_are_not_samples() {
        assert_eq!(value("x / y", &[1, 0], 32), Err(Undefined));
        assert_eq!(value("x << y", &[1, 32], 32), Err(Undefined));
        assert_eq!(value("sdiv(x, y)", &[0x8000_0000, 0xffff_ffff], 32), Err(Undefined));
    }

    #[test]
    fn parsing_reports_errors_and_variable_order() {
        assert!(Expression::parse("x +").is_err());
        assert!(Expression::parse("f(x)").is_err(), "an unknown name is a variable, not a call");
        assert!(Expression::parse("min(x)").is_err());
        assert!(Expression::parse("(((x").is_err());
        assert_eq!(Expression::parse("y * x + x").unwrap().default_order(), vec!["x", "y"]);
        assert_eq!(Expression::parse("arg10 + arg2").unwrap().default_order(), vec!["arg2", "arg10"]);
    }
}

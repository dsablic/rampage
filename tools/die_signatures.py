#!/usr/bin/env python3
"""Convert Detect It Easy (DIE) detection scripts into rampage-detect's bundled data file.

Usage, from the repository root, with a checkout of https://github.com/horsicq/Detect-It-Easy at PINNED_COMMIT:

    python3 -I tools/die_signatures.py /path/to/Detect-It-Easy [--report report.txt]

DIE signatures are small JavaScript programs (`db/<FileType>/*.sg`). This converter never runs them: it parses the
common subset (a `meta(type, name)` header and a `detect()` function made of `if`/`else` chains, assignments and
`return result()`) and evaluates it symbolically. Every way through `detect()` that ends with `bDetected` true becomes
one rampage signature: the conjunction of the conditions on that way. Only conditions rampage-detect can test exactly
are converted (entry-point and file/overlay byte patterns, section names, imported libraries and functions, exports,
overlay presence). A script, or a way through it, that needs anything else is skipped and counted in the report: a
converted signature is never broader than DIE's own condition.

`else` branches are converted without the negation of the conditions they skip only when that is exact: when every
way through the skipped `then` branch also ends in a detection of the same tool, any image that satisfies the dropped
condition is detected by DIE anyway. Otherwise the branch is skipped.

The output is deterministic: scripts are read in sorted order and the JSON is written with sorted keys.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PINNED_COMMIT = "7eaa31a972932113aa982cc0ebfa3352a1cd07fe"
SOURCE_URL = "https://github.com/horsicq/Detect-It-Easy"
OUTPUT = Path(__file__).resolve().parents[1] / "crates/rampage-detect/data/die-signatures.json"

# DIE file-type directories rampage loads, and the container format each one pins.
FILE_TYPES = {"PE": "pe", "ELF": "elf", "MACH": "macho"}
# DIE's script prefixes that name the current file's class.
CLASS_ALIASES = {"PE": {"PE", "X", "File"}, "ELF": {"ELF", "X", "File"}, "MACH": {"MACH", "X", "File"}}
# DIE detection types converted, and the rampage-detect kind each maps to. Library, tool, game-engine, format and
# similar types describe content rather than the tool that produced the image, so they stay out.
KINDS = {
    "packer": "packer",
    "protector": "protector",
    "protection": "protector",
    "cryptor": "cryptor",
    "compiler": "compiler",
    "linker": "linker",
    "installer": "installer",
    "sfx": "sfx",
    "joiner": "joiner",
}
# Variables that only describe a detection (version, options, language) and never decide it.
DESCRIPTIVE = {"sVersion", "sOptions", "sLang", "sLangVersion"}
# Calls that only log.
INERT_CALLS = {"_log", "_debug", "_warn", "_error"}
MAX_PATHS = 4096
# Scripts whose converted signatures matched clean binaries in the false-positive sweep (tests/fixtures, macOS
# system and Homebrew binaries): dropped whole, with the reason in the report.
EXCLUDED = {
    "MACH/compiler_Rust.4.sg": "false positives: its entry patterns are generic C prologues (matched coreutils)",
}
UNKNOWN = object()


class Unsupported(Exception):
    """A script, or a condition in it, that the converter cannot express exactly."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------------------------------------------
# Tokenizer and parser for the JavaScript subset DIE scripts use.

PUNCTUATION = sorted(
    ["===", "!==", "==", "!=", "&&", "||", "<=", ">=", "+=", "-=", "|=", "&=", "++", "--",
     "(", ")", "{", "}", "[", "]", ";", ",", "=", "!", "<", ">", "+", "-", "*", "/", "%", ".", "?", ":", "&", "|",
     "^", "~"],
    key=len,
    reverse=True,
)
REGEX_PREFIX = {"(", ",", "=", "!", "&&", "||", "return", "?", ":", "[", "{", ";", "==", "!=", "===", "!=="}


@dataclass
class Token:
    kind: str  # "id", "str", "num", "punct", "regex"
    value: Any


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise Unsupported("unterminated comment")
            i = end + 2
        elif c in "\"'`":
            if c == "`":
                raise Unsupported("template literal")
            j = i + 1
            out = []
            while j < n and text[j] != c:
                if text[j] == "\\":
                    if j + 1 >= n:
                        raise Unsupported("unterminated string")
                    escape = text[j + 1]
                    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"', "/": "/"}
                    if escape not in simple:
                        raise Unsupported("string escape")
                    out.append(simple[escape])
                    j += 2
                else:
                    out.append(text[j])
                    j += 1
            if j >= n:
                raise Unsupported("unterminated string")
            tokens.append(Token("str", "".join(out)))
            i = j + 1
        elif c == "/" and (not tokens or (tokens[-1].kind == "punct" and tokens[-1].value in REGEX_PREFIX)
                           or (tokens[-1].kind == "id" and tokens[-1].value == "return")):
            j = i + 1
            in_class = False
            while j < n and (text[j] != "/" or in_class):
                if text[j] == "\\":
                    j += 1
                elif text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                elif text[j] == "\n":
                    raise Unsupported("unterminated regex")
                j += 1
            j += 1
            while j < n and text[j].isalpha():
                j += 1
            tokens.append(Token("regex", text[i:j]))
            i = j
        elif c.isdigit():
            match = re.match(r"0[xX][0-9a-fA-F]+|\d+(\.\d+)?", text[i:])
            assert match
            literal = match.group(0)
            tokens.append(Token("num", int(literal, 16) if literal[:2].lower() == "0x" else float(literal)))
            i += len(literal)
        elif c.isalpha() or c in "_$":
            match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", text[i:])
            assert match
            tokens.append(Token("id", match.group(0)))
            i += len(match.group(0))
        else:
            for punct in PUNCTUATION:
                if text.startswith(punct, i):
                    tokens.append(Token("punct", punct))
                    i += len(punct)
                    break
            else:
                raise Unsupported(f"unexpected character {c!r}")
    return tokens


class Parser:
    """A recursive-descent parser producing tuples: statements ("if", cond, then, else), ("block", [..]),
    ("assign", name, op, expr), ("return", expr), ("expr", expr), ("var", [(name, expr)]), ("loop",) and
    ("function", name, params, body); expressions ("call", callee, args), ("member", obj, name), ("id", name),
    ("str", s), ("num", n), ("bool", b), ("regex", r), ("unary", op, e), ("binary", op, a, b)."""

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset: int = 0) -> Token | None:
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def at(self, value: str, kind: str = "punct") -> bool:
        token = self.peek()
        return token is not None and token.kind == kind and token.value == value

    def take(self, value: str, kind: str = "punct") -> Token:
        token = self.peek()
        if token is None or token.kind != kind or token.value != value:
            raise Unsupported(f"syntax: expected {value!r}")
        self.pos += 1
        return token

    def program(self) -> list[Any]:
        statements = []
        while self.peek() is not None:
            statements.append(self.statement())
        return statements

    def block(self) -> list[Any]:
        self.take("{")
        statements = []
        while not self.at("}"):
            if self.peek() is None:
                raise Unsupported("syntax: unterminated block")
            statements.append(self.statement())
        self.take("}")
        return statements

    def statement(self) -> Any:
        token = self.peek()
        assert token is not None
        if token.kind == "punct" and token.value == "{":
            return ("block", self.block())
        if token.kind == "punct" and token.value == ";":
            self.pos += 1
            return ("block", [])
        if token.kind == "id":
            if token.value == "function":
                self.pos += 1
                name = self.peek()
                if name is None or name.kind != "id":
                    raise Unsupported("anonymous function")
                self.pos += 1
                self.take("(")
                params = []
                while not self.at(")"):
                    param = self.peek()
                    if param is None or param.kind != "id":
                        raise Unsupported("syntax: parameter")
                    params.append(param.value)
                    self.pos += 1
                    if self.at(","):
                        self.pos += 1
                self.take(")")
                return ("function", name.value, params, self.block())
            if token.value == "if":
                self.pos += 1
                self.take("(")
                cond = self.expression()
                self.take(")")
                then = self.statement()
                other = None
                if self.at("else", "id"):
                    self.pos += 1
                    other = self.statement()
                return ("if", cond, then, other)
            if token.value in ("for", "while", "do", "switch", "try"):
                raise Unsupported(f"{token.value} statement")
            if token.value == "return":
                self.pos += 1
                expr = None if self.at(";") or self.at("}") else self.expression()
                self.semicolon()
                return ("return", expr)
            if token.value in ("var", "let", "const"):
                self.pos += 1
                decls = []
                while True:
                    name = self.peek()
                    if name is None or name.kind != "id":
                        raise Unsupported("syntax: declaration")
                    self.pos += 1
                    value = None
                    if self.at("="):
                        self.pos += 1
                        value = self.assignment_expression()
                    decls.append((name.value, value))
                    if not self.at(","):
                        break
                    self.pos += 1
                self.semicolon()
                return ("var", decls)
            follower = self.peek(1)
            if follower is not None and follower.kind == "punct" and follower.value in ("=", "+=", "-=", "|=", "&="):
                self.pos += 2
                value = self.assignment_expression()
                self.semicolon()
                return ("assign", token.value, follower.value, value)
        expr = self.expression()
        self.semicolon()
        return ("expr", expr)

    def semicolon(self) -> None:
        if self.at(";"):
            self.pos += 1

    def assignment_expression(self) -> Any:
        expr = self.expression()
        if self.at("="):
            raise Unsupported("chained assignment")
        return expr

    def expression(self) -> Any:
        cond = self.binary(0)
        if self.at("?"):
            self.pos += 1
            then = self.expression()
            self.take(":")
            other = self.expression()
            return ("ternary", cond, then, other)
        return cond

    LEVELS = [["||"], ["&&"], ["|"], ["^"], ["&"], ["==", "!=", "===", "!=="], ["<", ">", "<=", ">="],
              ["+", "-"], ["*", "/", "%"]]

    def binary(self, level: int) -> Any:
        if level == len(self.LEVELS):
            return self.unary()
        left = self.binary(level + 1)
        while True:
            token = self.peek()
            if token is not None and token.kind == "punct" and token.value in self.LEVELS[level]:
                self.pos += 1
                right = self.binary(level + 1)
                left = ("binary", token.value, left, right)
            elif token is not None and token.kind == "id" and token.value in ("in", "instanceof") and level == 6:
                raise Unsupported(f"{token.value} operator")
            else:
                return left

    def unary(self) -> Any:
        token = self.peek()
        if token is not None and token.kind == "punct" and token.value in ("!", "-", "+", "~"):
            self.pos += 1
            return ("unary", token.value, self.unary())
        if token is not None and token.kind == "punct" and token.value in ("++", "--"):
            raise Unsupported("increment")
        if token is not None and token.kind == "id" and token.value in ("typeof", "new", "delete", "void"):
            raise Unsupported(f"{token.value} operator")
        return self.postfix()

    def postfix(self) -> Any:
        expr = self.primary()
        while True:
            if self.at("("):
                self.pos += 1
                args = []
                while not self.at(")"):
                    args.append(self.expression())
                    if self.at(","):
                        self.pos += 1
                    elif not self.at(")"):
                        raise Unsupported("syntax: arguments")
                self.take(")")
                expr = ("call", expr, args)
            elif self.at("."):
                self.pos += 1
                name = self.peek()
                if name is None or name.kind != "id":
                    raise Unsupported("syntax: member")
                self.pos += 1
                expr = ("member", expr, name.value)
            elif self.at("["):
                self.pos += 1
                index = self.expression()
                self.take("]")
                expr = ("index", expr, index)
            elif self.at("++") or self.at("--"):
                raise Unsupported("increment")
            else:
                return expr

    def primary(self) -> Any:
        token = self.peek()
        if token is None:
            raise Unsupported("syntax: unexpected end")
        self.pos += 1
        if token.kind == "str":
            return ("str", token.value)
        if token.kind == "num":
            return ("num", token.value)
        if token.kind == "regex":
            return ("regex", token.value)
        if token.kind == "id":
            if token.value in ("true", "false"):
                return ("bool", token.value == "true")
            if token.value == "function":
                raise Unsupported("function expression")
            return ("id", token.value)
        if token.value == "(":
            expr = self.expression()
            self.take(")")
            return expr
        if token.value == "[":
            raise Unsupported("array literal")
        if token.value == "{":
            raise Unsupported("object literal")
        raise Unsupported(f"syntax: unexpected {token.value!r}")


# ---------------------------------------------------------------------------------------------------------------
# DIE signature strings.

def convert_pattern(signature: str, jumps: bool = False, skip: int = 0) -> str:
    """A DIE byte signature as rampage hex: `..` and `??` become `??`, `'text'` becomes its bytes, and hex digits
    and `?` nibbles pass through. With `jumps`, a relative jump (`$$`, `$$$$`, `$$$$$$$$`) becomes a `$1`, `$2` or
    `$4` token that rampage-detect follows as DIE does; `skip` leading bytes are matched as wildcards (a compare at
    an offset). Address (`#`), conditional (`*`, `!`, `_`) and delta (`+`, `-`, `%`) forms have no exact rampage
    equivalent, so they make the signature unsupported."""
    nibbles: list[str] = ["?"] * (2 * skip)
    i = 0
    while i < len(signature):
        c = signature[i]
        if c == "$" and jumps:
            run = len(signature) - i - len(signature[i:].lstrip("$"))
            if run not in (2, 4, 8):
                raise Unsupported("pattern: relative jump of unsupported size")
            if len("".join(nibbles).rsplit(" ", 1)[-1]) % 2:
                raise Unsupported("pattern: odd nibbles")
            nibbles.append(f" ${run // 2} ")
            i += run
        elif c == "'":
            end = signature.find("'", i + 1)
            if end < 0:
                raise Unsupported("pattern: unterminated text")
            text = signature[i + 1:end]
            try:
                data = text.encode("ascii")
            except UnicodeEncodeError as error:
                raise Unsupported("pattern: non-ASCII text") from error
            nibbles.extend(f"{byte:02X}" for byte in data)
            i = end + 1
        elif c == ".":
            nibbles.append("?")
            i += 1
        elif c in "0123456789abcdefABCDEF?":
            nibbles.append(c.upper())
            i += 1
        elif c.isspace():
            i += 1
        elif c == "$":
            raise Unsupported("pattern: relative jump ($)")
        elif c == "#":
            raise Unsupported("pattern: absolute address (#)")
        else:
            raise Unsupported(f"pattern: special symbol ({c})")
    pieces = "".join(nibbles).split(" ")
    out = []
    for piece in pieces:
        if piece.startswith("$"):
            out.append(piece)
            continue
        if len(piece) % 2:
            raise Unsupported("pattern: odd nibbles")
        out.extend(piece[k:k + 2] for k in range(0, len(piece), 2))
    fixed = [token for token in out if not token.startswith("$") and token != "??"]
    if not out:
        raise Unsupported("pattern: empty")
    if not fixed:
        raise Unsupported("pattern: all wildcards")
    return " ".join(out)


# ---------------------------------------------------------------------------------------------------------------
# Symbolic evaluation.

@dataclass(frozen=True)
class Atom:
    """One exactly-convertible condition, as it appears in the data file."""

    kind: str
    args: tuple[Any, ...]

    def to_json(self) -> dict[str, Any]:
        if self.kind == "ep":
            return {"entry": self.args[0]}
        if self.kind == "section":
            return {"section": self.args[0]}
        if self.kind == "library":
            return {"library": self.args[0]}
        if self.kind == "import":
            library, name = self.args
            return {"import": name} if library is None else {"import": name, "from": library}
        if self.kind == "export":
            return {"export": self.args[0]}
        if self.kind == "overlay":
            return {"overlay": True}
        if self.kind == "overlay_at":
            return {"overlay_bytes": self.args[0]}
        if self.kind == "file_at":
            return {"file_bytes": self.args[1], "offset": self.args[0]}
        if self.kind == "bits":
            return {"bits": self.args[0]}
        raise AssertionError(self.kind)


@dataclass
class Path_:
    atoms: tuple[Atom, ...] = ()
    # Decisions taken so far: (if-node id, "then" or "else"), for the exactness check on dropped negations.
    history: tuple[tuple[int, str], ...] = ()
    # The if-node ids whose condition this path skipped (an else branch over an atom condition).
    negations: tuple[int, ...] = ()
    values: dict[str, Any] = field(default_factory=dict)
    returned: bool = False


class Script:
    def __init__(self, file_type: str, statements: list[Any]) -> None:
        self.file_type = file_type
        self.aliases = CLASS_ALIASES[file_type]
        self.statements = statements
        self.node_ids: dict[int, int] = {}
        self.locals: set[str] = set()

    # Conditions -------------------------------------------------------------------------------------------------

    def literal_string(self, expr: Any, what: str) -> str:
        if expr[0] != "str":
            raise Unsupported(f"{what}: non-literal argument")
        return expr[1]

    def literal_zero(self, expr: Any) -> bool:
        return expr[0] == "num" and expr[1] == 0

    def offset(self, expr: Any) -> int | None:
        """A literal, non-negative whole-number offset."""
        if expr[0] == "num" and float(expr[1]).is_integer() and 0 <= expr[1] <= 4096:
            return int(expr[1])
        return None

    def method(self, expr: Any) -> tuple[str, list[Any]] | None:
        """`PE.name(args)` (or an alias of the file's class) as (name, args)."""
        if expr[0] == "call" and expr[1][0] == "member" and expr[1][1][0] == "id" and expr[1][1][1] in self.aliases:
            return expr[1][2], expr[2]
        return None

    def atom(self, expr: Any) -> Atom:
        call = self.method(expr)
        if call is None:
            raise Unsupported(f"condition: {describe(expr)}")
        name, args = call
        if name in ("compareEP", "compareOverlay"):
            if len(args) == 1:
                offset = 0
            elif len(args) == 2 and self.offset(args[1]) is not None:
                offset = self.offset(args[1])
            else:
                raise Unsupported(f"condition: {name} at a computed offset")
            text = self.literal_string(args[0], name)
            if name == "compareEP":
                return Atom("ep", (convert_pattern(text, jumps=True, skip=offset),))
            return Atom("overlay_at", (convert_pattern(text, skip=offset),))
        if name in ("is32", "is64") and self.file_type == "PE" and not args:
            return Atom("bits", (32 if name == "is32" else 64,))
        if name == "compare":
            if len(args) == 1:
                offset = 0
            elif len(args) == 2 and self.offset(args[1]) is not None:
                offset = self.offset(args[1])
            else:
                raise Unsupported("condition: compare at a computed offset")
            return Atom("file_at", (offset, convert_pattern(self.literal_string(args[0], "compare"))))
        if name == "isSectionNamePresent" and len(args) == 1:
            return Atom("section", (self.literal_string(args[0], name),))
        if name == "isLibraryPresent":
            if self.file_type == "PE" and len(args) == 2 and not (args[1][0] == "bool" and not args[1][1]):
                raise Unsupported("condition: case-sensitive isLibraryPresent")
            if len(args) not in (1, 2) or (self.file_type != "PE" and len(args) != 1):
                raise Unsupported("condition: isLibraryPresent arity")
            return Atom("library", (self.literal_string(args[0], name),))
        if name == "isFunctionPresent" and self.file_type == "PE" and len(args) == 1:
            return Atom("import", (None, self.literal_string(args[0], name)))
        if name == "isLibraryFunctionPresent" and self.file_type == "PE" and len(args) == 2:
            return Atom("import", (self.literal_string(args[0], name), self.literal_string(args[1], name)))
        if name == "isExportFunctionPresent" and self.file_type == "PE" and len(args) == 1:
            exported = self.literal_string(args[0], name)
            if not exported:
                raise Unsupported("condition: empty export name")
            return Atom("export", (exported,))
        if name == "isOverlayPresent" and not args:
            return Atom("overlay", ())
        raise Unsupported(f"condition: {self.file_type}.{name}")

    def condition(self, expr: Any, path: Path_) -> bool | list[tuple[Atom, ...]]:
        """A condition as a constant (when it reads only known variables) or in disjunctive normal form."""
        kind = expr[0]
        if kind == "bool":
            return expr[1]
        if kind == "num":
            return expr[1] != 0
        if kind == "str":
            return expr[1] != ""
        if kind == "id":
            return truthy(self.value(expr, path))
        if kind == "binary" and expr[1] in ("&&", "||"):
            left = self.condition(expr[2], path)
            right = self.condition(expr[3], path)
            if expr[1] == "&&":
                if left is False or right is False:
                    return False
                if left is True:
                    return right
                if right is True:
                    return left
                return [a + b for a, b in itertools.product(left, right)]
            if left is True or right is True:
                return True
            if left is False:
                return right
            if right is False:
                return left
            return left + right
        if kind == "unary" and expr[1] == "!":
            # A PE image is either PE32 or PE32+, so `!PE.is32()` is exactly `PE.is64()` and the other way round.
            call = self.method(expr[2])
            if self.file_type == "PE" and call is not None and call[0] in ("is32", "is64") and not call[1]:
                return [(Atom("bits", (64 if call[0] == "is32" else 32,)),)]
            inner = self.condition(expr[2], path)
            if isinstance(inner, bool):
                return not inner
            raise Unsupported("condition: negated test")
        if kind == "binary" and expr[1] in ("==", "!=", "===", "!=="):
            left, right = expr[2], expr[3]
            if self.method(left) is None and self.method(right) is None:
                equal = self.value(left, path) == self.value(right, path)
                return equal if expr[1] in ("==", "===") else not equal
            # `PE.isX() == true` and `PE.isX() == false`.
            if right[0] == "bool" and self.method(left) is not None:
                positive = right[1] == (expr[1] in ("==", "==="))
                if not positive:
                    raise Unsupported("condition: negated test")
                return [(self.atom(left),)]
            raise Unsupported(f"condition: comparison {describe(left)}")
        if kind == "call" and expr[1] == ("id", "Boolean") and len(expr[2]) == 1:
            return truthy(self.value(expr[2][0], path))
        return [(self.atom(expr),)]

    def value(self, expr: Any, path: Path_) -> Any:
        """The concrete value of an expression over the script's own variables, or UNKNOWN."""
        kind = expr[0]
        if kind in ("str", "num", "bool"):
            return expr[1]
        if kind == "id":
            name = expr[1]
            if name in path.values:
                result = path.values[name]
                if result is UNKNOWN:
                    raise Unsupported(f"reads {name} computed from the file")
                return result
            if name in ("bShowType", "bShowVersion", "bShowOptions"):
                raise Unsupported("reads display flags")
            raise Unsupported(f"reads variable {name}")
        if kind == "call" and expr[1] == ("id", "Boolean") and len(expr[2]) == 1:
            return truthy(self.value(expr[2][0], path))
        if kind == "binary" and expr[1] == "||":
            left = self.value(expr[2], path)
            return left if truthy(left) else self.value(expr[3], path)
        if kind == "binary" and expr[1] == "&&":
            left = self.value(expr[2], path)
            return self.value(expr[3], path) if truthy(left) else left
        if kind == "binary" and expr[1] == "+" and expr[2][0] == "str" and expr[3][0] == "str":
            return expr[2][1] + expr[3][1]
        if kind == "unary" and expr[1] == "!":
            return not truthy(self.value(expr[2], path))
        raise Unsupported(f"value: {describe(expr)}")

    # Statements -------------------------------------------------------------------------------------------------

    def run(self, meta: dict[str, str]) -> list[Path_]:
        start = Path_(values={"bDetected": False, "sName": meta["name"], "sVersion": meta["version"],
                              "sOptions": meta["options"], "sLang": "", "sLangVersion": ""})
        paths = self.block(self.statements, [start])
        return paths

    def block(self, statements: list[Any], paths: list[Path_]) -> list[Path_]:
        for statement in statements:
            done = [path for path in paths if path.returned]
            live = [path for path in paths if not path.returned]
            if not live:
                break
            paths = done + self.statement(statement, live)
            if len(paths) > MAX_PATHS:
                raise Unsupported("too many paths")
        return paths

    def statement(self, statement: Any, paths: list[Path_]) -> list[Path_]:
        kind = statement[0]
        if kind == "block":
            return self.block(statement[1], paths)
        if kind == "return":
            expr = statement[1]
            if expr is None:
                # A bare return skips result(), so nothing is reported on this path.
                return [replace(path, returned=True, values={**path.values, "bDetected": False}) for path in paths]
            if not (expr[0] == "call" and expr[1] == ("id", "result")):
                raise Unsupported("returns something other than result()")
            return [replace(path, returned=True) for path in paths]
        if kind == "var":
            for name, _ in statement[1]:
                if name in path_variables():
                    raise Unsupported("redeclares a DIE variable")
                self.locals.add(name)
            for path in paths:
                for name, value in statement[1]:
                    path.values[name] = self.try_value(value, path) if value is not None else None
            return paths
        if kind == "assign":
            _, name, op, expr = statement
            if name not in path_variables() and name not in self.locals:
                raise Unsupported(f"assigns {name}")
            out = []
            for path in paths:
                values = dict(path.values)
                if op == "=":
                    if name in DESCRIPTIVE or name in self.locals:
                        values[name] = self.try_value(expr, path)
                    else:
                        values[name] = self.value(expr, path)
                elif op == "+=" and (name in DESCRIPTIVE or name in self.locals):
                    values[name] = UNKNOWN
                else:
                    raise Unsupported(f"{op} on {name}")
                out.append(replace(path, values=values))
            return out
        if kind == "expr":
            expr = statement[1]
            if expr[0] == "call" and expr[1][0] == "id" and expr[1][1] in INERT_CALLS:
                return paths
            if expr[0] == "call" and expr[1][0] == "member" and expr[1][1][0] == "id" \
                    and expr[1][1][1] in DESCRIPTIVE | self.locals:
                # sOptions.append(...) and the like change only descriptive text.
                return [replace(path, values={**path.values, expr[1][1][1]: UNKNOWN}) for path in paths]
            raise Unsupported(f"statement: {describe(expr)}")
        if kind == "if":
            return self.if_statement(statement, paths)
        if kind == "function":
            raise Unsupported("nested function")
        raise Unsupported(f"statement kind {kind}")

    def try_value(self, expr: Any, path: Path_) -> Any:
        try:
            return self.value(expr, path)
        except Unsupported:
            return UNKNOWN

    def if_statement(self, statement: Any, paths: list[Path_]) -> list[Path_]:
        _, cond, then, other = statement
        node = self.node_ids.setdefault(id(statement), len(self.node_ids))
        out: list[Path_] = []
        for path in paths:
            try:
                decided = self.condition(cond, path)
            except Unsupported:
                # A test rampage cannot express is harmless when neither branch can change the detection.
                if descriptive_only(then, self.locals) and (other is None or descriptive_only(other, self.locals)):
                    out.append(taint(path, then, other))
                    continue
                raise
            if decided is True:
                out.extend(self.statement(then, [path]))
            elif decided is False:
                out.extend(self.statement(other, [path]) if other is not None else [path])
            else:
                for conjunction in decided:
                    branch = replace(path, atoms=path.atoms + conjunction, history=path.history + ((node, "then"),),
                                     values=dict(path.values))
                    out.extend(self.statement(then, [branch]))
                skipped = replace(path, history=path.history + ((node, "else"),),
                                  negations=path.negations + (node,), values=dict(path.values))
                out.extend(self.statement(other, [skipped]) if other is not None else [skipped])
        return out


def path_variables() -> set[str]:
    return {"bDetected", "sName"} | DESCRIPTIVE


def replace(path: Path_, **changes: Any) -> Path_:
    fields = {"atoms": path.atoms, "history": path.history, "negations": path.negations,
              "values": path.values, "returned": path.returned}
    fields.update(changes)
    return Path_(**fields)


def taint(path: Path_, *branches: Any) -> Path_:
    """The path after an if whose test we cannot read: every descriptive variable either branch assigns is unknown."""
    values = dict(path.values)
    for branch in branches:
        if branch is not None:
            for name in assigned(branch):
                values[name] = UNKNOWN
    return replace(path, values=values)


def assigned(statement: Any) -> set[str]:
    kind = statement[0]
    if kind == "assign":
        return {statement[1]}
    if kind == "block":
        return set().union(*(assigned(s) for s in statement[1])) if statement[1] else set()
    if kind == "if":
        return assigned(statement[2]) | (assigned(statement[3]) if statement[3] is not None else set())
    if kind == "var":
        return {name for name, _ in statement[1]}
    if kind == "expr" and statement[1][0] == "call" and statement[1][1][0] == "member" \
            and statement[1][1][1][0] == "id":
        return {statement[1][1][1][1]}
    return set()


def descriptive_only(statement: Any, local_names: set[str]) -> bool:
    """Whether a statement can only change descriptive text (version, options, locals), never the detection."""
    kind = statement[0]
    if kind == "assign":
        return statement[1] in DESCRIPTIVE or statement[1] in local_names
    if kind == "block":
        return all(descriptive_only(s, local_names) for s in statement[1])
    if kind == "if":
        return descriptive_only(statement[2], local_names) and (
            statement[3] is None or descriptive_only(statement[3], local_names))
    if kind == "expr":
        expr = statement[1]
        if expr[0] == "call" and expr[1][0] == "id" and expr[1][1] in INERT_CALLS:
            return True
        return expr[0] == "call" and expr[1][0] == "member" and expr[1][1][0] == "id" \
            and (expr[1][1][1] in DESCRIPTIVE or expr[1][1][1] in local_names)
    return False


def truthy(value: Any) -> bool:
    if value is UNKNOWN:
        raise Unsupported("tests a value computed from the file")
    return bool(value)


def describe(expr: Any) -> str:
    """A short name for an expression in skip reasons: `PE.name()` for method calls, else its node kind."""
    if expr[0] == "call" and expr[1][0] == "member" and expr[1][1][0] == "id":
        return f"{expr[1][1][1]}.{expr[1][2]}()"
    if expr[0] == "call" and expr[1][0] == "id":
        return f"{expr[1][1]}()"
    if expr[0] == "member" and expr[1][0] == "id":
        return f"{expr[1][1]}.{expr[2]}"
    if expr[0] == "id":
        return expr[1]
    return expr[0]


# ---------------------------------------------------------------------------------------------------------------
# Whole scripts.

@dataclass
class Converted:
    signatures: list[dict[str, Any]]
    skipped_paths: Counter


def read_meta(statements: list[Any]) -> tuple[dict[str, str], list[Any]]:
    meta = None
    detect = None
    for statement in statements:
        if statement[0] == "expr" and statement[1][0] == "call" and statement[1][1][0] == "id" \
                and statement[1][1][1] in ("meta", "init"):
            if meta is not None:
                raise Unsupported("several meta() calls")
            args = statement[1][2]
            if not 2 <= len(args) <= 4 or any(arg[0] != "str" for arg in args):
                raise Unsupported("meta() with computed arguments")
            values = [arg[1] for arg in args] + [""] * (4 - len(args))
            meta = {"type": values[0], "name": values[1], "version": values[2], "options": values[3]}
        elif statement[0] == "function" and statement[1] == "detect":
            detect = statement[3]
        elif statement[0] == "function":
            raise Unsupported("helper function")
        elif statement[0] == "expr" and statement[1][0] == "call" and statement[1][1] == ("id", "includeScript"):
            raise Unsupported("includeScript")
        else:
            raise Unsupported("top-level statement")
    if meta is None:
        raise Unsupported("no meta()")
    if detect is None:
        raise Unsupported("no detect()")
    return meta, detect


def convert_script(file_type: str, text: str) -> tuple[dict[str, str], Converted]:
    """Converts one script; raises Unsupported when no part of it can be converted exactly."""
    statements = Parser(tokenize(text)).program()
    meta, detect = read_meta(statements)
    if meta["type"] not in KINDS:
        raise Unsupported(f"type out of scope ({meta['type']})")
    script = Script(file_type, detect)
    paths = script.run(meta)
    for path in paths:
        if not path.returned:
            raise Unsupported("detect() falls off its end")
    detected = [path for path in paths if path.values["bDetected"] is True]
    if any(path.values["bDetected"] not in (True, False) for path in paths):
        raise Unsupported("bDetected computed from the file")
    if any(path.values["sName"] is UNKNOWN for path in detected):
        raise Unsupported("name computed from the file")
    skipped = Counter()
    kept: list[Path_] = []
    for path in detected:
        if not path.atoms:
            skipped["detects unconditionally"] += 1
            continue
        if all(exact_without(path, node, paths) for node in path.negations):
            kept.append(path)
        else:
            skipped["else branch whose skipped test does not always detect"] += 1
    signatures = []
    seen = set()
    for path in kept:
        atoms = tuple(sorted(set(path.atoms), key=lambda atom: json.dumps(atom.to_json(), sort_keys=True)))
        version = text_value(path.values["sVersion"])
        options = text_value(path.values["sOptions"])
        key = (atoms, path.values["sName"], version, options)
        if key in seen:
            continue
        seen.add(key)
        signature = {
            "kind": KINDS[meta["type"]],
            "die_type": meta["type"],
            "name": path.values["sName"],
            "conditions": [atom.to_json() for atom in atoms],
        }
        if version:
            signature["version"] = version
        if options:
            signature["options"] = options
        signatures.append(signature)
    signatures = subsume(signatures)
    if not signatures:
        reasons = skipped.most_common(1)
        raise Unsupported(reasons[0][0] if reasons else "never detects")
    return meta, Converted(signatures, skipped)


def subsume(signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drops each signature that another one with the same name, version and options implies: its conditions are a
    strict superset, so it can only fire where the other already does and adds nothing to the report."""
    def key(signature: dict[str, Any]) -> tuple[str, str, str]:
        return signature["name"], signature.get("version", ""), signature.get("options", "")

    def atoms(signature: dict[str, Any]) -> frozenset[str]:
        return frozenset(json.dumps(condition, sort_keys=True) for condition in signature["conditions"])

    return [
        signature for signature in signatures
        if not any(key(other) == key(signature) and atoms(other) < atoms(signature) for other in signatures)
    ]


def text_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def exact_without(path: Path_, node: int, paths: list[Path_]) -> bool:
    """Whether dropping the negation of `node`'s test from `path` stays exact: every way through `node`'s then
    branch, from the same decisions before it, ends in a detection of the same name."""
    index = next(k for k, (seen, branch) in enumerate(path.history) if seen == node and branch == "else")
    prefix = path.history[:index] + ((node, "then"),)
    through = [other for other in paths if other.history[:len(prefix)] == prefix]
    return bool(through) and all(
        other.values["bDetected"] is True and other.values["sName"] == path.values["sName"] for other in through
    )


AUTHOR = re.compile(r"^//\s*Authors?:\s*(.+?)\s*$", re.MULTILINE)


def authors(text: str) -> str:
    names = [re.sub(r"\s*<[^>]*>", "", match).strip() for match in AUTHOR.findall(text)]
    return ", ".join(dict.fromkeys(name for name in names if name))


def load_peid_patterns(root: Path) -> set[str]:
    """The entry-point patterns of the PeID-derived userdb files DIE carries, normalized, so no signature that is
    a copy of a PeID userdb entry ships."""
    patterns = set()
    for path in sorted((root / "peid_rules").rglob("*.txt")):
        for line in path.read_text(encoding="latin-1").splitlines():
            line = line.strip()
            if line.lower().startswith("signature"):
                _, _, value = line.partition("=")
                patterns.add(normalize(value))
    return patterns


def normalize(pattern: str) -> str:
    return re.sub(r"\s+", "", pattern).upper().replace("..", "??")


def peid_copy(signature: dict[str, Any], peid: set[str]) -> bool:
    for condition in signature["conditions"]:
        if "entry" in condition:
            mine = normalize(condition["entry"])
            if mine in peid:
                return True
    return False


def convert(root: Path) -> tuple[dict[str, Any], list[str]]:
    db = root / "db"
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=False).stdout.strip()
    peid = load_peid_patterns(root)
    signatures: list[dict[str, Any]] = []
    report: list[str] = []
    files = Counter()
    skip_reasons: Counter = Counter()
    path_reasons: Counter = Counter()
    other_dirs = Counter()
    for directory in sorted(p for p in db.iterdir() if p.is_dir()):
        if directory.name not in FILE_TYPES:
            other_dirs[directory.name] = sum(1 for _ in directory.rglob("*.sg"))
    for file_type, format_name in FILE_TYPES.items():
        for script_path in sorted((db / file_type).glob("*.sg")):
            relative = script_path.relative_to(db).as_posix()
            if script_path.name.startswith("_"):
                files[(file_type, "framework")] += 1
                continue
            text = script_path.read_text(encoding="utf-8", errors="replace")
            if relative in EXCLUDED:
                files[(file_type, "skipped")] += 1
                skip_reasons[(file_type, "excluded after the false-positive sweep")] += 1
                report.append(f"skip {relative}: {EXCLUDED[relative]}")
                continue
            try:
                meta, converted = convert_script(file_type, text)
            except Unsupported as error:
                files[(file_type, "skipped")] += 1
                skip_reasons[(file_type, error.reason)] += 1
                report.append(f"skip {relative}: {error.reason}")
                continue
            kept = []
            for signature in converted.signatures:
                if peid_copy(signature, peid):
                    path_reasons[(file_type, "entry pattern equals a PeID userdb entry")] += 1
                    continue
                kept.append(signature)
            for reason, count in converted.skipped_paths.items():
                path_reasons[(file_type, reason)] += count
            if not kept:
                files[(file_type, "skipped")] += 1
                skip_reasons[(file_type, "every detection was a PeID userdb entry")] += 1
                report.append(f"skip {relative}: every detection was a PeID userdb entry")
                continue
            files[(file_type, "converted")] += 1
            for signature in kept:
                signature["format"] = format_name
                signature["file"] = relative
                written_by = authors(text)
                if written_by:
                    signature["authors"] = written_by
                signatures.append(signature)
            report.append(f"ok   {relative}: {len(kept)} signature(s)")
    signatures.sort(key=lambda s: (s["format"], s["file"], json.dumps(s, sort_keys=True)))
    data = {
        "source": "Detect It Easy",
        "url": SOURCE_URL,
        "commit": commit,
        "license": "MIT",
        "copyright": "Copyright (c) 2012-2026 hors <horsicq@gmail.com> and the Detect It Easy contributors",
        "signatures": signatures,
    }
    summary = ["", "Summary by file type (scripts):"]
    for (file_type, outcome), count in sorted(files.items()):
        summary.append(f"  {file_type:5} {outcome:10} {count}")
    summary.append(f"  signatures written: {len(signatures)}")
    summary.append("Scripts skipped, by reason:")
    for (file_type, reason), count in sorted(skip_reasons.items(), key=lambda item: (-item[1], item[0])):
        summary.append(f"  {count:5}  {file_type:5} {reason}")
    summary.append("Detections dropped inside converted scripts, by reason:")
    for (file_type, reason), count in sorted(path_reasons.items(), key=lambda item: (-item[1], item[0])):
        summary.append(f"  {count:5}  {file_type:5} {reason}")
    summary.append("Other DIE file types (not loaded by rampage or out of scope), scripts:")
    for name, count in sorted(other_dirs.items()):
        summary.append(f"  {count:5}  {name}")
    return data, report + summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("checkout", type=Path, help="a Detect It Easy checkout at the pinned commit")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--report", type=Path, help="write the per-script report here instead of stdout")
    parser.add_argument("--allow-other-commit", action="store_true", help="convert a checkout off the pin")
    args = parser.parse_args()
    data, report = convert(args.checkout)
    if data["commit"] != PINNED_COMMIT and not args.allow_other_commit:
        print(f"checkout is at {data['commit'] or 'an unknown commit'}, not the pinned {PINNED_COMMIT}",
              file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    text = "\n".join(report) + "\n"
    if args.report:
        args.report.write_text(text, encoding="utf-8")
        print("\n".join(line for line in report if not line.startswith(("ok ", "skip "))))
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())

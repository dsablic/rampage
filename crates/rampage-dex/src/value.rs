//! `encoded_value`: the tagged constants of call sites, static field initial values and annotations. Only scalar
//! values are decoded; arrays and annotations are reported by kind, so a hostile nesting cannot recurse.

use crate::error::{Result, malformed};
use crate::read::Cursor;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Float(u64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array,
    Annotation,
    Null,
    Bool(bool),
}

/// Reads one `encoded_value` at the cursor. An array or annotation is returned as a marker without its content, and
/// the cursor is then no longer at a value boundary: callers stop there.
pub(crate) fn read(cursor: &mut Cursor<'_>) -> Result<Value> {
    let tag = cursor.u8()?;
    let (kind, arg) = (tag & 0x1f, tag >> 5);
    let unsigned = |cursor: &mut Cursor<'_>, len: u8| -> Result<u64> {
        let bytes = cursor.bytes(usize::from(len) + 1)?;
        Ok(bytes.iter().rev().fold(0u64, |value, &byte| (value << 8) | u64::from(byte)))
    };
    let index = |cursor: &mut Cursor<'_>| -> Result<u32> {
        if arg > 3 {
            return Err(malformed(format!("encoded index of {} bytes", arg + 1)));
        }
        Ok(unsigned(cursor, arg)? as u32)
    };
    Ok(match kind {
        0x00 | 0x02 | 0x03 | 0x04 | 0x06 => {
            if arg > 7 {
                return Err(malformed("encoded integer longer than 8 bytes"));
            }
            let raw = unsigned(cursor, arg)?;
            let bits = (u32::from(arg) + 1) * 8;
            let value =
                if kind == 0x03 || bits == 64 { raw as i64 } else { ((raw << (64 - bits)) as i64) >> (64 - bits) };
            Value::Int(value)
        }
        0x10 | 0x11 => Value::Float(unsigned(cursor, arg.min(7))?),
        0x15 => Value::MethodType(index(cursor)?),
        0x16 => Value::MethodHandle(index(cursor)?),
        0x17 => Value::String(index(cursor)?),
        0x18 => Value::Type(index(cursor)?),
        0x19 => Value::Field(index(cursor)?),
        0x1a => Value::Method(index(cursor)?),
        0x1b => Value::Enum(index(cursor)?),
        0x1c => Value::Array,
        0x1d => Value::Annotation,
        0x1e => Value::Null,
        0x1f => Value::Bool(arg != 0),
        _ => return Err(malformed(format!("encoded value type {kind:#x}"))),
    })
}

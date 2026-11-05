//! Target writes (phase 9.4): memory and register writes to a stopped target, served only by a registry whose
//! consent allows them (`--debug-writes`). Each write reads what it replaces first and reads back what it wrote;
//! nothing here writes on its own initiative, programs flash or patches code to plant breakpoints.

use rampage_debug::ByteOrder;
use serde::Serialize;

use crate::ApiError;
use crate::debug_control::{DebugRegistry, debug_failure, failure, parse_thread};

/// Why a registry refuses writes it was not configured for.
const WRITES_NOT_ALLOWED: &str = "writes need the operator to start rampage with --debug-writes (or \
                                  RAMPAGE_DEBUG_WRITES=1); nothing was sent";

/// A register value for [`DebugRegistry::write_register`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DebugRegisterValue {
    /// The register's bytes in the order the stub transfers them (target-endian), as hex digits without `0x`,
    /// exactly the register's size: the form debug_registers reports as `bytes`.
    Bytes(String),
    /// A non-negative integer, accepted only when the session's byte order is known (as for `value` in reads).
    Integer(u64),
}

/// The outcome of `debug_write_memory`.
#[derive(Debug, Serialize)]
pub struct DebugMemoryWrite {
    pub session: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub length: usize,
    /// The epoch the write happened at; writing does not change it.
    pub epoch: u64,
    pub thread: Option<rampage_debug::ThreadId>,
    /// The bytes read before writing, as hex.
    pub before: String,
    /// The bytes read back after writing, as hex; shorter than `length` when the read-back failed part-way.
    pub after: String,
    pub after_error: Option<String>,
    /// Every packet sent, in order, with whether the stub accepted it; writing stops at the first refusal.
    pub chunks: Vec<rampage_debug::WriteChunk>,
    /// Whether every packet was accepted.
    pub complete: bool,
    /// Whether the read-back equals the bytes written. False when the stub dropped or refused part of the write
    /// (flash and ROM often accept writes they ignore).
    pub verified: bool,
    pub limitations: Vec<String>,
}

/// The outcome of `debug_write_register`.
#[derive(Debug, Serialize)]
pub struct DebugRegisterWrite {
    pub session: String,
    #[serde(flatten)]
    pub write: rampage_debug::RegisterWrite,
    pub limitations: Vec<String>,
}

/// Bytes from hex digits (no `0x`, no separators), or why not.
pub(crate) fn parse_hex_bytes(field: &str, text: &str) -> Result<Vec<u8>, ApiError> {
    rampage_debug::packet::decode_hex(text.as_bytes())
        .filter(|_| !text.starts_with("0x"))
        .ok_or_else(|| failure("invalid_argument", format!("{field} must be an even number of hex digits, without 0x")))
}

impl DebugRegistry {
    /// Writes `bytes` (1..=4096) at a runtime `address` of a stopped target at `epoch`; see
    /// [`rampage_debug::Session::write_memory`]. Refused with `not_allowed` unless the registry's consent allows
    /// writes.
    pub fn write_memory(
        &self,
        id: &str,
        epoch: u64,
        address: u64,
        bytes: &[u8],
        expect: Option<&[u8]>,
    ) -> Result<DebugMemoryWrite, ApiError> {
        if !self.consent().writes {
            return Err(failure("not_allowed", WRITES_NOT_ALLOWED));
        }
        let session = self.session(id)?;
        let write = session.write_memory(Some(epoch), address, bytes, expect).map_err(debug_failure)?;
        let mut limitations = vec![
            "verified compares a read-back: a stub can accept a write it drops (flash, ROM) or a device register can \
             read back differently; rampage never programs flash"
                .to_owned(),
            "nothing else is written: no breakpoint is planted and nothing is retried".to_owned(),
        ];
        let last = address + (write.length as u64 - 1);
        let bound: Vec<String> = self
            .bindings_of(id)
            .iter()
            .filter(|binding| {
                let probes = (0..write.length as u64).step_by(16).map(|offset| address + offset).chain([last]);
                probes.into_iter().any(|at| binding.to_static(at).is_some())
            })
            .map(|binding| binding.path.clone())
            .collect();
        if !bound.is_empty() && write.chunks.iter().any(|chunk| chunk.written) {
            limitations.push(format!(
                "the write falls in bound project(s) {}: their files (and decompiled views) no longer match the target \
                 there, and the bindings were verified before it; a later debug_snapshot records the written bytes",
                bound.join(", ")
            ));
        }
        Ok(DebugMemoryWrite {
            session: id.to_owned(),
            address: write.address,
            length: write.length,
            epoch: write.epoch,
            thread: write.thread,
            before: rampage_arch::hex::bytes(&write.before),
            after: rampage_arch::hex::bytes(&write.after),
            after_error: write.after_error,
            chunks: write.chunks,
            complete: write.complete,
            verified: write.verified,
            limitations,
        })
    }

    /// Writes register `name` of `thread` (the stop's thread when omitted) of a stopped target at `epoch`; see
    /// [`rampage_debug::Session::write_register`]. Refused with `not_allowed` unless the registry's consent allows
    /// writes. An integer value needs the session's byte order.
    pub fn write_register(
        &self,
        id: &str,
        epoch: u64,
        thread: Option<&str>,
        name: &str,
        value: &DebugRegisterValue,
    ) -> Result<DebugRegisterWrite, ApiError> {
        if !self.consent().writes {
            return Err(failure("not_allowed", WRITES_NOT_ALLOWED));
        }
        let session = self.session(id)?;
        let thread = thread.map(parse_thread).transpose()?;
        let info = session.info();
        let register = info.layout.as_ref().and_then(|layout| layout.register(name)).ok_or_else(|| {
            failure("invalid_argument", format!("`{name}` is not a register of the target description"))
        })?;
        let bytes = match value {
            DebugRegisterValue::Bytes(text) => {
                let bytes = parse_hex_bytes("value", text)?;
                if bytes.len() != register.bytes() || !register.bitsize.is_multiple_of(8) {
                    return Err(failure(
                        "invalid_argument",
                        format!(
                            "`{name}` is {} bits: value must be exactly {} bytes ({} hex digits), target-endian",
                            register.bitsize,
                            register.bytes(),
                            register.bytes() * 2
                        ),
                    ));
                }
                bytes
            }
            DebugRegisterValue::Integer(number) => {
                rampage_debug::encode_register_value(*number, register.bitsize, info.byte_order).map_err(|message| {
                    let code = if info.byte_order == ByteOrder::Unknown { "unsupported" } else { "invalid_argument" };
                    failure(code, message)
                })?
            }
        };
        let write = session.write_register(Some(epoch), thread, name, &bytes).map_err(debug_failure)?;
        let mut limitations = vec![
            "the stop reply and last stop keep the registers as they were at the stop; read them again with \
             debug_registers"
                .to_owned(),
        ];
        if info.byte_order == ByteOrder::Unknown {
            limitations.push(format!(
                "data byte order is unknown ({}); values are null and bytes are as the stub sent them",
                info.byte_order_evidence
            ));
        }
        if !write.verified {
            limitations.push(
                "the register reads back differently from what was written: the stub or the hardware may ignore or \
                 mask writes to it"
                    .to_owned(),
            );
        }
        Ok(DebugRegisterWrite { session: id.to_owned(), write, limitations })
    }
}

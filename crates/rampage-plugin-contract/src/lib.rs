//! Experimental JSON schema 1 over the import-free workflow component ABI 0.0.1.
//!
//! Fact references identify prepared records, not proof of a plugin's interpretation. Host provenance is
//! deliberately absent: the host must label every returned report as plugin claims outside this schema.
//! Use `decode_facts` and `decode_response` for untrusted bytes: they finish allocation-free lexical admission
//! before serde can allocate collections or internally tagged enum buffers. The validators accept typed values.

mod facts;
mod json;
mod report;
mod validation;

pub use facts::*;
pub use json::{decode_facts, decode_response, preflight_facts_json, preflight_response_json};
pub use report::*;
pub use validation::{validate_facts, validate_report};

pub const SCHEMA_VERSION: u32 = 1;
pub const COMPONENT_INTERFACE: &str = "rampage:workflow/triage@0.0.1";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_RECORDS: usize = 16_384;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_OUTPUT_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_SECTIONS: usize = 6;
pub const MAX_FINDINGS_PER_SECTION: usize = 200;
pub const MAX_EVIDENCE: usize = 8;
pub const MAX_NEXT_STEPS: usize = 10;
pub const MAX_QUOTE_CHARS: usize = 160;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_NODES: usize = MAX_RECORDS * 16;
pub const MAX_JSON_CONTAINERS: usize = MAX_RECORDS * 2;
pub const MAX_JSON_ARRAY_ITEMS: usize = MAX_RECORDS * 2;

pub type FactId = u32;

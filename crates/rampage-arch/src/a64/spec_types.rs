//! What the generated A64 tables use: the shared table types, and the Arm pseudocode helpers A64 conditions call.

pub use super::helpers::{bfx_preferred, move_wide_preferred, sve_move_mask_preferred, sys_op, sys_op128, sysl_op};

pub use crate::mrs::*;

/// System instruction kinds named in the specification's register data. Operations that take no named operand
/// (APAS, GCS*, TRCIT) never appear in the generated table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysKind {
    At,
    Brb,
    Cfp,
    Cosp,
    Cpp,
    Dc,
    Dvp,
    Gic,
    Gicr,
    Gsb,
    Ic,
    Plbi,
    Tlbi,
    Tlbip,
}

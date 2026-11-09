//! M-profile (ARMv6-M/ARMv7-M) T32 encodings the A-profile specification tables leave out or spell differently,
//! written by hand from the ARMv7-M Architecture Reference Manual (A7.7.82 MRS, A7.7.83 MSR), and the A-profile-only
//! encodings an M-profile processor leaves UNDEFINED. Used only when decoding for an M-profile target. The ARMv8-M
//! Mainline stack-limit and Non-secure register names decode too; ARMv8-M-only instructions are not reviewed.

use super::spec_types::*;

const MSR_FIELDS: &[Field] = &[f("Rn", 16, 4), f("mask", 10, 2), f("SYSm", 0, 8)];
const MRS_FIELDS: &[Field] = &[f("Rd", 8, 4), f("SYSm", 0, 8)];

pub(super) static ENCODINGS: [Encoding; 2] = [
    // MSR<c> <spec_reg>, <Rn>: 11110 0 1110 0 0 Rn | 10 0 0 mask 0 0 SYSm.
    enc(
        "MSR_M_T1",
        0xfff0_f300,
        0xf380_8000,
        0,
        MSR_FIELDS,
        syn(&[T("MSR"), Opt(&[O(0)]), T(" "), O(1), T(", "), O(2)], &[op("<c>", &[], &[]), op("<sysm>", &[2], &[]), op("<Rn>", &[0], &[])]),
        &[],
    ),
    // MRS<c> <Rd>, <spec_reg>: 11110 0 1111 1 0 1111 | 10 0 0 Rd SYSm.
    enc(
        "MRS_M_T1",
        0xffff_f000,
        0xf3ef_8000,
        0,
        MRS_FIELDS,
        syn(&[T("MRS"), Opt(&[O(0)]), T(" "), O(1), T(", "), O(2)], &[op("<c>", &[], &[]), op("<Rd>", &[0], &[]), op("<sysm>", &[1], &[])]),
        &[],
    ),
];

/// Whether a 32-bit T32 word is in the M-profile MRS/MSR encoding space, allocated or not.
pub(super) fn claims(word: u32) -> bool {
    ENCODINGS.iter().any(|encoding| word & encoding.mask == encoding.value)
}

/// The M-profile MRS/MSR encoding of a 32-bit T32 word. UNPREDICTABLE forms (an empty
/// or non-`nzcvq` mask for a register other than an APSR form, SP or PC as the general register, a SYSm no
/// M-profile register uses) are left unallocated.
pub(super) fn lookup(word: u32) -> Option<&'static Encoding> {
    let encoding = ENCODINGS.iter().find(|encoding| word & encoding.mask == encoding.value)?;
    let sysm = encoding.field(word, "SYSm")?;
    let register = encoding.field(word, "Rn").or_else(|| encoding.field(word, "Rd"))?;
    let mask = encoding.field(word, "mask");
    let mask_ok = match mask {
        None => true,
        Some(0) => false,
        Some(mask) => sysm <= 3 || mask == 0b10,
    };
    (mask_ok && !matches!(register, 13 | 15) && special_register(sysm, mask).is_some()).then_some(encoding)
}

/// Whether an encoding of the A-profile tables is UNDEFINED on an ARMv6-M/ARMv7-M(E) processor. Floating-point
/// (VFP, coprocessors 10 and 11) instructions of the FP extension stay allocated.
pub(super) fn undefined(encoding: &Encoding, word: u32) -> bool {
    let name = encoding.name;
    let wide = word > 0xffff;
    let top = word >> 24;
    // Advanced SIMD data processing (0xEF/0xFF) and element/structure loads and stores (0xF9 with bit 20 clear).
    let simd = wide && (top == 0xef || top == 0xff || (top == 0xf9 && (word >> 20) & 1 == 0));
    let a_profile_only = [
        "BL_i_T2", "SETEND_T1", "SRS_T1_AS", "SRS_T2_AS", "RFE_T1_AS", "RFE_T2_AS", "ERET_T1", "SUBS_PC_T5_AS",
        "SMC_T1_AS", "HVC_T1", "MSR_br_T1_AS", "MRS_br_T1_AS", "LDREXD_T1", "STREXD_T1", "LDAEXD_T1", "STLEXD_T1",
        "CPS_T2_AS", "CPSID_T2_AS", "CPSID_T2_ASM", "CPSIE_T2_AS", "CPSIE_T2_ASM",
    ]
    .contains(&name);
    let cps_a = matches!(name, "CPSID_T1_AS" | "CPSIE_T1_AS") && encoding.field(word, "A") == Some(1);
    simd || a_profile_only || cps_a
}

/// The special register SYSm names, as LLVM spells it; MSR to an APSR form names the flags `mask` writes.
pub(super) fn special_register(sysm: u64, msr_mask: Option<u64>) -> Option<String> {
    let name = match sysm {
        0..=3 => {
            let base = ["apsr", "iapsr", "eapsr", "xpsr"][sysm as usize];
            return Some(match msr_mask {
                None => base.to_owned(),
                Some(0b10) => format!("{base}_nzcvq"),
                Some(0b01) => format!("{base}_g"),
                Some(0b11) => format!("{base}_nzcvqg"),
                Some(_) => return None,
            });
        }
        5 => "ipsr",
        6 => "epsr",
        7 => "iepsr",
        8 => "msp",
        9 => "psp",
        10 => "msplim",
        11 => "psplim",
        16 => "primask",
        17 => "basepri",
        18 => "basepri_max",
        19 => "faultmask",
        20 => "control",
        0x88 => "msp_ns",
        0x89 => "psp_ns",
        0x8a => "msplim_ns",
        0x8b => "psplim_ns",
        0x90 => "primask_ns",
        0x91 => "basepri_ns",
        0x93 => "faultmask_ns",
        0x94 => "control_ns",
        0x98 => "sp_ns",
        _ => return None,
    };
    Some(name.to_owned())
}

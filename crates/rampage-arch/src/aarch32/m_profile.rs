//! M-profile (ARMv6-M/ARMv7-M/ARMv8-M) T32 encodings the A-profile specification tables leave out, written by hand
//! from the ARMv7-M Architecture Reference Manual (A7.7.82 MRS, A7.7.83 MSR). Only words the generated tables leave
//! unallocated reach these: the A-profile forms with SYSm zero (`MRS Rd, APSR`, `MSR APSR_nzcvq, Rn`) keep their
//! generated decoding.

use super::spec_types::*;

const MSR_FIELDS: &[Field] = &[f("Rn", 16, 4), f("mask", 10, 2), f("SYSm", 0, 8)];
const MRS_FIELDS: &[Field] = &[f("Rd", 8, 4), f("SYSm", 0, 8)];

static ENCODINGS: [Encoding; 2] = [
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

/// The M-profile encoding of a 32-bit T32 word the generated tables do not allocate.
pub(super) fn lookup(word: u32) -> Option<&'static Encoding> {
    ENCODINGS.iter().find(|encoding| word & encoding.mask == encoding.value)
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

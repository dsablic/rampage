use serde::Serialize;

use crate::{Arch, Flow, Insn};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiftedInstruction {
    #[serde(serialize_with = "crate::hex::address")]
    pub address: u64,
    pub bits: u8,
    pub effects: Vec<Effect>,
    pub flow: Flow,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Register {
        number: u8,
    },
    StackPointer,
    Constant {
        #[serde(serialize_with = "crate::hex::address")]
        value: u64,
    },
    Add {
        left: Box<Value>,
        right: Box<Value>,
    },
    Subtract {
        left: Box<Value>,
        right: Box<Value>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Discard { value: Value },
    LoadDiscard { address: Value },
    Assign { destination: Value, value: Value },
    Load { destination: Value, address: Value },
    Store { address: Value, value: Value },
    Barrier { reason: String },
}

fn register(number: u8, stack: bool) -> Value {
    match number {
        31 if stack => Value::StackPointer,
        31 => Value::Constant { value: 0 },
        _ => Value::Register { number },
    }
}

fn assign(destination: Value, value: Value) -> Effect {
    if matches!(destination, Value::Constant { .. }) {
        Effect::Discard { value }
    } else {
        Effect::Assign { destination, value }
    }
}

/// A deliberately partial IR: unknown instructions are semantic barriers, never no-ops.
pub fn lift(arch: Arch, bytes: &[u8], insn: &Insn) -> LiftedInstruction {
    let mut lifted =
        LiftedInstruction { address: insn.address, bits: 64, effects: Vec::new(), flow: insn.flow, complete: false };
    if arch != Arch::Aarch64 || bytes.len() < 4 || insn.flow == Flow::Invalid {
        lifted.effects.push(Effect::Barrier { reason: "unsupported architecture or invalid instruction".to_owned() });
        return lifted;
    }
    let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let rd = (word & 31) as u8;
    let rn = ((word >> 5) & 31) as u8;
    let sf = word >> 31 != 0;
    if word & 0x1f80_0000 == 0x1100_0000 && word & (1 << 29) == 0 {
        lifted.bits = if sf { 64 } else { 32 };
        let immediate = u64::from((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
        let (left, right) = (Box::new(register(rn, true)), Box::new(Value::Constant { value: immediate }));
        let value = if word & (1 << 30) == 0 { Value::Add { left, right } } else { Value::Subtract { left, right } };
        lifted.effects.push(assign(register(rd, true), value));
        lifted.complete = true;
    } else if word & 0x7f80_0000 == 0x5280_0000 {
        lifted.bits = if sf { 64 } else { 32 };
        let shift = ((word >> 21) & 3) * 16;
        if sf || shift < 32 {
            lifted
                .effects
                .push(assign(register(rd, false), Value::Constant { value: u64::from((word >> 5) & 0xffff) << shift }));
            lifted.complete = true;
        }
    } else if word & 0xffe0_ffe0 == 0xaa00_03e0 {
        let rm = ((word >> 16) & 31) as u8;
        lifted.effects.push(assign(register(rd, false), register(rm, false)));
        lifted.complete = true;
    } else if matches!(word & 0xffc0_0000, 0xf940_0000 | 0xf900_0000) {
        let address = Value::Add {
            left: Box::new(register(rn, true)),
            right: Box::new(Value::Constant { value: u64::from((word >> 10) & 0xfff) * 8 }),
        };
        let rt = register(rd, false);
        lifted.effects.push(if word & (1 << 22) != 0 {
            if rd == 31 { Effect::LoadDiscard { address } } else { Effect::Load { destination: rt, address } }
        } else {
            Effect::Store { address, value: rt }
        });
        lifted.complete = true;
    } else if word == 0xd503_201f {
        lifted.complete = true;
    }
    if !lifted.complete {
        lifted.effects.push(Effect::Barrier { reason: "instruction semantics not yet implemented".to_owned() });
    }
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Target, decoder};

    fn instruction(word: u32) -> LiftedInstruction {
        let bytes = word.to_le_bytes();
        let insn = decoder(&Target::new(Arch::Aarch64)).unwrap().decode(&bytes, 0x1000);
        lift(Arch::Aarch64, &bytes, &insn)
    }

    #[test]
    fn arithmetic_preserves_register_width_stack_pointer_and_immediate() {
        let lifted = instruction(0x9100_1020); // add x0,x1,#4
        assert!(lifted.complete);
        assert_eq!(lifted.bits, 64);
        assert_eq!(
            lifted.effects,
            vec![Effect::Assign {
                destination: Value::Register { number: 0 },
                value: Value::Add {
                    left: Box::new(Value::Register { number: 1 }),
                    right: Box::new(Value::Constant { value: 4 }),
                },
            }]
        );
        assert_eq!(instruction(0x1100_1020).bits, 32);
        assert!(matches!(
            &instruction(0x9100_13ff).effects[0],
            Effect::Assign { destination: Value::StackPointer, .. }
        ));
    }

    #[test]
    fn unsupported_flag_setting_instructions_are_barriers() {
        let lifted = instruction(0xb100_1020);
        assert!(!lifted.complete);
        assert!(matches!(&lifted.effects[0], Effect::Barrier { .. }));
    }

    #[test]
    fn loads_and_stores_are_distinct_effects_and_zero_register_is_constant() {
        assert!(matches!(&instruction(0xf940_0100).effects[0], Effect::Load { .. }));
        assert!(matches!(
            &instruction(0xf900_011f).effects[0],
            Effect::Store { value: Value::Constant { value: 0 }, .. }
        ));
    }

    #[test]
    fn moves_to_zero_discard_the_value_and_unknown_instructions_do_not_lift() {
        assert!(matches!(&instruction(0xd280_003f).effects[0], Effect::Discard { .. }));
        assert!(matches!(
            &instruction(0xaa08_03e9).effects[0],
            Effect::Assign { destination: Value::Register { number: 9 }, value: Value::Register { number: 8 } }
        ));
        assert!(!instruction(0x8b01_0008).complete);
    }

    #[test]
    fn tagged_arithmetic_and_minmax_are_not_ordinary_add_sub() {
        for word in [0x9181_0420, 0xd181_0420, 0x11c0_0420, 0x91cc_0420] {
            assert!(!instruction(word).complete, "{word:08x}");
        }
        assert!(matches!(&instruction(0xf940_03ff).effects[0], Effect::LoadDiscard { .. }));
    }
}

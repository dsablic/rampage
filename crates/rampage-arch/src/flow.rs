use crate::Flow;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Next,
    Jump(Option<u64>),
    Call(Option<u64>),
    Return,
    Halt,
}

impl Kind {
    pub(crate) fn flow(self, conditional: bool) -> Flow {
        match self {
            Self::Next => Flow::Next,
            Self::Halt => Flow::Halt,
            Self::Return if conditional => Flow::Next,
            Self::Return => Flow::Return,
            Self::Call(Some(target)) => Flow::Call(target),
            Self::Call(None) => Flow::IndirectCall,
            Self::Jump(Some(target)) if conditional => Flow::ConditionalJump(target),
            Self::Jump(Some(target)) => Flow::Jump(target),
            Self::Jump(None) if conditional => Flow::Next,
            Self::Jump(None) => Flow::IndirectJump,
        }
    }

    /// Whether this predicated kind is a call, return or register-indirect jump that [`crate::Insn::conditional`]
    /// marks.
    pub(crate) fn is_conditional_transfer(self, conditional: bool) -> bool {
        conditional && matches!(self, Self::Call(_) | Self::Return | Self::Jump(None))
    }
}

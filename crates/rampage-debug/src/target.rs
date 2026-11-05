//! Register layouts: from the stub's target description (`target.xml` and its includes), or a fallback for stubs
//! without one; and the architecture facts derived from them.

use serde::Serialize;

use crate::xml::{self, Element};

/// Most registers in one layout.
const MAX_REGISTERS: usize = 4096;
/// Widest register, in bits.
const MAX_REGISTER_BITS: u32 = 4096;
/// Most target description documents fetched for one layout, counting `target.xml`.
pub const MAX_DESCRIPTION_DOCUMENTS: usize = 32;
/// Deepest `<xi:include>` nesting.
pub const MAX_INCLUDE_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Register {
    pub name: String,
    pub regnum: u32,
    pub bitsize: u32,
    /// The type the description names (`int`, `code_ptr`, `ieee_double`, a vector type...), if any.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub group: Option<String>,
    /// The description feature that declared the register.
    pub feature: Option<String>,
    /// Where the register's bytes start in a `g` reply.
    pub offset: usize,
    /// LLDB's alternative name (`x30` for debugserver's `lr`, `x29` for `fp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_name: Option<String>,
    /// LLDB's generic role: `pc`, `sp`, `fp`, `ra`, `flags`, `arg1`...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic: Option<String>,
}

impl Register {
    pub fn bytes(&self) -> usize {
        self.bitsize as usize / 8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutSource {
    /// Parsed from the stub's `target.xml`.
    TargetDescription,
    /// A built-in GDB layout, chosen because the stub has no target description and its `g` reply has exactly
    /// this layout's size.
    Fallback,
    /// Built from LLDB's `qRegisterInfo<n>` replies (debugserver without a target description).
    RegisterInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// The `<architecture>` the description names, or the fallback's GDB architecture name.
    pub architecture: Option<String>,
    pub source: LayoutSource,
    pub features: Vec<String>,
    /// Registers in register-number order, which is their order in a `g` reply.
    pub registers: Vec<Register>,
    /// The bytes all registers take in a `g` reply.
    pub g_size: usize,
    /// The `<osabi>` the description names (`GNU/Linux`, `Windows`...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osabi: Option<String>,
}

impl Layout {
    pub fn register(&self, name: &str) -> Option<&Register> {
        self.registers.iter().find(|register| register.name == name)
    }

    /// The register named `name`, or whose LLDB alternative name is `name` (`x30` finds debugserver's `lr`).
    pub fn register_or_alias(&self, name: &str) -> Option<&Register> {
        self.register(name)
            .or_else(|| self.registers.iter().find(|register| register.alt_name.as_deref() == Some(name)))
    }

    /// The register whose LLDB generic role is `role` (`pc`, `sp`, `ra`...).
    pub fn generic(&self, role: &str) -> Option<&Register> {
        self.registers.iter().find(|register| register.generic.as_deref() == Some(role))
    }

    /// A layout whose registers follow each other in register-number order in a `g` reply.
    fn new(
        architecture: Option<String>,
        source: LayoutSource,
        features: Vec<String>,
        registers: Vec<Register>,
    ) -> Result<Self, String> {
        Self::build(architecture, source, features, registers, None)
    }

    /// A layout with offsets as the stub states them (LLDB's `offset`): `extent` is the end of the `g` reply,
    /// counting registers rampage leaves out (views of other registers, or wider than it reads). The offsets must
    /// rise with the register numbers and must not overlap, so a `g` reply cut short still holds whole registers
    /// up to where it ends.
    fn with_offsets(
        architecture: Option<String>,
        source: LayoutSource,
        features: Vec<String>,
        registers: Vec<Register>,
        extent: usize,
    ) -> Result<Self, String> {
        Self::build(architecture, source, features, registers, Some(extent))
    }

    fn build(
        architecture: Option<String>,
        source: LayoutSource,
        features: Vec<String>,
        mut registers: Vec<Register>,
        extent: Option<usize>,
    ) -> Result<Self, String> {
        if registers.is_empty() {
            return Err("target description declares no registers".into());
        }
        registers.sort_by_key(|register| register.regnum);
        let mut offset = 0usize;
        let mut names = std::collections::HashSet::new();
        for index in 0..registers.len() {
            if index > 0 && registers[index - 1].regnum == registers[index].regnum {
                return Err(format!("register number {} is declared twice", registers[index].regnum));
            }
            if !names.insert(registers[index].name.clone()) {
                return Err(format!("register `{}` is declared twice", registers[index].name));
            }
            match extent {
                None => registers[index].offset = offset,
                Some(_) if registers[index].offset < offset => {
                    return Err(format!(
                        "register `{}` at offset {} overlaps the register before it",
                        registers[index].name, registers[index].offset
                    ));
                }
                Some(_) => offset = registers[index].offset,
            }
            offset = offset.checked_add(registers[index].bytes()).ok_or("register offsets overflow")?;
        }
        let g_size = offset.max(extent.unwrap_or(0));
        if g_size > crate::packet::MAX_PACKET_BYTES / 2 {
            return Err("register file exceeds the packet limit".into());
        }
        Ok(Self { architecture, source, features, registers, g_size, osabi: None })
    }
}

/// Builds a layout from `target.xml`, fetching each `<xi:include href>` through `fetch` (an annex name), at most
/// [`MAX_INCLUDE_DEPTH`] deep and [`MAX_DESCRIPTION_DOCUMENTS`] documents in all.
pub fn parse_description(root: &str, fetch: &mut dyn FnMut(&str) -> Result<String, String>) -> Result<Layout, String> {
    let mut state = Description::default();
    state.document(root, 0, fetch)?;
    let osabi = state.osabi.take();
    let layout = match state.offsets {
        // LLDB's descriptions (debugserver) state every register's offset and declare views of other registers.
        Some(true) => Layout::with_offsets(
            state.architecture,
            LayoutSource::TargetDescription,
            state.features,
            state.registers,
            state.extent,
        ),
        _ => Layout::new(state.architecture, LayoutSource::TargetDescription, state.features, state.registers),
    };
    layout.map(|layout| Layout { osabi, ..layout })
}

#[derive(Default)]
struct Description {
    architecture: Option<String>,
    osabi: Option<String>,
    features: Vec<String>,
    registers: Vec<Register>,
    next_regnum: u32,
    documents: usize,
    /// Whether the registers state their `g` offsets (all of them or none).
    offsets: Option<bool>,
    /// The end of the `g` reply by the stated offsets, counting registers left out.
    extent: usize,
}

impl Description {
    fn document(
        &mut self,
        text: &str,
        depth: usize,
        fetch: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> Result<(), String> {
        self.documents += 1;
        if self.documents > MAX_DESCRIPTION_DOCUMENTS || depth > MAX_INCLUDE_DEPTH {
            return Err("target description includes too many or too deeply nested documents".into());
        }
        let root = xml::parse(text)?;
        match root.name.as_str() {
            "target" => {
                for child in &root.children {
                    match child.name.as_str() {
                        "architecture" => {
                            let name = child.text.trim();
                            if name.is_empty() || name.len() > 64 {
                                return Err("invalid <architecture>".into());
                            }
                            self.architecture = Some(name.to_owned());
                        }
                        "osabi" => {
                            let name = child.text.trim();
                            if !name.is_empty() && name.len() <= 64 {
                                self.osabi = Some(name.to_owned());
                            }
                        }
                        "feature" => self.feature(child)?,
                        "xi:include" => self.include(child, depth, fetch)?,
                        _ => {}
                    }
                }
                Ok(())
            }
            "feature" => self.feature(&root),
            other => Err(format!("unexpected target description root <{other}>")),
        }
    }

    fn include(
        &mut self,
        element: &Element,
        depth: usize,
        fetch: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> Result<(), String> {
        let href = element.attribute("href").ok_or("<xi:include> without href")?;
        if href.is_empty()
            || href.len() > 64
            || !href.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
        {
            return Err(format!("unsupported include `{}`", href.chars().take(64).collect::<String>()));
        }
        let text = fetch(href)?;
        self.document(&text, depth + 1, fetch)
    }

    fn feature(&mut self, feature: &Element) -> Result<(), String> {
        // lldb-server writes its one feature without a name (`GDBRemoteCommunicationServerLLGS.cpp`, `BuildTargetXml`).
        let name = feature.attribute("name").unwrap_or("");
        if !name.is_empty() {
            self.features.push(name.chars().take(128).collect());
        }
        for register in feature.children_named("reg") {
            if self.registers.len() >= MAX_REGISTERS {
                return Err("target description declares too many registers".into());
            }
            let reg_name = register.attribute("name").ok_or("<reg> without name")?;
            if reg_name.is_empty() || reg_name.len() > 64 || !reg_name.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err("invalid register name".into());
            }
            let bitsize: u32 =
                register.attribute("bitsize").and_then(|bits| bits.parse().ok()).ok_or("<reg> without bitsize")?;
            let regnum = match register.attribute("regnum") {
                Some(number) => number.parse().map_err(|_| format!("register `{reg_name}` has invalid regnum"))?,
                None => self.next_regnum,
            };
            self.next_regnum = regnum.checked_add(1).ok_or("register number overflows")?;
            // LLDB's `offset` places the register in the `g` reply; GDB's descriptions have none.
            let offset = register
                .attribute("offset")
                .map(|offset| offset.parse::<usize>().map_err(|_| format!("register `{reg_name}` has invalid offset")))
                .transpose()?;
            if self.offsets.is_some_and(|stated| stated != offset.is_some()) {
                return Err("some registers state their offset and others do not".into());
            }
            self.offsets = Some(offset.is_some());
            // A view of other registers (LLDB's `value_regnums`: w0 of x0, s0 of v0) has no bytes of its own in
            // a `g` reply.
            if register.attribute("value_regnums").is_some() {
                continue;
            }
            let usable = bitsize > 0 && bitsize.is_multiple_of(8) && bitsize <= MAX_REGISTER_BITS;
            if let Some(offset) = offset {
                let end = offset
                    .checked_add(bitsize.div_ceil(8) as usize)
                    .filter(|end| *end <= crate::packet::MAX_PACKET_BYTES / 2)
                    .ok_or_else(|| format!("register `{reg_name}` lies beyond the packet limit"))?;
                self.extent = self.extent.max(end);
                // A register wider than rampage reads (an SME ZA array) is left out; its stated offset keeps the
                // others in place.
                if !usable && bitsize.is_multiple_of(8) && bitsize > 0 {
                    continue;
                }
            }
            if !usable {
                return Err(format!("register `{reg_name}` has unsupported bitsize {bitsize}"));
            }
            let text = |attribute: &str| register.attribute(attribute).map(|value| value.chars().take(64).collect());
            self.registers.push(Register {
                name: reg_name.to_owned(),
                regnum,
                bitsize,
                kind: text("type"),
                group: text("group"),
                feature: Some(name.chars().take(128).collect()).filter(|name: &String| !name.is_empty()),
                offset: offset.unwrap_or(0),
                alt_name: text("altname"),
                generic: text("generic"),
            });
        }
        Ok(())
    }
}

/// Builds a layout from LLDB's `qRegisterInfo<n>` replies, in register-number order. Registers that are views of
/// others (`container-regs`) are left out, as from a `g` reply; so are registers wider than rampage reads, whose
/// stated offsets keep the others in place.
pub fn from_register_info(architecture: Option<String>, infos: &[crate::lldb::RegisterInfo]) -> Result<Layout, String> {
    let mut registers = Vec::new();
    let mut sets = Vec::new();
    let mut extent = 0usize;
    for (regnum, info) in infos.iter().enumerate() {
        if !info.container.is_empty() {
            continue;
        }
        let end = info
            .offset
            .checked_add(info.bitsize.div_ceil(8) as usize)
            .filter(|end| *end <= crate::packet::MAX_PACKET_BYTES / 2)
            .ok_or_else(|| format!("register `{}` lies beyond the packet limit", info.name))?;
        extent = extent.max(end);
        if info.bitsize > MAX_REGISTER_BITS {
            continue;
        }
        if let Some(set) = &info.set
            && !sets.contains(set)
            && sets.len() < 64
        {
            sets.push(set.clone());
        }
        registers.push(Register {
            name: info.name.clone(),
            regnum: regnum as u32,
            bitsize: info.bitsize,
            kind: info.encoding.clone(),
            group: info.set.clone(),
            feature: None,
            offset: info.offset,
            alt_name: info.alt_name.clone(),
            generic: info.generic.clone(),
        });
    }
    Layout::with_offsets(architecture, LayoutSource::RegisterInfo, sets, registers, extent)
}

fn fallback(architecture: &str, registers: &[(&str, u32)], feature: &str) -> Layout {
    let registers = registers
        .iter()
        .enumerate()
        .map(|(regnum, (name, bitsize))| Register {
            name: (*name).to_owned(),
            regnum: regnum as u32,
            bitsize: *bitsize,
            kind: None,
            group: None,
            feature: Some(feature.to_owned()),
            offset: 0,
            alt_name: None,
            generic: None,
        })
        .collect();
    Layout::new(Some(architecture.to_owned()), LayoutSource::Fallback, vec![feature.to_owned()], registers)
        .expect("built-in layouts are valid")
}

/// GDB's built-in register layouts for stubs without a target description.
pub fn fallback_layouts() -> Vec<Layout> {
    let x86_64: Vec<(&str, u32)> = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip",
    ]
    .iter()
    .map(|name| (*name, 64))
    .chain(["eflags", "cs", "ss", "ds", "es", "fs", "gs"].iter().map(|name| (*name, 32)))
    .chain(["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"].iter().map(|name| (*name, 80)))
    .chain(["fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop"].iter().map(|name| (*name, 32)))
    .chain((0..16).map(|index| (XMM[index], 128)))
    .chain([("mxcsr", 32)])
    .collect();
    let aarch64_core: Vec<(&str, u32)> =
        X_REGISTERS.iter().map(|name| (*name, 64)).chain([("sp", 64), ("pc", 64), ("cpsr", 32)]).collect();
    let aarch64_fp: Vec<(&str, u32)> = aarch64_core
        .iter()
        .copied()
        .chain(V_REGISTERS.iter().map(|name| (*name, 128)))
        .chain([("fpsr", 32), ("fpcr", 32)])
        .collect();
    let arm_core: Vec<(&str, u32)> = ARM_CORE.iter().map(|name| (*name, 32)).chain([("cpsr", 32)]).collect();
    let arm_fpa: Vec<(&str, u32)> = ARM_CORE
        .iter()
        .map(|name| (*name, 32))
        .chain(["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"].iter().map(|name| (*name, 96)))
        .chain([("fps", 32), ("cpsr", 32)])
        .collect();
    let riscv = |bits| RISCV.iter().map(move |name| (*name, bits)).collect::<Vec<_>>();
    vec![
        fallback("i386:x86-64", &x86_64, "org.gnu.gdb.i386.core"),
        fallback("aarch64", &aarch64_core, "org.gnu.gdb.aarch64.core"),
        fallback("aarch64", &aarch64_fp, "org.gnu.gdb.aarch64.core"),
        fallback("arm", &arm_core, "org.gnu.gdb.arm.core"),
        fallback("arm", &arm_fpa, "org.gnu.gdb.arm.core"),
        fallback("riscv:rv32", &riscv(32), "org.gnu.gdb.riscv.cpu"),
        fallback("riscv:rv64", &riscv(64), "org.gnu.gdb.riscv.cpu"),
    ]
}

/// The fallback layout whose `g` size is exactly `g_size`, if exactly one is.
pub fn fallback_for(g_size: usize) -> Option<Layout> {
    let mut matching = fallback_layouts().into_iter().filter(|layout| layout.g_size == g_size);
    let layout = matching.next()?;
    matching.next().is_none().then_some(layout)
}

const XMM: [&str; 16] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",
    "xmm14", "xmm15",
];
const X_REGISTERS: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
    "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
];
const V_REGISTERS: [&str; 32] = [
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
    "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
];
const ARM_CORE: [&str; 16] =
    ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];
const RISCV: [&str; 33] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2",
    "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6", "pc",
];

/// The architectures this client knows facts about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    X86,
    X86_64,
    Aarch64,
    Arm,
    Riscv32,
    Riscv64,
    Other,
}

impl Family {
    pub fn of(layout: Option<&Layout>) -> Self {
        let Some(layout) = layout else { return Family::Other };
        let architecture = layout.architecture.as_deref().unwrap_or("").to_ascii_lowercase();
        let has_feature = |prefix: &str| layout.features.iter().any(|feature| feature.starts_with(prefix));
        // debugserver's descriptions name no architecture; their feature (`com.apple.debugserver.arm64`) does.
        let apple =
            |suffix: &str| layout.features.iter().any(|feature| feature == &format!("com.apple.debugserver.{suffix}"));
        if architecture.starts_with("i386:x86-64") || architecture == "x86-64" || apple("x86_64") || apple("x86_64h") {
            Family::X86_64
        } else if architecture.starts_with("i386") || apple("i386") {
            Family::X86
        } else if architecture.starts_with("aarch64")
            || has_feature("org.gnu.gdb.aarch64.")
            || apple("arm64")
            || apple("arm64e")
        {
            Family::Aarch64
        } else if architecture.starts_with("arm") || has_feature("org.gnu.gdb.arm.") {
            Family::Arm
        } else if architecture.starts_with("riscv") || has_feature("org.gnu.gdb.riscv.") {
            match architecture.as_str() {
                "riscv:rv32" => Family::Riscv32,
                "riscv:rv64" => Family::Riscv64,
                _ => match layout.register("pc").map(|pc| pc.bitsize) {
                    Some(32) => Family::Riscv32,
                    Some(64) => Family::Riscv64,
                    _ => Family::Other,
                },
            }
        } else {
            Family::Other
        }
    }

    pub fn pointer_size(self, layout: Option<&Layout>) -> Option<u8> {
        match self {
            Family::X86_64 | Family::Aarch64 | Family::Riscv64 => Some(8),
            Family::X86 | Family::Arm | Family::Riscv32 => Some(4),
            Family::Other => {
                let layout = layout?;
                ["pc", "rip", "eip"].iter().find_map(|name| layout.register(name)).map(|pc| (pc.bitsize / 8) as u8)
            }
        }
    }
}

/// Whether the layout is an ARM M-profile one.
pub fn m_profile(layout: Option<&Layout>) -> bool {
    layout.is_some_and(|layout| layout.features.iter().any(|feature| feature == "org.gnu.gdb.arm.m-profile"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QEMU_ROOT: &str = "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
        <architecture>arm</architecture><xi:include href=\"arm-m-profile.xml\"/>\
        <xi:include href=\"system-registers.xml\"/><xi:include href=\"arm-m-system.xml\"/></target>";

    fn qemu_fetch(name: &str) -> Result<String, String> {
        Ok(match name {
            "arm-m-profile.xml" => {
                let mut text = String::from("<?xml version=\"1.0\"?><feature name=\"org.gnu.gdb.arm.m-profile\">");
                for index in 0..13 {
                    text.push_str(&format!("<reg name=\"r{index}\" bitsize=\"32\"/>"));
                }
                text.push_str(
                    "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/><reg name=\"lr\" bitsize=\"32\"/>\
                     <reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/>\
                     <reg name=\"xpsr\" bitsize=\"32\" regnum=\"25\"/></feature>",
                );
                text
            }
            "system-registers.xml" => "<feature name=\"org.qemu.gdb.arm.sys.regs\"></feature>".into(),
            "arm-m-system.xml" => "<feature name=\"org.gnu.gdb.arm.m-system\">\
                <reg name=\"msp\" bitsize=\"32\" regnum=\"26\" type=\"int\"/><reg name=\"psp\" bitsize=\"32\"/>\
                <reg name=\"primask\" bitsize=\"32\"/></feature>"
                .into(),
            _ => return Err(format!("no {name}")),
        })
    }

    #[test]
    fn resolves_includes_and_numbers_registers_like_gdb() {
        let layout = parse_description(QEMU_ROOT, &mut qemu_fetch).unwrap();
        assert_eq!(layout.architecture.as_deref(), Some("arm"));
        assert_eq!(Family::of(Some(&layout)), Family::Arm);
        assert!(m_profile(Some(&layout)));
        let xpsr = layout.register("xpsr").unwrap();
        assert_eq!((xpsr.regnum, xpsr.offset), (25, 64));
        let psp = layout.register("psp").unwrap();
        assert_eq!((psp.regnum, psp.offset), (27, 72));
        assert_eq!(layout.g_size, 80);
        assert_eq!(layout.register("pc").unwrap().kind.as_deref(), Some("code_ptr"));
    }

    #[test]
    fn refuses_bad_descriptions_and_include_loops() {
        let mut looping = |_: &str| Ok("<target><xi:include href=\"self.xml\"/></target>".to_owned());
        assert!(parse_description("<target><xi:include href=\"self.xml\"/></target>", &mut looping).is_err());
        let mut none = |name: &str| Err(format!("no {name}"));
        for text in [
            "<target/>",
            "<target><xi:include href=\"a:b\"/></target>",
            "<target><feature name=\"f\"><reg name=\"a\" bitsize=\"12\"/></feature></target>",
            "<target><feature name=\"f\"><reg name=\"a\"/></feature></target>",
            "<target><feature name=\"f\"><reg name=\"a\" bitsize=\"8\"/><reg name=\"a\" bitsize=\"8\"/></feature></target>",
            "<target><feature name=\"f\"><reg name=\"a\" bitsize=\"8\" regnum=\"1\"/><reg name=\"b\" bitsize=\"8\" regnum=\"1\"/></feature></target>",
            "<target><feature name=\"f\"><reg name=\"a\" bitsize=\"8\" regnum=\"4294967295\"/><reg name=\"b\" bitsize=\"8\"/></feature></target>",
            "<library-list/>",
        ] {
            assert!(parse_description(text, &mut none).is_err(), "{text}");
        }
    }

    #[test]
    fn fallback_layouts_have_gdb_g_sizes() {
        let sizes: Vec<_> = fallback_layouts().iter().map(|layout| layout.g_size).collect();
        assert_eq!(sizes, vec![536, 268, 788, 68, 168, 132, 264]);
        assert_eq!(fallback_for(268).unwrap().register("pc").unwrap().offset, 256);
        assert_eq!(Family::of(fallback_for(264).as_ref()), Family::Riscv64);
        assert!(fallback_for(100).is_none());
        for layout in fallback_layouts() {
            assert!(Family::of(Some(&layout)) != Family::Other);
        }
    }
}

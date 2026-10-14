use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, Platform};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES: &[(&str, &str, &[u32], &[&str])] = &[
    ("narrow_signed_char", "int4 narrow_signed_char(int1 value);", &[0x11001c00, 0xd65f03c0], &["addw0,w0,#7", "ret"]),
    (
        "narrow_signed_short",
        "int4 narrow_signed_short(int2 value);",
        &[0x11001c00, 0xd65f03c0],
        &["addw0,w0,#7", "ret"],
    ),
    (
        "narrow_unsigned_char",
        "uint4 narrow_unsigned_char(uint1 value);",
        &[0x11001c00, 0xd65f03c0],
        &["addw0,w0,#7", "ret"],
    ),
    (
        "narrow_unsigned_short",
        "uint4 narrow_unsigned_short(uint2 value);",
        &[0x11001c00, 0xd65f03c0],
        &["addw0,w0,#7", "ret"],
    ),
    (
        "narrow_signed_char_u32",
        "uint8 narrow_signed_char_u32(int1 value);",
        &[0x2a0003e0, 0xd65f03c0],
        &["movw0,w0", "ret"],
    ),
    (
        "narrow_signed_short_u32",
        "uint8 narrow_signed_short_u32(int2 value);",
        &[0x2a0003e0, 0xd65f03c0],
        &["movw0,w0", "ret"],
    ),
    ("narrow_signed_int", "int4 narrow_signed_int(int4 value);", &[0x11001c00, 0xd65f03c0], &["addw0,w0,#7", "ret"]),
    (
        "narrow_unsigned_int",
        "uint4 narrow_unsigned_int(uint4 value);",
        &[0x11001c00, 0xd65f03c0],
        &["addw0,w0,#7", "ret"],
    ),
    ("narrow_signed_long", "int8 narrow_signed_long(int8 value);", &[0x91001c00, 0xd65f03c0], &["addx0,x0,#7", "ret"]),
    ("narrow_pair", "int4 narrow_pair(int1 first, int2 second);", &[0x0b000020, 0xd65f03c0], &["addw0,w1,w0", "ret"]),
    (
        "narrow_fixed_stack",
        concat!(
            "int4 narrow_fixed_stack(int8 a, int8 b, int8 c, int8 d, ",
            "int8 e, int8 f, int8 g, int8 h, int1 first, int2 second);",
        ),
        &[0x39c003e8, 0x79c007e9, 0x0b080120, 0xd65f03c0],
        &["ldrsbw8,[sp]", "ldrshw9,[sp,#2]", "addw0,w9,w8", "ret"],
    ),
];

const C_TYPES: &str = r#"
#include <stdbool.h>
#include <stdint.h>
typedef signed char int1;
typedef unsigned char uint1;
typedef short int2;
typedef unsigned short uint2;
typedef int int4;
typedef unsigned int uint4;
typedef long int8;
typedef unsigned long uint8;
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
"#;

struct TemporaryFixtures {
    directory: PathBuf,
    files: Vec<PathBuf>,
}

impl TemporaryFixtures {
    fn new(scope: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("darwin_narrow_{scope}_{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        Self { directory, files: Vec::new() }
    }

    fn file(&mut self, name: &str) -> PathBuf {
        let path = self.directory.join(name);
        self.files.push(path.clone());
        path
    }
}

impl Drop for TemporaryFixtures {
    fn drop(&mut self) {
        for path in &self.files {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(command: &mut Command, description: &str) -> Output {
    let output = command.output().unwrap_or_else(|error| panic!("{description}: {error}"));
    assert!(
        output.status.success(),
        "{description}: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn instructions(assembly: &str, name: &str) -> Vec<String> {
    let label = format!("_{name}:");
    let mut lines = assembly.lines().skip_while(|line| !line.trim_start().starts_with(&label));
    assert!(lines.next().is_some(), "Missing compiler oracle for {name}:\n{assembly}");
    lines
        .take_while(|line| !line.trim_start().starts_with(".cfi_endproc"))
        .filter_map(|line| {
            let instruction = line.split(';').next().unwrap().trim();
            if instruction.is_empty() || instruction.starts_with('.') || instruction.ends_with(':') {
                None
            } else {
                Some(instruction.chars().filter(|character| !character.is_ascii_whitespace()).collect())
            }
        })
        .collect()
}

fn canonical_instruction(instruction: &str) -> String {
    let operands: Vec<_> = instruction.split(',').collect();
    if let [destination, left, right] = operands.as_slice()
        && destination.starts_with("add")
        && (left.starts_with('w') || left.starts_with('x'))
        && (right.starts_with('w') || right.starts_with('x'))
    {
        return format!("{destination},{},{}", left.min(right), left.max(right));
    }
    instruction.replace(",#0]", "]")
}

fn generate_oracle(source: &Path, assembly_path: &Path, ir_path: &Path) -> (String, String) {
    for (path, emit_ir) in [(assembly_path, false), (ir_path, true)] {
        let mut command = Command::new("clang");
        command.args(["-target", "arm64-apple-macos11", "-std=c11", "-O2", "-fno-stack-protector", "-S"]);
        if emit_ir {
            command.arg("-emit-llvm");
        }
        run(command.arg(source).arg("-o").arg(path), "Generate the independent Apple compiler oracle");
    }
    let assembly = std::fs::read_to_string(assembly_path).unwrap();
    let ir = std::fs::read_to_string(ir_path).unwrap();
    println!("Independent Apple compiler assembly:\n{assembly}\nIndependent Apple LLVM IR:\n{ir}");
    (assembly, ir)
}

fn check_caller_oracle(assembly: &str, ir: &str) {
    for (caller, extension) in [("narrow_call_signed_char", "sxtbw0,w0"), ("narrow_call_signed_short", "sxthw0,w0")] {
        assert!(instructions(assembly, caller).iter().any(|instruction| instruction == extension), "{assembly}");
    }
    for (caller, mask) in [("narrow_call_unsigned_char", "0xff"), ("narrow_call_unsigned_short", "0xffff")] {
        let extension = format!("andw0,w0,#{mask}");
        let decimal = u32::from_str_radix(mask.trim_start_matches("0x"), 16).unwrap();
        let decimal_extension = format!("andw0,w0,#{decimal}");
        assert!(
            instructions(assembly, caller)
                .iter()
                .any(|instruction| instruction == &extension || instruction == &decimal_extension),
            "{assembly}",
        );
    }
    for (callee, integer_type, extension) in [
        ("narrow_signed_char", "i8", "signext"),
        ("narrow_signed_short", "i16", "signext"),
        ("narrow_unsigned_char", "i8", "zeroext"),
        ("narrow_unsigned_short", "i16", "zeroext"),
    ] {
        let target = format!("@{callee}(");
        let call = ir.lines().find(|line| line.contains("call ") && line.contains(&target)).unwrap();
        assert!(call.contains(integer_type) && call.contains(extension), "{call}");
    }
    let call = ir.lines().find(|line| line.contains("call ") && line.contains("@narrow_variadic(")).unwrap();
    let arguments = call.split_once("@narrow_variadic(").unwrap().1;
    assert_eq!(arguments.matches("i32").count(), 3, "C-promoted variadic arguments: {call}");
    assert!(!arguments.contains("i8") && !arguments.contains("i16"), "{call}");
}

fn decompile(name: &str, prototype: &str, words: &[u32]) -> String {
    let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let regions = [MemoryRegion {
        base: 0x1000,
        bytes: &bytes,
        size: bytes.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    }];
    let options = DecompilerOptions { platform: Platform::Darwin, ..Default::default() };
    let mut engine = Decompiler::open_with_options(Arch::Aarch64, false, &regions, &options).unwrap();
    assert!(engine.language_id().ends_with(":apple"));
    engine.set_symbol(0x1000, name).unwrap();
    engine.apply_prototype(0x1000, false, prototype).unwrap();
    engine.decompile(0x1000, name, false).unwrap()
}

fn compile_source_oracle(callee: &Path, caller: &Path, executable: &Path) {
    run(
        Command::new("cc").args(["-std=c11", "-O2", "-fsigned-char"]).arg(callee).arg(caller).arg("-o").arg(executable),
        "Compile the independent owned C source oracle",
    );
}

#[test]
fn darwin_fixed_narrow_input_embedded_c_matches_source_arithmetic() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let callee = root.join("tests/fixtures/narrow_callee.c");
    let caller = root.join("tests/fixtures/narrow_caller.c");
    let mut temporary = TemporaryFixtures::new("arithmetic");
    let assembly_path = temporary.file("narrow_callee.s");
    let ir_path = temporary.file("narrow_callee.ll");
    let caller_assembly_path = temporary.file("narrow_abi_caller.s");
    let caller_ir_path = temporary.file("narrow_abi_caller.ll");
    let oracle_path = temporary.file("narrow_source_oracle");
    let recovered_path = temporary.file("narrow_recovered");
    let recovered_c_path = temporary.file("narrow_recovered.c");

    let (assembly, _) = generate_oracle(&callee, &assembly_path, &ir_path);
    let (caller_assembly, caller_ir) =
        generate_oracle(&root.join("tests/fixtures/narrow_abi_caller.c"), &caller_assembly_path, &caller_ir_path);
    check_caller_oracle(&caller_assembly, &caller_ir);
    for &(name, _, _, expected_instructions) in FIXTURES {
        assert_eq!(
            instructions(&assembly, name)
                .iter()
                .map(|instruction| canonical_instruction(instruction))
                .collect::<Vec<_>>(),
            expected_instructions.iter().map(|instruction| canonical_instruction(instruction)).collect::<Vec<_>>(),
            "The deterministic bytes need revalidation against the compiler oracle for {name}",
        );
    }

    compile_source_oracle(&callee, &caller, &oracle_path);
    let oracle = run(&mut Command::new(&oracle_path), "Validate source-derived arithmetic before testing Ghidra");
    println!("Independent owned source arithmetic:\n{}", String::from_utf8_lossy(&oracle.stdout));

    let mut recovered_c = String::from(C_TYPES);
    for &(name, prototype, words, _) in FIXTURES {
        let code = decompile(name, prototype, words);
        println!("Actual embedded-Ghidra C for {name}:\n{code}");
        recovered_c.push_str(&code);
        recovered_c.push('\n');
    }
    std::fs::write(&recovered_c_path, &recovered_c).unwrap();
    run(
        Command::new("cc")
            .args(["-std=c11", "-O2", "-fsigned-char", "-DNARROW_ORACLE", "-DNARROW_COMPARE_DECOMPILED"])
            .arg(&callee)
            .arg(&caller)
            .arg(&recovered_c_path)
            .arg("-o")
            .arg(&recovered_path),
        &format!("Compile emitted C without rewriting its arithmetic:\n{recovered_c}"),
    );
    let comparison = run(
        &mut Command::new(&recovered_path),
        &format!("Compare actual embedded-Ghidra C arithmetic with the independent source oracle:\n{recovered_c}"),
    );
    println!("Embedded-Ghidra arithmetic comparison:\n{}", String::from_utf8_lossy(&comparison.stdout));
}

#[test]
fn darwin_narrow_extension_window_preserves_unknown_upper_bits_and_legacy_models() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut temporary = TemporaryFixtures::new("engine");
    let executable = temporary.file("narrow_engine");
    run(
        Command::new("c++")
            .arg("-std=c++14")
            .arg("-I")
            .arg(root.join("vendor/ghidra"))
            .arg(root.join("tests/fixtures/narrow_engine.cc"))
            .arg(PathBuf::from(env!("OUT_DIR")).join("librampage_ghidra.a"))
            .arg("-lz")
            .arg("-o")
            .arg(&executable),
        "Compile the owned embedded-Ghidra input window regression",
    );
    let caller_assembly_path = temporary.file("narrow_call_storage.s");
    let caller_ir_path = temporary.file("narrow_call_storage.ll");
    let (caller_assembly, _) =
        generate_oracle(&root.join("tests/fixtures/narrow_abi_caller.c"), &caller_assembly_path, &caller_ir_path);
    let fixture_assembly = run(
        Command::new(&executable).arg("--caller-assembly"),
        "Read the owned literal call-storage instruction fixture",
    );
    let fixture_assembly = String::from_utf8(fixture_assembly.stdout).unwrap();
    assert_eq!(
        instructions(&caller_assembly, "narrow_call_small_return"),
        fixture_assembly.lines().map(str::to_owned).collect::<Vec<_>>(),
        "Call-storage fixture differs from the independent compiler caller assembly",
    );
    let output =
        run(Command::new(&executable).arg(root.join("specs")), "Validate the bounded input extension contract");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

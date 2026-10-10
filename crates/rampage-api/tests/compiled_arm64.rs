#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod arm64 {
    use rampage_api::Project;
    use rampage_arch::ir::{self, Effect, LiftedInstruction, Value};
    use rampage_loaders::Binary;

    struct Fixture(std::path::PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!("cannot clean compiled fixture {}: {error}", self.0.display());
            }
        }
    }

    fn evaluate(value: &Value, registers: &[u64; 31]) -> u64 {
        match value {
            Value::Constant { value } => *value,
            Value::Register { number } => registers[*number as usize],
            Value::Low32 { value } => evaluate(value, registers) & 0xffff_ffff,
            Value::Add { left, right } => evaluate(left, registers).wrapping_add(evaluate(right, registers)),
            Value::Subtract { left, right } => evaluate(left, registers).wrapping_sub(evaluate(right, registers)),
            Value::Binary { operation, left, right, bits } => {
                ir::binary(*operation, evaluate(left, registers), evaluate(right, registers), *bits).unwrap()
            }
            Value::StackPointer => panic!("unexpected stack access in straight-line fixture"),
        }
    }

    fn execute(instructions: &[LiftedInstruction], left: u64, right: u64) -> u64 {
        assert!(!instructions.is_empty());
        let mut registers = [0; 31];
        registers[0] = left;
        registers[1] = right;
        let mut flags = 0;
        for instruction in instructions {
            assert!(instruction.complete);
            for effect in &instruction.effects {
                let (destination, value) = match effect {
                    Effect::Assign { destination, value } => (destination, evaluate(value, &registers)),
                    Effect::Select { destination, condition, when_true, when_false } => {
                        let selected = if ir::condition(flags, *condition).unwrap() { when_true } else { when_false };
                        (destination, evaluate(selected, &registers))
                    }
                    Effect::SetFlags { operation, left, right } => {
                        flags = ir::flags(
                            *operation,
                            evaluate(left, &registers),
                            evaluate(right, &registers),
                            instruction.bits,
                        )
                        .unwrap();
                        continue;
                    }
                    Effect::Control { .. } | Effect::Discard { .. } => continue,
                    _ => panic!("unexpected effect in straight-line fixture: {effect:?}"),
                };
                let Value::Register { number } = destination else { panic!("unexpected destination") };
                registers[*number as usize] = if instruction.bits == 32 { value & 0xffff_ffff } else { value };
            }
        }
        registers[0]
    }

    #[test]
    #[ignore = "requires macOS ARM64 clang and a usable SDK; run with --ignored"]
    fn native_compiled_integer_function_lifts_without_semantic_gaps() {
        let allocation = std::process::Command::new("mktemp")
            .arg("-d")
            .arg(std::env::temp_dir().join("rampage-arm64-corpus.XXXXXX"))
            .output()
            .unwrap();
        assert!(allocation.status.success(), "cannot allocate compiled fixture directory");
        let fixture = Fixture(std::path::PathBuf::from(std::str::from_utf8(&allocation.stdout).unwrap().trim()));
        let source = fixture.0.join("fixture.c");
        let executable = fixture.0.join("fixture");
        std::fs::write(
            &source,
            "__attribute__((noinline)) unsigned long sample(unsigned long a, unsigned long b) {\n\
             return (a + (b << 3)) ^ 0xff;\n}\n\
             __attribute__((noinline)) unsigned long choose(unsigned long a) {\n\
             if (a == 0) return 7;\nreturn a + 3;\n}\n\
             int main(void) { return sample(3, 5) != 212 || choose(0) != 7 || choose(5) != 8; }\n",
        )
        .unwrap();
        let output = std::process::Command::new("clang")
            .args(["-O2", "-g"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(std::process::Command::new(&executable).status().unwrap().success());
        let project = Project::new(Binary::open(&executable).unwrap());
        let summary = project.function_summary(project.resolve("_sample").unwrap()).unwrap();
        assert!(summary.ir.iter().all(|instruction| instruction.complete), "{:#?}", summary.graph);
        assert_eq!(summary.graph.blocks.len(), 1);
        for (left, right, expected) in [(3, 5, 212), (0, 0, 255), (u64::MAX, 1, 248)] {
            assert_eq!(execute(&summary.ir, left, right), expected);
        }
        assert!(summary.dataflow.is_some());
        assert!(summary.pseudocode.is_some());
        assert!(summary.structured_control.is_some());
        let choose = project.function_summary(project.resolve("_choose").unwrap()).unwrap();
        assert!(choose.ir.iter().all(|instruction| instruction.complete), "{:#?}", choose.graph);
        assert_eq!(choose.graph.blocks.len(), 1);
        assert!(
            choose
                .ir
                .iter()
                .flat_map(|instruction| &instruction.effects)
                .any(|effect| matches!(effect, Effect::Select { .. }))
        );
        for (left, expected) in [(0, 7), (5, 8), (u64::MAX, 2)] {
            assert_eq!(execute(&choose.ir, left, 0), expected);
        }
    }
}

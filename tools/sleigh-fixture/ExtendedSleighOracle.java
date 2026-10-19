/* SPDX-License-Identifier: Apache-2.0 */
import com.google.gson.GsonBuilder;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.util.PseudoDisassembler;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.util.*;

public class ExtendedSleighOracle extends SleighOracle {
    record Owned(String name, String language, long base, String hex, int callee,
                 int mainEnd, int[] starts) {}
    static final Owned[] OWNED = {
        new Owned("8051-v1", "8051:BE:16:default", 0x1000, "1210080070fa22000022", 8, 7,
            new int[]{0,3,4,6,7,8,9}),
        new Owned("PIC-v1", "PIC-16:LE:16:PIC-16", 0x200,
            "08210000201c0000080000000000000000000800", 16, 10,
            new int[]{0,2,4,6,8,10,12,14,16,18}),
        new Owned("SuperH-v1", "SuperH:BE:32:SH-2", 0x1000,
            "b006000989fc000b00090009000900090009000b0009", 16, 10,
            new int[]{0,2,4,6,8,10,12,14,16,18,20}),
        new Owned("V850-v1", "V850:LE:32:default", 0x1000,
            "80ff10000000dafd7f0000000000000000007f00", 16, 10,
            new int[]{0,4,6,8,10,12,14,16,18}),
        new Owned("TriCore-v1", "tricore:LE:32:default", 0x1000,
            "5c080000eefe0090000000000000000000000090", 16, 8,
            new int[]{0,2,4,6,8,10,12,14,16,18}),
        new Owned("Xtensa-v1", "Xtensa:LE:32:default", 0x4000,
            "c50000f020003792f60df03df0f020003df00df0", 16, 11,
            new int[]{0,3,6,9,11,13,16,18}),
        new Owned("Z80-v1", "z80:LE:16:default", 0x4000, "cd08400020fac90000c9", 8, 7,
            new int[]{0,3,4,6,7,8,9}),
        new Owned("HCS12-v1", "HCS-12:BE:24:default", 0x2000, "0706a726fb3da7a7a73d", 8, 6,
            new int[]{0,2,3,5,6,7,8,9}),
        new Owned("6805-v1", "6805:BE:16:default", 0x1000, "cd10089d26fa819d9d81", 8, 7,
            new int[]{0,3,4,6,7,8,9}),
        new Owned("CR16-v1", "CR16C:LE:16:default", 0x1000,
            "00c01000002c1d1fee0a002c002c002c002cee0a", 16, 10,
            new int[]{0,4,6,8,10,12,14,16,18}),
        new Owned("eBPF-v1", "eBPF:LE:64:default", 0x1000,
            "8510000003000000b7000000000000001500fdff000000009500000000000000b7000000000000009500000000000000",
            32, 32, new int[]{0,8,16,24,32,40}),
        new Owned("Loongarch-v1", "Loongarch:LE:64:lp64d", 0x1000,
            "001000540000400320f8ff5f2000004c000040032000004c", 16, 16,
            new int[]{0,4,8,12,16,20}),
        new Owned("Hexagon-v1", "Hexagon:LE:32:default", 0x1000,
            "08c0005a00c0007ffce0df5c00c09f5200c0007f00c09f52", 16, 16,
            new int[]{0,4,8,12,16,20})
    };

    static byte[] readOwned(Path path) throws Exception {
        require(!Files.isSymbolicLink(path) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
            "regular owned bytes required");
        require(Files.size(path) <= 128, "owned fixture pre-read size cap");
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = input.readNBytes(129);
            require(bytes.length <= 128, "owned fixture read cap");
            return bytes;
        }
    }

    static Object context(Program program, Address at) {
        List<Object> values = new ArrayList<>();
        List<Register> registers = program.getLanguage().getContextRegisters();
        require(registers.size() <= 64, "context register count cap");
        for (Register register : registers) {
            RegisterValue value = program.getProgramContext().getRegisterValue(register, at);
            values.add(map("register", register.getName(), "value", value == null ? null
                : bounded(value.toString())));
        }
        return values;
    }

    static Map<String, Object> describe(Instruction instruction, Address base, int available) {
        int length = instruction.getLength();
        require(length > 0 && length <= 32, "32-byte prototype cap");
        require(length <= available, "prototype exceeds backed byte suffix");
        var flow = instruction.getFlowType();
        List<Object> targets = new ArrayList<>();
        for (Address target : instruction.getFlows()) targets.add(address(target));
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            operands.add(bounded(instruction.getDefaultOperandRepresentation(i)));
        }
        Map<String, Object> row = map("status", "decoded", "address", address(instruction.getAddress()),
            "fixture_offset_bytes", instruction.getAddress().subtract(base), "length_bytes", length,
            "mnemonic", bounded(instruction.getMnemonicString()), "operands", operands,
            "flow", map("name", flow.toString(), "is_call", flow.isCall(), "is_jump", flow.isJump(),
                "is_conditional", flow.isConditional(), "is_computed", flow.isComputed(),
                "is_terminal", flow.isTerminal()),
            "delay_slot_depth", instruction.getDelaySlotDepth(), "is_in_delay_slot", instruction.isInDelaySlot(),
            "direct_flow_targets", targets, "fallthrough", address(instruction.getFallThrough()));
        try { row.put("raw_pcode", pcode(instruction)); }
        catch (Exception error) {
            row.put("pcode_status", "technical_failure");
            row.put("pcode_error", bounded(error.getClass().getName() + ": " + error.getMessage()));
        }
        return row;
    }

    static Object analyze(Owned owned, byte[] bytes, List<Object> standalone) throws Exception {
        Language language = SleighLanguageProvider.getSleighLanguageProvider()
            .getLanguage(new LanguageID(owned.language()));
        require(language != null, "selected language unavailable");
        CompilerSpec compiler = language.getCompilerSpecByID(new CompilerSpecID("default"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("owned-extended-" + owned.name(), language, compiler, consumer);
        try {
            int tx = program.startTransaction("Owned extended static oracle");
            try {
                Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(owned.base());
                MemoryBlock block = program.getMemory().createInitializedBlock("owned_code", base,
                    new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                block.setRead(true);
                block.setWrite(false);
                PseudoDisassembler pseudo = new PseudoDisassembler(program);
                pseudo.setMaxInstructions(32);
                for (int offset : owned.starts()) {
                    try {
                        var instruction = pseudo.disassemble(base.addNoWrap(offset),
                            Arrays.copyOfRange(bytes, offset, bytes.length));
                        standalone.add(describe(instruction, base, bytes.length - offset));
                    }
                    catch (Exception error) {
                        standalone.add(map("fixture_offset_bytes", offset, "status", "technical_failure",
                            "error", bounded(error.getClass().getName() + ": " + error.getMessage())));
                    }
                }
                AddressSet window = new AddressSet(base, base.addNoWrap(bytes.length - 1));
                List<String> messages = new ArrayList<>();
                Disassembler disassembler = Disassembler.getDisassembler(program, false, false, true,
                    TaskMonitor.DUMMY, message -> {
                        require(messages.size() < 128, "diagnostic count cap");
                        messages.add(bounded(message));
                    });
                for (int seed : new int[]{0, owned.callee()}) {
                    disassembler.disassemble(base.addNoWrap(seed), window, true);
                }
                List<Long> initiallyReachable = new ArrayList<>();
                for (Instruction instruction : program.getListing().getInstructions(true)) {
                    initiallyReachable.add(instruction.getAddress().subtract(base));
                }
                List<Object> functions = new ArrayList<>();
                for (int seed : new int[]{0, owned.callee()}) {
                    try {
                        CreateFunctionCmd command = new CreateFunctionCmd(base.addNoWrap(seed));
                        require(command.applyTo(program, TaskMonitor.DUMMY), "CreateFunctionCmd refused seed");
                        Function function = command.getFunction();
                        List<Object> ranges = new ArrayList<>();
                        for (AddressRange range : function.getBody().getAddressRanges()) {
                            require(ranges.size() < 32, "function range cap");
                            ranges.add(map("start", address(range.getMinAddress()),
                                "end_inclusive", address(range.getMaxAddress())));
                        }
                        functions.add(map("manual_seed_offset_bytes", seed, "status", "created",
                            "entry", address(function.getEntryPoint()), "body_ranges", ranges));
                    }
                    catch (Exception error) {
                        functions.add(map("manual_seed_offset_bytes", seed, "status", "technical_failure",
                            "error", bounded(error.getClass().getName() + ": " + error.getMessage())));
                    }
                }
                for (int seed : owned.starts()) disassembler.disassemble(base.addNoWrap(seed), window, true);
                List<Object> rows = new ArrayList<>();
                int noise = 0;
                for (Instruction instruction : program.getListing().getInstructions(true)) {
                    require(rows.size() < 32, "instruction count cap");
                    long offset = instruction.getAddress().subtract(base);
                    if (offset >= owned.mainEnd() && offset < owned.callee()) noise++;
                    try {
                        var row = describe(instruction, base, bytes.length - (int) offset);
                        row.put("context_trace", context(program, instruction.getAddress()));
                        rows.add(row);
                    }
                    catch (Exception error) {
                        rows.add(map("fixture_offset_bytes", offset, "status", "technical_failure",
                            "error", bounded(error.getClass().getName() + ": " + error.getMessage())));
                    }
                }
                return map("status", "observed", "language_id", owned.language(), "compiler_spec_id", "default",
                    "base", address(base), "window_end_exclusive", address(base.addNoWrap(bytes.length)),
                    "memory_space", base.getAddressSpace().getName(), "byte_backed", true,
                    "execute", block.isExecute(), "overlay", block.isOverlay(), "rows", rows,
                    "functions", functions, "messages", messages,
                    "initial_flow_instruction_offsets", initiallyReachable,
                    "observed_function_count", program.getFunctionManager().getFunctionCount(),
                    "padding_instruction_count", noise, "all_instruction_count", rows.size());
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(consumer); }
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 3, "fixed owned profile key, fixture directory and new output required");
        Owned owned = Arrays.stream(OWNED).filter(item -> item.name().equals(args[0])).findFirst().orElseThrow();
        byte[] bytes = readOwned(Path.of(args[1]).resolve(owned.name() + ".bin"));
        require(Arrays.equals(bytes, HexFormat.of().parseHex(owned.hex())), "fixed hand-owned bytes differ");
        ApplicationConfiguration config = new ApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(SDK.toFile()), config);
        require(Application.getApplicationVersion().equals("12.1.4"), "unsupported SDK");
        List<Object> standalone = new ArrayList<>();
        Map<String, Object> result = map("schema_version", 1, "fixture", owned.name(),
            "language_id", owned.language(), "target_execution", false, "decompilation", false,
            "standalone_context_origin", "program default context before flowed disassembly",
            "standalone_rows", standalone);
        try { result.put("program_oracle", analyze(owned, bytes, standalone)); }
        catch (Throwable error) {
            error.printStackTrace(System.err);
            result.put("program_oracle", map("status", "technical_failure", "error",
                bounded(error.getClass().getName() + ": " + error.getMessage())));
        }
        require(Arrays.equals(bytes, readOwned(Path.of(args[1]).resolve(owned.name() + ".bin"))),
            "owned bytes changed during oracle");
        String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create()
            .toJson(result) + "\n";
        require(json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 4 * 1024 * 1024, "result cap");
        Files.writeString(Path.of(args[2]), json, StandardOpenOption.CREATE_NEW);
    }
}

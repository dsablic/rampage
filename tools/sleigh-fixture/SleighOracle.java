/* SPDX-License-Identifier: Apache-2.0 */
import com.google.gson.GsonBuilder;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class SleighOracle {
    static final Path SDK = Path.of("/opt/homebrew/opt/ghidra/libexec");
    record Fixture(String name, String language, String compiler, long base, String hex, int[] starts) {}
    static final Fixture[] FIXTURES = {
        new Fixture("msp430", "TI_MSP430:LE:16:default", "default", 0x4400,
            "b01210440343fc233041304020440343145330418512004630400044b012",
            new int[]{0, 4, 6, 8, 10, 14, 16, 18, 20, 22, 24, 28}),
        new Fixture("avr8", "avr8:LE:16:default", "gcc", 0x200,
            "0e9408010000e1f708950ac00995099403950895fccf011000000b94ffff0e94",
            new int[]{0, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}),
        new Fixture("6502", "6502:LE:16:default", "default", 0x8000,
            "201080a901d0f9604c19806c0020eaeae860d0ec4c00800220",
            new int[]{0, 3, 5, 7, 8, 11, 14, 15, 16, 17, 18, 20, 23, 24})
    };

    static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }

    static Map<String, Object> map(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    static String hex(long value) { return "0x" + Long.toUnsignedString(value, 16); }

    static String bounded(String value) {
        require(value.length() <= 512, "text budget exceeded");
        return value;
    }

    static Object address(Address address) {
        if (address == null) return null;
        AddressSpace space = address.getAddressSpace();
        Map<String, Object> result = map("display", bounded(address.toString(true)), "space", space.getName(),
            "getOffset_raw", hex(address.getOffset()),
            "getAddressableWordOffset_raw", hex(address.getAddressableWordOffset()),
            "addressableUnitSize_bytes", space.getAddressableUnitSize());
        if (address.isMemoryAddress()) {
            result.put("getOffset_bytes", hex(address.getOffset()));
            result.put("getAddressableWordOffset_words", hex(address.getAddressableWordOffset()));
        }
        else result.put("offset_semantics", address.isConstantAddress() ? "constant scalar, not a byte address"
            : "non-memory storage-space offset");
        return result;
    }

    static Object varnode(Varnode node) {
        if (node == null) return null;
        return map("address", address(node.getAddress()), "size_bytes", node.getSize(),
            "is_constant", node.isConstant(), "is_register", node.isRegister(),
            "is_unique", node.isUnique());
    }

    static List<Object> pcode(Instruction instruction) {
        PcodeOp[] operations = instruction.getPcode();
        require(operations.length <= 128, "pcode budget");
        List<Object> result = new ArrayList<>();
        for (PcodeOp op : operations) {
            List<Object> inputs = new ArrayList<>();
            for (Varnode input : op.getInputs()) inputs.add(varnode(input));
            result.add(map("sequence_time", op.getSeqnum().getTime(),
                "opcode", op.getOpcode(), "mnemonic", op.getMnemonic(),
                "text", bounded(op.toString()), "output", varnode(op.getOutput()), "inputs", inputs));
        }
        return result;
    }

    static Object programOracle(Fixture fixture, Language language, CompilerSpec compiler, byte[] bytes)
            throws Exception {
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("owned-" + fixture.name(), language, compiler, consumer);
        try {
            int transaction = program.startTransaction("Owned static disassembly");
            try {
                Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(fixture.base());
                MemoryBlock block = program.getMemory().createInitializedBlock("owned_code", base,
                    new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                block.setRead(true);
                block.setWrite(false);
                int validLength = fixture.name().equals("6502") ? 23 : 28;
                AddressSet valid = new AddressSet(base, base.addNoWrap(validLength - 1));
                List<String> messages = new ArrayList<>();
                Disassembler disassembler = Disassembler.getDisassembler(program, false, false, true,
                    TaskMonitor.DUMMY, message -> {
                        require(messages.size() < 128, "diagnostic count budget");
                        messages.add(bounded(message));
                    });
                for (int seed : new int[]{0, 16}) {
                    disassembler.disassemble(base.addNoWrap(seed), valid, true);
                }
                List<Object> functions = new ArrayList<>();
                for (int seed : new int[]{0, 16}) {
                    CreateFunctionCmd command = new CreateFunctionCmd(base.addNoWrap(seed));
                    require(command.applyTo(program, TaskMonitor.DUMMY), "function creation failed");
                    Function function = command.getFunction();
                    List<Object> ranges = new ArrayList<>();
                    for (AddressRange range : function.getBody().getAddressRanges()) {
                        ranges.add(map("start", address(range.getMinAddress()),
                            "end_inclusive", address(range.getMaxAddress())));
                    }
                    functions.add(map("manual_seed_offset_bytes", seed, "entry", address(function.getEntryPoint()),
                        "body_ranges", ranges));
                }
                for (int seed : fixture.starts()) {
                    if (seed < validLength) disassembler.disassemble(base.addNoWrap(seed), valid, true);
                }
                List<Object> rows = new ArrayList<>();
                for (Instruction instruction : program.getListing().getInstructions(true)) {
                    require(rows.size() < 32, "program instruction budget");
                    require(instruction.getLength() <= 32, "program instruction length budget");
                    List<Object> targets = new ArrayList<>();
                    for (Address target : instruction.getFlows()) targets.add(address(target));
                    rows.add(map("fixture_offset_bytes", instruction.getAddress().subtract(base),
                        "address", address(instruction.getAddress()), "length_bytes", instruction.getLength(),
                        "mnemonic", instruction.getMnemonicString(), "flow_name", instruction.getFlowType().toString(),
                        "direct_flow_targets", targets, "fallthrough", address(instruction.getFallThrough()),
                        "raw_pcode", pcode(instruction)));
                }
                return map("memory_space", base.getAddressSpace().getName(), "execute", block.isExecute(),
                    "byte_backed", true, "overlay", block.isOverlay(),
                    "manual_function_seeds_only", true, "functions", functions,
                    "rows", rows, "messages", messages);
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(consumer); }
    }

    static Map<String, Object> instruction(Language language, byte[] bytes, Address base, int offset)
            throws Exception {
        Address at = base.addNoWrap(offset);
        Map<String, Object> row = map("fixture_offset_bytes", offset, "address", address(at),
            "available_bytes", bytes.length - offset);
        byte[] remaining = Arrays.copyOfRange(bytes, offset, bytes.length);
        ByteMemBufferImpl buffer = new ByteMemBufferImpl(at, remaining, language.isBigEndian());
        ProcessorContextImpl context = new ProcessorContextImpl(language);
        try {
            InstructionPrototype prototype = language.parse(buffer, context, false);
            PseudoInstruction instruction = new PseudoInstruction(language.getAddressFactory(), at,
                prototype, buffer, context);
            int length = instruction.getLength();
            require(length > 0 && length <= 32, "instruction budget at " + at);
            if (length > remaining.length) {
                row.putAll(map("status", "rejected_unbacked_instruction", "parsed_length_bytes", length,
                    "reason", "Java parser length exceeds available owned bytes; no pcode requested"));
                return row;
            }
            FlowType flow = instruction.getFlowType();
            List<Object> targets = new ArrayList<>();
            for (Address target : instruction.getFlows()) targets.add(address(target));
            List<String> operands = new ArrayList<>();
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                operands.add(bounded(instruction.getDefaultOperandRepresentation(i)));
            }
            row.putAll(map("status", "decoded", "length_bytes", length,
                "bytes_hex", HexFormat.of().formatHex(remaining, 0, length),
                "mnemonic", bounded(instruction.getMnemonicString()), "operands", operands,
                "flow", map("name", flow.toString(), "is_call", flow.isCall(),
                    "is_jump", flow.isJump(), "is_conditional", flow.isConditional(),
                    "is_computed", flow.isComputed(), "is_terminal", flow.isTerminal()),
                "direct_flow_targets", targets, "fallthrough", address(instruction.getFallThrough())));
            row.put("raw_pcode", pcode(instruction));
        }
        catch (InsufficientBytesException | UnknownInstructionException error) {
            row.put("status", "decode_error");
            row.put("exception", error.getClass().getSimpleName());
            row.put("message", bounded(String.valueOf(error.getMessage())));
        }
        return row;
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 2, "fixed fixture directory and new output path required");
        ApplicationConfiguration config = new ApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(SDK.toFile()), config);
        require(Application.getApplicationVersion().equals("12.1.4"), "unexpected SDK version");
        List<Object> fixtures = new ArrayList<>();
        for (Fixture fixture : FIXTURES) {
            Path input = Path.of(args[0]).resolve(fixture.name() + ".bin");
            require(!Files.isSymbolicLink(input) && Files.isRegularFile(input), "regular owned input required");
            require(Files.size(input) <= 128, "fixture byte budget");
            byte[] bytes = Files.readAllBytes(input);
            require(Arrays.equals(bytes, HexFormat.of().parseHex(fixture.hex())), "owned bytes differ");
            Language language = SleighLanguageProvider.getSleighLanguageProvider()
                .getLanguage(new LanguageID(fixture.language()));
            require(language != null, "selected language unavailable");
            CompilerSpec compiler = language.getCompilerSpecByID(new CompilerSpecID(fixture.compiler()));
            Address base = language.getDefaultSpace().getAddress(fixture.base());
            List<Object> rows = new ArrayList<>();
            require(fixture.starts().length <= 32, "instruction row budget");
            for (int offset : fixture.starts()) rows.add(instruction(language, bytes, base, offset));
            require(Arrays.equals(bytes, Files.readAllBytes(input)), "input changed during oracle");
            fixtures.add(map("name", fixture.name(), "language_id", language.getLanguageID().toString(),
                "language_version", language.getVersion(), "language_minor_version", language.getMinorVersion(),
                "compiler_spec_id", compiler.getCompilerSpecID().toString(), "base", address(base),
                "window_end_exclusive", address(base.addNoWrap(bytes.length)), "byte_length", bytes.length,
                "input_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                "rows", rows, "program_oracle", programOracle(fixture, language, compiler, bytes)));
        }
        String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create()
            .toJson(map("schema_version", 1, "oracle", "Ghidra Java Language.parse + PseudoInstruction",
                "ghidra_version", Application.getApplicationVersion(), "target_execution", false,
                "decompilation", false, "fixtures", fixtures));
        require(json.length() <= 4 * 1024 * 1024, "output budget");
        Files.writeString(Path.of(args[1]), json + "\n", StandardOpenOption.CREATE_NEW);
    }
}

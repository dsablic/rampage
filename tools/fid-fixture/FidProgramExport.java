/* SPDX-License-Identifier: Apache-2.0
 * Owned trusted-host Ghidra script. Only static analysis is performed; the imported executable
 * is never launched. Hashes come from Ghidra's actual FidService, including its instruction skippers.
 * Relation traversal and terminator semantics adapted from Ghidra 12.1.4, IP: GHIDRA,
 * FidServiceLibraryIngest.java (Apache-2.0), URL recorded in the owned fixture provenance.
 */
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.framework.options.Options;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.framework.Application;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import db.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class FidProgramExport extends HeadlessScript {
    static final int MAX_FUNCTIONS = 100000;
    static final int MAX_RANGES = 4096;
    static final int MAX_EDGES = 1000000;
    static final long MAX_OUTPUT = 128L << 20;
    static final String PROFILE = "ghidra-12.1.4-x86-elf-minimal-v1";
    static final Set<String> ANALYZERS = Set.of(
        "ghidra.app.plugin.core.disassembler.EntryPointAnalyzer",
        "ghidra.app.plugin.core.function.ExternalEntryFunctionAnalyzer",
        "ghidra.app.plugin.core.function.FunctionAnalyzer",
        "ghidra.app.plugin.core.function.CreateThunkAnalyzer"
    );
    Map<Function, FidHashQuad> hashes = new LinkedHashMap<>();
    Map<Function, Set<Function>> children = new LinkedHashMap<>();
    Map<Function, Boolean> terminators = new LinkedHashMap<>();

    void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    void text(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= 4096, "text budget");
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    boolean terminator(Function function) throws Exception {
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            if (instructions.next().getFlowType().isTerminal()) return true;
        }
        return false;
    }

    // The launcher MUST use -noanalysis. A missing/failed script can never fall back to default
    // analysis. HeadlessAnalyzer.analyzeProgram gates both default and post-script analysis on that
    // flag. Only these in-memory disassembly/function analyzers are enabled before startAnalysis.
    // Audited pinned sources: Features/Base/.../{disassembler/EntryPointAnalyzer,
    // function/ExternalEntryFunctionAnalyzer,FunctionAnalyzer,CreateThunkAnalyzer}.java.
    void prepareAndAnalyze(int seconds) throws Exception {
        require(Application.getApplicationVersion().equals("12.1.4"), "unsupported Ghidra host version");
        require(currentProgram.getExecutableFormat().equals("Executable and Linking Format (ELF)"),
            "unsupported executable format");
        require(seconds > 0 && seconds <= 600, "analysis deadline");
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : options.getOptionNames()) {
            Analyzer analyzer = manager.getAnalyzer(name);
            if (analyzer != null) options.setBoolean(name, ANALYZERS.contains(analyzer.getClass().getName()));
        }
        for (String name : new String[]{"Disassemble Entry Points", "Subroutine References",
                "External Entry References"}) {
            require(options.contains(name) && options.getBoolean(name, false), "required analyzer not registered");
        }
        manager.initializeOptions();
        for (String name : options.getOptionNames()) {
            Analyzer analyzer = manager.getAnalyzer(name);
            require(analyzer == null || !options.getBoolean(name, false)
                || ANALYZERS.contains(analyzer.getClass().getName()), "unexpected enabled analyzer");
        }
        TimeoutTaskMonitor timer = TimeoutTaskMonitor.timeoutIn(seconds, TimeUnit.SECONDS, monitor);
        try {
            manager.reAnalyzeAll(null);
            manager.startAnalysis(timer);
            timer.checkCancelled();
        }
        finally { timer.finished(); }
        currentProgram.getOptions(Program.PROGRAM_INFO).setString("Rampage FID Static Profile", PROFILE);
    }

    void collect() throws Exception {
        require(Application.getApplicationVersion().equals("12.1.4"), "unsupported Ghidra host version");
        require(currentProgram.getOptions(Program.PROGRAM_INFO).getString("Rampage FID Static Profile", "")
            .equals(PROFILE), "owned static-analysis controls were not established");
        String language = currentProgram.getLanguageID().getIdAsString();
        require(language.equals("x86:LE:64:default") || language.equals("x86:LE:32:default"),
            "unsupported FID host language profile");
        require(!analysisTimeoutOccurred(), "Ghidra analysis timed out");
        FidService service = new FidService();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int examined = 0;
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            require(++examined <= MAX_FUNCTIONS, "function budget");
            if (function.isExternal()) continue;
            require(function.getEntryPoint().getAddressSpace().equals(currentProgram.getAddressFactory()
                .getDefaultAddressSpace()), "unsupported overlay or non-default function space");
            require(function.getBody().getNumAddressRanges() <= MAX_RANGES, "body range budget");
            FidHashQuad hash = service.hashFunction(function);
            if (hash == null) continue;
            hashes.put(function, hash);
            terminators.put(function, terminator(function));
        }
        int edges = 0;
        for (Function function : hashes.keySet()) {
            Set<Function> targets = new LinkedHashSet<>();
            ReferenceManager references = currentProgram.getReferenceManager();
            AddressIterator sources = references.getReferenceSourceIterator(function.getBody(), true);
            while (sources.hasNext()) {
                monitor.checkCancelled();
                Address source = sources.next();
                Instruction instruction = currentProgram.getListing().getInstructionAt(source);
                if (instruction == null || !instruction.getFlowType().isCall()) continue;
                for (Reference reference : references.getReferencesFrom(source)) {
                    require(++edges <= MAX_EDGES, "call reference budget");
                    Function target = currentProgram.getFunctionManager()
                        .getFunctionContaining(reference.getToAddress());
                    if (target != null && target.isThunk()) target = target.getThunkedFunction(true);
                    if (target != null && hashes.containsKey(target)) targets.add(target);
                }
            }
            children.put(function, targets);
        }
    }

    void features(Path output) throws Exception {
        try (OutputStream file = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            OutputStream bounded = new FilterOutputStream(file) {
                long written;
                @Override public void write(int value) throws IOException {
                    require(++written <= MAX_OUTPUT, "feature output budget");
                    out.write(value);
                }
                @Override public void write(byte[] bytes, int offset, int length) throws IOException {
                    require(length <= MAX_OUTPUT - written, "feature output budget");
                    written += length;
                    out.write(bytes, offset, length);
                }
            };
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(bounded));
            out.writeBytes("RPFPG001");
            out.writeInt(6);
            String sha = currentProgram.getExecutableSHA256();
            require(sha != null && sha.matches("[0-9a-fA-F]{64}"), "source SHA-256 unavailable");
            for (int i = 0; i < 64; i += 2) out.writeByte(Integer.parseInt(sha.substring(i, i + 2), 16));
            text(out, Application.getApplicationVersion());
            text(out, PROFILE);
            text(out, currentProgram.getLanguageID().getIdAsString());
            out.writeInt(currentProgram.getLanguage().getVersion());
            out.writeInt(currentProgram.getLanguage().getMinorVersion());
            text(out, currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
            out.writeInt(hashes.size());
            for (Map.Entry<Function, FidHashQuad> entry : hashes.entrySet()) {
                Function function = entry.getKey();
                FidHashQuad hash = entry.getValue();
                out.writeLong(function.getEntryPoint().getOffset());
                out.writeShort(hash.getCodeUnitSize());
                out.writeLong(hash.getFullHash());
                out.writeByte(hash.getSpecificHashAdditionalSize());
                out.writeLong(hash.getSpecificHash());
                out.writeByte((terminators.get(function) ? 1 : 0) | (function.isThunk() ? 2 : 0));
                out.writeInt(function.getBody().getNumAddressRanges());
                for (AddressRange range : function.getBody().getAddressRanges()) {
                    require(range.getAddressSpace().equals(currentProgram.getAddressFactory()
                        .getDefaultAddressSpace()), "unsupported body address space");
                    long end = range.getMaxAddress().getOffset();
                    require(end != -1L, "body end overflow");
                    out.writeLong(range.getMinAddress().getOffset());
                    out.writeLong(end + 1);
                }
                out.writeInt(children.get(function).size());
                for (Function child : children.get(function)) out.writeLong(child.getEntryPoint().getOffset());
            }
            out.flush();
        }
    }

    // Owned corpus creation only. Uses actual hashes and producer names from the reference binary.
    // Target feature exports NEVER include function names or derive relationships from names.
    void fixture(Path output) throws Exception {
        require(!Files.exists(output, LinkOption.NOFOLLOW_LINKS), "fixture output already exists");
        DBHandle db = new DBHandle();
        try {
            long tx = db.startTransaction();
            Field[][] fields = {
                {StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                 StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE},
                {StringField.INSTANCE},
                {ShortField.INSTANCE, LongField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
                 LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, ByteField.INSTANCE}, {}, {}
            };
            String[][] names = {
                {"Library Family Name", "Library Version", "Library Variant", "Ghidra Version", "Ghidra Language ID",
                 "Ghidra Language Version", "Ghidra Language Minor Version", "Ghidra Compiler Spec ID"},
                {"String Value"},
                {"Code Unit Size", "Full Hash", "Specific Hash Additional Size", "Specific Hash", "Library ID",
                 "Name ID", "Entry Point", "Domain Path ID", "Flags"}, {}, {}
            };
            String[] tables = {"Libraries Table", "Strings Table", "Functions Table", "Inferior Table",
                "Superior Table"};
            String[] keys = {"Library ID", "String ID", "Function ID", "Relation Smash", "Relation Smash"};
            Table[] table = new Table[5];
            for (int i = 0; i < 5; i++) table[i] = db.createTable(tables[i],
                new Schema(6, keys[i], fields[i], names[i]), i == 0 ? new int[]{0, 1}
                    : i == 1 ? new int[]{0} : i == 2 ? new int[]{1, 5} : new int[]{});
            DBRecord library = table[0].getSchema().createRecord(1);
            String[] metadata = {"rampage-owned-ghidra-fid", "1", "host-x86", Application.getApplicationVersion(),
                currentProgram.getLanguageID().getIdAsString()};
            for (int i = 0; i < 5; i++) library.setString(i, metadata[i]);
            library.setIntValue(5, currentProgram.getLanguage().getVersion());
            library.setIntValue(6, currentProgram.getLanguage().getMinorVersion());
            library.setString(7, currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
            table[0].putRecord(library);
            DBRecord path = table[1].getSchema().createRecord(1);
            path.setString(0, "owned-reference-only");
            table[1].putRecord(path);
            Map<Function, Long> ids = new LinkedHashMap<>();
            long next = 2;
            for (Function function : hashes.keySet()) {
                if (!function.getName().startsWith("owned_fid_")) continue;
                long id = next++;
                ids.put(function, id);
                DBRecord name = table[1].getSchema().createRecord(id);
                name.setString(0, function.getName());
                table[1].putRecord(name);
                FidHashQuad hash = hashes.get(function);
                DBRecord record = table[2].getSchema().createRecord(id);
                record.setShortValue(0, hash.getCodeUnitSize());
                record.setLongValue(1, hash.getFullHash());
                record.setByteValue(2, hash.getSpecificHashAdditionalSize());
                record.setLongValue(3, hash.getSpecificHash());
                record.setLongValue(4, 1);
                record.setLongValue(5, id);
                record.setLongValue(6, function.getEntryPoint().getOffset());
                record.setLongValue(7, 1);
                record.setByteValue(8, (byte) ((terminators.get(function) ? 1 : 0)
                    | (children.get(function).isEmpty() ? 0 : 16)));
                table[2].putRecord(record);
            }
            require(!ids.isEmpty(), "owned reference functions not found");
            for (Function caller : ids.keySet()) for (Function callee : children.get(caller)) {
                if (!ids.containsKey(callee)) continue;
                table[3].putRecord(table[3].getSchema().createRecord(ids.get(callee) * 1099511628211L
                    ^ hashes.get(caller).getFullHash()));
                table[4].putRecord(table[4].getSchema().createRecord(ids.get(caller) * 1099511628211L
                    ^ hashes.get(callee).getFullHash()));
            }
            db.endTransaction(tx, true);
            db.saveAs(output.toFile(), false, monitor);
        }
        finally { db.close(); }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 2 || args.length == 3,
            "usage: FidProgramExport.java features|fixture new-output-path [deadline-seconds]");
        prepareAndAnalyze(args.length == 3 ? Integer.parseInt(args[2]) : 90);
        collect();
        if (args[0].equals("features")) features(Path.of(args[1]));
        else if (args[0].equals("fixture")) fixture(Path.of(args[1]));
        else throw new IOException("unsupported export operation");
    }
}

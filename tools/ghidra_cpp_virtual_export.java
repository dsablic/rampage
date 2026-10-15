// SPDX-License-Identifier: Apache-2.0
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.SleighLanguageDescription;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

public class ghidra_cpp_virtual_export extends GhidraScript {
    private static final int LIMIT = 1024 * 1024;
    private static final Gson JSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private int renderedBytes = 0;

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }

    private static String text(JsonObject object, String key) {
        require(object.has(key) && object.get(key).isJsonPrimitive(), "missing text: " + key);
        String value = object.get(key).getAsString();
        require(!value.isEmpty() && value.length() <= 32768, "text bound: " + key);
        return value;
    }

    private static long number(JsonObject object, String key, long maximum) {
        require(object.has(key) && object.get(key).isJsonPrimitive(), "missing integer: " + key);
        String value = object.get(key).getAsString();
        require(value.matches("0|[1-9][0-9]{0,18}"), "invalid integer: " + key);
        long result = Long.parseLong(value);
        require(result <= maximum, "integer bound: " + key);
        return result;
    }

    private static String identifier(String name) {
        require(name.matches("[A-Za-z_][A-Za-z_0-9]{0,127}"), "invalid C identifier");
        return name;
    }

    private static byte[] boundedRead(Path path, int limit) throws Exception {
        require(Files.isRegularFile(path) && Files.size(path) <= limit, "file bound: " + path);
        byte[] bytes = Files.readAllBytes(path);
        require(bytes.length <= limit, "file changed beyond bound: " + path);
        return bytes;
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String asciiJson(String value) {
        String encoded = JSON.toJson(value);
        StringBuilder output = new StringBuilder();
        for (int index = 0; index < encoded.length(); index++) {
            char character = encoded.charAt(index);
            if (character > 127) output.append(String.format("\\u%04x", (int) character));
            else output.append(character);
        }
        return output.toString();
    }

    private static String canonical(JsonElement value) {
        if (value.isJsonObject()) {
            JsonObject object = value.getAsJsonObject();
            List<String> entries = new ArrayList<>();
            for (String key : new TreeSet<>(object.keySet())) {
                entries.add(asciiJson(key) + ":" + canonical(object.get(key)));
            }
            return "{" + String.join(",", entries) + "}";
        }
        if (value.isJsonArray()) {
            List<String> entries = new ArrayList<>();
            for (JsonElement item : value.getAsJsonArray()) entries.add(canonical(item));
            return "[" + String.join(",", entries) + "]";
        }
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            return asciiJson(value.getAsString());
        }
        return value.toString();
    }

    private void validateRuntimeDirectories(JsonObject request, JsonObject result) throws Exception {
        Path root = Path.of(text(request, "scratch_root")).toRealPath();
        JsonObject directories = new JsonObject();
        Path[] paths = {
            Path.of(System.getProperty("user.home")), Path.of(System.getProperty("java.io.tmpdir")),
            Application.getUserSettingsDirectory().toPath(), Application.getUserCacheDirectory().toPath(),
            Application.getUserTempDirectory().toPath()
        };
        String[] names = {"user_home", "java_temp", "application_settings", "application_cache", "application_temp"};
        for (int index = 0; index < paths.length; index++) {
            Path actual = paths[index].toRealPath();
            require(Files.isDirectory(actual) && actual.startsWith(root), "runtime directory escaped scratch");
            directories.addProperty(names[index], actual.toString());
        }
        String[] properties = {"application.settingsdir", "application.cachedir", "application.tempdir"};
        String[] leaves = {"gs", "gc", "gt"};
        for (int index = 0; index < properties.length; index++) {
            Path configured = Path.of(System.getProperty(properties[index])).toRealPath();
            require(configured.equals(root.resolve(leaves[index]).toRealPath()), "application directory override");
            Path actual = Path.of(directories.get(names[index + 2]).getAsString());
            require(actual.startsWith(configured), "actual application directory ignored scratch override");
        }
        require(paths[0].toRealPath().equals(Path.of(System.getenv("HOME")).toRealPath()), "Java user home");
        require(paths[1].toRealPath().equals(Path.of(System.getenv("TMPDIR")).toRealPath()),
            "Java temporary directory");
        result.add("runtime_directories", directories);
        result.addProperty("scratch_settings_owned", true);
    }

    private void validateIdentity(JsonObject request, JsonObject result) throws Exception {
        require(text(request, "schema").equals("rampage-cpp-virtual-input-v1"), "request schema mismatch");
        String expected = text(request, "input_sha256");
        JsonObject unsigned = request.deepCopy();
        unsigned.remove("input_sha256");
        require(sha256(canonical(unsigned).getBytes(StandardCharsets.UTF_8)).equals(expected), "request hash mismatch");
        result.addProperty("input_sha256", expected);
        String language = currentProgram.getLanguageID().toString();
        String compiler = currentProgram.getCompilerSpec().getCompilerSpecID().toString();
        String model = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        require(language.equals(text(request, "language_id")) && language.equals("x86:LE:64:default"), "language");
        require(compiler.equals(text(request, "compiler_id")) && compiler.equals("gcc"), "compiler");
        require(model.equals("__stdcall"), "requires GCC SysV default model, not thiscall/Windows");
        require(!currentProgram.getLanguage().isBigEndian(), "endianness");
        result.addProperty("language_id", language);
        result.addProperty("compiler_id", compiler);
        result.addProperty("default_model", model);
        result.addProperty("ghidra_version", Application.getApplicationVersion());
        require(Application.getApplicationVersion().equals("12.1.4"), "requires installed Ghidra 12.1.4");
        result.addProperty("java_version", System.getProperty("java.version"));
        result.addProperty("analysis_mode", getScriptAnalysisMode().name());
        validateRuntimeDirectories(request, result);
        require(Runtime.version().feature() == 21, "requires the explicitly selected installed JDK 21");
        SleighLanguageDescription description = (SleighLanguageDescription)
            currentProgram.getLanguage().getLanguageDescription();
        JsonObject specifications = request.getAsJsonObject("specifications");
        JsonObject actual = new JsonObject();
        for (String name : List.of("x86-64.sla", "x86-64.pspec", "x86-64-gcc.cspec")) {
            Path path;
            if (name.endsWith(".sla")) path = description.getSlaFile().getFile(false).toPath();
            else if (name.endsWith(".pspec")) path = description.getSpecFile().getFile(false).toPath();
            else path = Path.of(currentProgram.getCompilerSpec().getCompilerSpecDescription().getSource());
            JsonObject expectedSpec = specifications.getAsJsonObject(name);
            require(path.toRealPath().equals(Path.of(text(expectedSpec, "path")).toRealPath()), "actual spec path");
            String hash = sha256(boundedRead(path, 32 * LIMIT));
            require(hash.equals(text(expectedSpec, "sha256")), "actual spec bytes mismatch: " + name);
            JsonObject row = new JsonObject();
            row.addProperty("sha256", hash);
            row.addProperty("path", text(expectedSpec, "path"));
            actual.add(name, row);
        }
        result.add("specifications", actual);
        result.addProperty("compiler_spec_sha256", text(request, "compiler_spec_sha256"));
    }

    private void removeImportedEnrichment() throws Exception {
        List<Address> entryPoints = new ArrayList<>();
        Iterator<Address> importedEntries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (importedEntries.hasNext()) entryPoints.add(importedEntries.next());
        for (Address entry : entryPoints) currentProgram.getSymbolTable().removeExternalEntryPoint(entry);
        List<Address> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            functions.add(function.getEntryPoint());
        }
        for (Address entry : functions) currentProgram.getFunctionManager().removeFunction(entry);
        List<Symbol> symbols = new ArrayList<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) symbols.add(symbol);
        for (Symbol symbol : symbols) {
            if (!symbol.isDynamic()) require(symbol.delete(), "cannot remove imported symbol enrichment");
        }
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) memory.removeBlock(block, monitor);
        require(memory.getBlocks().length == 0, "imported memory remains");
        require(currentProgram.getFunctionManager().getFunctionCount() == 0, "imported functions remain");
        DataTypeManager manager = currentProgram.getDataTypeManager();
        List<DataType> importedTypes = new ArrayList<>();
        Iterator<DataType> types = manager.getAllDataTypes();
        while (types.hasNext()) {
            DataType type = types.next();
            if (!(type instanceof BuiltIn)) importedTypes.add(type);
        }
        for (DataType type : importedTypes) {
            if (manager.contains(type)) require(manager.remove(type, monitor), "cannot remove imported datatype");
        }
    }

    private void rebuildMemory(JsonObject request, JsonObject result) throws Exception {
        removeImportedEnrichment();
        Memory memory = currentProgram.getMemory();
        JsonArray mappings = request.getAsJsonArray("mappings");
        require(mappings.size() > 0 && mappings.size() <= 32, "mapping count bound");
        int total = 0;
        long previousEnd = -1;
        int index = 0;
        for (JsonElement element : mappings) {
            JsonObject mapping = element.getAsJsonObject();
            long base = number(mapping, "base", Long.MAX_VALUE - LIMIT);
            int size = (int) number(mapping, "size", LIMIT);
            require(size > 0 && base >= previousEnd, "mapping overlap/order/size");
            previousEnd = base + size;
            String hex = mapping.get("hex_bytes").getAsString();
            require(hex.length() <= 2 * size && hex.matches("(?:[0-9a-f]{2})*"), "mapping hex bound");
            byte[] bytes = Arrays.copyOf(HexFormat.of().parseHex(hex), size);
            total += size;
            require(total <= LIMIT, "aggregate memory bound");
            MemoryBlock block = memory.createInitializedBlock("controlled_" + index++, toAddr(base),
                new ByteArrayInputStream(bytes), size, monitor, false);
            block.setRead(mapping.get("readable").getAsBoolean());
            block.setWrite(mapping.get("writable").getAsBoolean());
            block.setExecute(mapping.get("executable").getAsBoolean());
        }
        validateMemory(request, result);
    }

    private void validateMemory(JsonObject request, JsonObject result) throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        Arrays.sort(blocks, Comparator.comparing(MemoryBlock::getStart));
        JsonArray mappings = request.getAsJsonArray("mappings");
        require(blocks.length == mappings.size(), "memory has extra/missing ranges or gaps");
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        JsonArray ranges = new JsonArray();
        for (int index = 0; index < mappings.size(); index++) {
            JsonObject mapping = mappings.get(index).getAsJsonObject();
            MemoryBlock block = blocks[index];
            long base = number(mapping, "base", Long.MAX_VALUE - LIMIT);
            int size = (int) number(mapping, "size", LIMIT);
            byte[] backed = HexFormat.of().parseHex(mapping.get("hex_bytes").getAsString());
            byte[] expected = Arrays.copyOf(backed, size);
            byte[] actual = new byte[size];
            require(block.getStart().equals(toAddr(base)) && block.getSize() == size && block.isInitialized(),
                "actual initialized memory range mismatch");
            require(block.getStart().getAddressSpace().equals(
                currentProgram.getAddressFactory().getDefaultAddressSpace()),
                "overlay/alternate memory space");
            require(block.isRead() == mapping.get("readable").getAsBoolean()
                && block.isWrite() == mapping.get("writable").getAsBoolean()
                && block.isExecute() == mapping.get("executable").getAsBoolean(), "memory permission mismatch");
            require(memory.getBytes(toAddr(base), actual) == size && Arrays.equals(actual, expected),
                "memory backed/zero-fill byte mismatch");
            int flags = (block.isRead() ? 4 : 0) | (block.isWrite() ? 2 : 0) | (block.isExecute() ? 1 : 0);
            hash.update(ByteBuffer.allocate(25).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(base).putLong(size).putLong(backed.length).put((byte) flags).array());
            hash.update(actual);
            if (index > 0) {
                long previousEnd = blocks[index - 1].getEnd().getOffset() + 1;
                if (previousEnd < base) {
                    AddressSet gap = new AddressSet(toAddr(previousEnd), toAddr(base - 1));
                    require(!memory.intersects(gap), "unexpected mapped memory gap");
                }
            }
            JsonObject range = new JsonObject();
            range.addProperty("base", base);
            range.addProperty("size", size);
            range.addProperty("file_backed_size", backed.length);
            range.addProperty("initialized_zero_tail_size", size - backed.length);
            range.addProperty("rwx_bits", flags);
            range.addProperty("bytes_sha256", sha256(actual));
            ranges.add(range);
        }
        String digest = HexFormat.of().formatHex(hash.digest());
        require(digest.equals(text(request, "memory_sha256")), "memory map readback hash mismatch");
        result.addProperty("memory_sha256", digest);
        result.addProperty("memory_validated", true);
        result.add("memory_ranges", ranges);
    }

    private DataType unalias(DataType type) {
        int depth = 0;
        while (type instanceof TypeDef) {
            require(depth++ < 8, "datatype alias depth");
            type = ((TypeDef) type).getBaseDataType();
        }
        return type;
    }

    private DataType alias(String name, DataType type) {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        return manager.resolve(new TypedefDataType(CategoryPath.ROOT, identifier(name), type, manager),
            DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private DataType scalar(JsonObject descriptor) {
        String kind = text(descriptor, "kind");
        int size = (int) number(descriptor, "size", 8);
        DataTypeManager manager = currentProgram.getDataTypeManager();
        DataType result;
        if (kind.equals("void")) {
            require(size == 0, "void width");
            return VoidDataType.dataType.clone(manager);
        }
        if (kind.equals("signed_integer") && size == 4) result = IntegerDataType.dataType.clone(manager);
        else if (kind.equals("unsigned_integer") && size == 4) result = UnsignedIntegerDataType.dataType.clone(manager);
        else if ((kind.equals("unsigned_integer") || kind.equals("unsigned_character")) && size == 1) {
            result = UnsignedCharDataType.dataType.clone(manager);
        }
        else throw new IllegalArgumentException("unsupported admitted scalar");
        require(result.getLength() == size && result.getAlignment() == number(descriptor, "alignment", 8),
            "scalar width/alignment mismatch");
        String name = text(descriptor, "name");
        return result.getName().equals(name) ? result : alias(name, result);
    }

    private DataType leaf(JsonObject descriptor) {
        if (text(descriptor, "kind").equals("scalar")) return scalar(descriptor.getAsJsonObject("scalar"));
        require(text(descriptor, "kind").equals("pointer"), "only scalar/opaque pointer fields");
        JsonObject pointee = descriptor.getAsJsonObject("pointee");
        require(text(pointee, "kind").equals("void") && text(pointee, "name").equals("void"), "vptr is not void *");
        require(number(pointee, "size", 8) == 0 && number(pointee, "alignment", 8) == 1, "void pointee facts");
        require(descriptor.get("name").getAsString().isEmpty(), "opaque pointer has no callback type name");
        require(number(descriptor, "size", 8) == 8 && number(descriptor, "alignment", 8) == 8, "pointer facts");
        return new PointerDataType(scalar(pointee), 8, currentProgram.getDataTypeManager());
    }

    private JsonObject readLeaf(DataType displayed, JsonObject expected) {
        DataType actual = unalias(displayed);
        JsonObject row = new JsonObject();
        row.addProperty("display_name", displayed.getName());
        row.addProperty("leaf_display_name", actual.getName());
        row.addProperty("size", actual instanceof VoidDataType ? 0 : actual.getLength());
        row.addProperty("alignment", actual.getAlignment());
        if (text(expected, "kind").equals("pointer")) {
            require(actual instanceof Pointer && actual.getLength() == 8 && actual.getAlignment() == 8,
                "pointer readback");
            DataType pointee = unalias(((Pointer) actual).getDataType());
            require(pointee instanceof VoidDataType, "opaque pointer became callback/integer/undefined");
            row.addProperty("kind", "pointer");
            row.addProperty("pointee_kind", "void");
        }
        else {
            JsonObject scalar = expected.getAsJsonObject("scalar");
            require(actual instanceof AbstractIntegerDataType, "scalar became undefined/noninteger");
            boolean signed = ((AbstractIntegerDataType) actual).isSigned();
            String kind = text(scalar, "kind");
            require(signed == kind.startsWith("signed_"), "scalar signedness readback");
            require(actual.getLength() == number(scalar, "size", 8)
                && actual.getAlignment() == number(scalar, "alignment", 8), "scalar size/alignment readback");
            row.addProperty("kind", signed ? "signed_integer" : "unsigned_integer");
        }
        return row;
    }

    private void installLayouts(JsonObject request, JsonObject result) throws Exception {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        DataOrganization organization = manager.getDataOrganization();
        require(organization.getPointerSize() == 8 && organization.getIntegerSize() == 4
            && organization.getLongSize() == 8, "data organization mismatch");
        for (int size : List.of(1, 2, 4, 8)) {
            require(organization.getSizeAlignment(size) == size, "scalar alignment map mismatch");
        }
        alias("int4", IntegerDataType.dataType.clone(manager));
        alias("uint4", UnsignedIntegerDataType.dataType.clone(manager));
        alias("uint1", UnsignedCharDataType.dataType.clone(manager));
        JsonArray layouts = request.getAsJsonArray("layouts");
        require(layouts.size() == 2, "bounded lane requires two distinct admitted records");
        JsonArray readback = new JsonArray();
        TreeSet<String> names = new TreeSet<>();
        for (JsonElement element : layouts) {
            JsonObject layout = element.getAsJsonObject();
            String name = identifier(text(layout, "name"));
            require(names.add(name), "duplicate record identity");
            int size = (int) number(layout, "size", LIMIT);
            int alignment = (int) number(layout, "alignment", 8);
            require(size == 16 && alignment == 8, "record bounds");
            StructureDataType structure = new StructureDataType(CategoryPath.ROOT, name, size, manager);
            structure.setPackingEnabled(false);
            structure.setExplicitMinimumAlignment(alignment);
            JsonArray fields = layout.getAsJsonArray("fields");
            require(fields.size() == 3, "record field count");
            for (JsonElement member : fields) {
                JsonObject field = member.getAsJsonObject();
                structure.replaceAtOffset((int) number(field, "offset", size), leaf(field.getAsJsonObject("ty")),
                    (int) number(field, "size", size), identifier(text(field, "name")), null);
            }
            Structure actual = (Structure) manager.resolve(structure, DataTypeConflictHandler.REPLACE_HANDLER);
            require(actual.getLength() == size && actual.getAlignment() == alignment, "record size/alignment readback");
            require(actual.getNumDefinedComponents() == fields.size(), "record has extra/missing fields");
            JsonObject row = new JsonObject();
            row.addProperty("name", actual.getName());
            row.addProperty("size", actual.getLength());
            row.addProperty("alignment", actual.getAlignment());
            JsonArray actualFields = new JsonArray();
            for (JsonElement member : fields) {
                JsonObject field = member.getAsJsonObject();
                int offset = (int) number(field, "offset", size);
                DataTypeComponent component = actual.getComponentAt(offset);
                require(component != null && component.getOffset() == offset
                    && component.getLength() == number(field, "size", size)
                    && text(field, "name").equals(component.getFieldName()), "field offset/size/name readback");
                JsonObject actualField = readLeaf(component.getDataType(), field.getAsJsonObject("ty"));
                actualField.addProperty("name", component.getFieldName());
                actualField.addProperty("offset", component.getOffset());
                actualFields.add(actualField);
            }
            row.add("fields", actualFields);
            readback.add(row);
        }
        result.add("layout_readback", readback);
        result.addProperty("layout_validated", true);
    }

    private List<Function> installMethods(JsonObject request) throws Exception {
        JsonArray methods = request.getAsJsonArray("methods");
        require(methods.size() > 0 && methods.size() <= 128, "method count bound");
        List<Function> functions = new ArrayList<>();
        FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
        TreeSet<Long> addresses = new TreeSet<>();
        for (JsonElement element : methods) {
            JsonObject method = element.getAsJsonObject();
            long value = number(method, "address", Long.MAX_VALUE - 128);
            require(addresses.add(value), "aliased method VA");
            int size = (int) number(method, "size", 128);
            require(size > 0, "empty method");
            Address start = toAddr(value);
            AddressSet body = new AddressSet(start, start.add(size - 1));
            require(currentProgram.getMemory().getExecuteSet().contains(body), "method outside executable map");
            DisassembleCommand command = new DisassembleCommand(start, body, true);
            command.enableCodeAnalysis(false);
            require(command.applyTo(currentProgram, monitor), "bounded disassembly: " + command.getStatusMsg());
            require(currentProgram.getListing().getInstructionAt(start) != null, "no method entry instruction");
            String name = identifier(text(method, "name"));
            Function function = currentProgram.getFunctionManager().createFunction(
                name, start, body, SourceType.USER_DEFINED);
            require(function != null, "cannot create exact-VA function");
            String declaration = text(method, "declaration").trim();
            require(declaration.endsWith(";"), "accepted prototype missing semicolon");
            FunctionDefinitionDataType signature = parser.parse(
                null, declaration.substring(0, declaration.length() - 1));
            signature.setCallingConvention("__stdcall");
            ApplyFunctionSignatureCmd apply = new ApplyFunctionSignatureCmd(start, signature, SourceType.USER_DEFINED,
                false, true);
            require(apply.applyTo(currentProgram, monitor), "prototype apply: " + apply.getStatusMsg());
            require(function.getName().equals(name) && !function.isThunk(), "method symbol/prototype identity");
            require(function.getParameterCount() >= 1 && function.getParameterCount() <= 2, "explicit parameter count");
            require(function.getParameter(0).getName().equals("self") && !function.getParameter(0).isAutoParameter(),
                "requires explicit self, not injected this");
            require(function.getParameter(0).getDataType() instanceof Pointer, "self is not a record pointer");
            functions.add(function);
        }
        return functions;
    }

    private String layoutDeclaration(JsonObject layout) {
        List<String> fields = new ArrayList<>();
        for (JsonElement element : layout.getAsJsonArray("fields")) {
            JsonObject field = element.getAsJsonObject();
            JsonObject descriptor = field.getAsJsonObject("ty");
            String type;
            if (text(descriptor, "kind").equals("pointer")) {
                type = text(descriptor.getAsJsonObject("pointee"), "name") + " *";
            }
            else {
                require(text(descriptor, "kind").equals("scalar"), "controlled field declaration kind");
                type = text(descriptor.getAsJsonObject("scalar"), "name");
            }
            fields.add(" " + type + " " + identifier(text(field, "name")) + ";");
        }
        return "struct " + identifier(text(layout, "name")) + " {\n" + String.join("\n", fields) + "\n};";
    }

    private void validateOperations(JsonObject request) {
        JsonArray operations = request.getAsJsonArray("operations");
        JsonArray layouts = request.getAsJsonArray("layouts");
        JsonArray methods = request.getAsJsonArray("methods");
        require(operations.size() == 2 * layouts.size() + 2 * methods.size(), "controlled operation count");
        int index = 0;
        List<String> declarations = new ArrayList<>();
        for (JsonElement layout : layouts) {
            String declaration = layoutDeclaration(layout.getAsJsonObject());
            JsonObject parse = operations.get(index++).getAsJsonObject();
            require(text(parse, "op").equals("parse_types")
                && text(parse, "declarations").equals(declaration), "one controlled declaration per layout");
            declarations.add(declaration);
        }
        require(String.join("\n", declarations).equals(text(request, "declarations")),
            "controlled aggregate layout declarations");
        for (JsonElement layout : layouts) {
            JsonObject operation = operations.get(index++).getAsJsonObject();
            require(text(operation, "op").equals("assert_plain_struct_layout")
                && operation.get("layout").equals(layout)
                && text(operation, "expected_context").equals(text(request, "compiler_spec_sha256")),
                "controlled layout assertion input");
        }
        for (JsonElement element : methods) {
            JsonObject method = element.getAsJsonObject();
            JsonObject symbol = operations.get(index++).getAsJsonObject();
            JsonObject prototype = operations.get(index++).getAsJsonObject();
            require(text(symbol, "op").equals("symbol") && symbol.get("address").equals(method.get("address"))
                && text(symbol, "name").equals(text(method, "name")), "controlled symbol input");
            require(text(prototype, "op").equals("prototype")
                && prototype.get("address").equals(method.get("address"))
                && !prototype.get("indirect").getAsBoolean()
                && text(prototype, "declaration").equals(text(method, "declaration")), "controlled prototype input");
        }
    }

    private JsonObject storage(VariableStorage storage) {
        Varnode[] nodes = storage.getVarnodes();
        require(nodes.length == 1 && !storage.isAutoStorage() && !storage.isForcedIndirect(),
            "unsupported automatic/split/indirect parameter storage");
        Varnode node = nodes[0];
        require(node.getAddress().getAddressSpace().isRegisterSpace(), "parameter register storage unavailable");
        JsonObject result = new JsonObject();
        result.addProperty("kind", "processor");
        result.addProperty("space", node.getAddress().getAddressSpace().getName());
        result.addProperty("address", node.getOffset());
        result.addProperty("size", node.getSize());
        return result;
    }

    private String semanticKind(DataType displayed) {
        DataType type = unalias(displayed);
        if (type instanceof VoidDataType) return "void";
        if (type instanceof Pointer) {
            DataType pointee = unalias(((Pointer) type).getDataType());
            require(pointee instanceof Structure, "method parameter points to nonrecord");
            return "record_pointer";
        }
        require(type instanceof AbstractIntegerDataType, "method semantic datatype unavailable");
        return ((AbstractIntegerDataType) type).isSigned() ? "signed_integer" : "unsigned_integer";
    }

    private JsonObject decompile(DecompInterface engine, Function function, JsonObject method, int timeout) {
        JsonObject row = new JsonObject();
        row.addProperty("symbol", text(method, "symbol"));
        row.addProperty("address", function.getEntryPoint().getOffset());
        row.addProperty("ok", false);
        long started = System.nanoTime();
        try {
            DecompileResults decompiled = engine.decompileFunction(function, timeout, monitor);
            row.addProperty("decompile_inner_seconds", (System.nanoTime() - started) / 1.0e9);
            row.addProperty("warning", decompiled.getErrorMessage());
            require(decompiled.decompileCompleted(), "reference incomplete: " + decompiled.getErrorMessage());
            require(decompiled.getDecompiledFunction() != null && decompiled.getHighFunction() != null,
                "reference missing C/syntax result");
            String code = decompiled.getDecompiledFunction().getC();
            renderedBytes += code.getBytes(StandardCharsets.UTF_8).length;
            require(renderedBytes <= LIMIT && code.length() <= 65536, "aggregate rendered output bound");
            row.addProperty("text", code);
            HighFunction high = decompiled.getHighFunction();
            FunctionPrototype prototype = high.getFunctionPrototype();
            require(!prototype.hasThisPointer() && !prototype.isVarArg(), "injected this/variadic prototype");
            row.addProperty("calling_convention", prototype.getModelName());
            row.addProperty("return_size", prototype.getReturnType() instanceof VoidDataType ? 0
                : prototype.getReturnType().getLength());
            row.addProperty("return_display_type", prototype.getReturnType().getDisplayName());
            row.addProperty("return_kind", semanticKind(prototype.getReturnType()));
            row.addProperty("native_return_storage", "unavailable");
            JsonArray parameters = new JsonArray();
            for (int index = 0; index < prototype.getNumParams(); index++) {
                HighSymbol parameter = prototype.getParam(index);
                require(!parameter.isThisPointer() && !parameter.isHiddenReturn(), "automatic parameter injection");
                JsonObject actual = new JsonObject();
                actual.addProperty("name", parameter.getName());
                actual.addProperty("size", parameter.getDataType().getLength());
                actual.addProperty("display_type", parameter.getDataType().getDisplayName());
                String kind = semanticKind(parameter.getDataType());
                actual.addProperty("kind", kind);
                if (kind.equals("record_pointer")) {
                    Pointer pointer = (Pointer) unalias(parameter.getDataType());
                    actual.addProperty("record_name", unalias(pointer.getDataType()).getName());
                }
                actual.add("storage", storage(parameter.getStorage()));
                parameters.add(actual);
            }
            row.add("parameters", parameters);
            JsonArray calls = new JsonArray();
            Iterator<PcodeOpAST> pcode = high.getPcodeOps();
            int count = 0;
            while (pcode.hasNext()) {
                PcodeOpAST operation = pcode.next();
                require(++count <= 10000, "bounded high P-code operation count");
                if (operation.getOpcode() == PcodeOp.CALL || operation.getOpcode() == PcodeOp.CALLIND) {
                    JsonObject call = new JsonObject();
                    call.addProperty("mnemonic", operation.getMnemonic());
                    call.addProperty("instruction_address", operation.getSeqnum().getTarget().getOffset());
                    calls.add(call);
                }
            }
            row.add("high_pcode_calls", calls);
            row.addProperty("ok", true);
        }
        catch (Exception error) {
            row.addProperty("error", error.toString());
        }
        return row;
    }

    private void executeRequest(JsonObject request, JsonObject result) throws Exception {
        validateIdentity(request, result);
        validateOperations(request);
        rebuildMemory(request, result);
        installLayouts(request, result);
        List<Function> functions = installMethods(request);
        JsonObject expected = request.getAsJsonObject("options");
        require(!expected.get("respect_readonly").getAsBoolean()
            && text(expected, "protoeval").equals("default")
            && number(expected, "max_instructions", 100000) == 100000
            && number(expected, "max_jumptable", 1024) == 1024
            && text(expected, "simplification").equals("decompile")
            && expected.get("c_code").getAsBoolean() && expected.get("syntax_tree").getAsBoolean(), "options");
        DecompileOptions options = new DecompileOptions();
        options.setRespectReadOnly(false);
        options.setProtoEvalModel("default");
        options.setMaxInstructions(100000);
        options.setMaxJumpTableEntries(1024);
        DecompInterface engine = new DecompInterface();
        try {
            require(engine.setOptions(options), "setOptions: " + engine.getLastMessage());
            require(engine.setSimplificationStyle("decompile"), "setSimplificationStyle");
            require(engine.toggleCCode(true), "toggleCCode");
            require(engine.toggleSyntaxTree(true), "toggleSyntaxTree");
            require(engine.openProgram(currentProgram), "openProgram: " + engine.getLastMessage());
            result.addProperty("setup_warning", engine.getLastMessage());
            DecompileOptions actualOptions = engine.getOptions();
            JsonObject effective = new JsonObject();
            effective.addProperty("respect_readonly", actualOptions.isRespectReadOnly());
            effective.addProperty("protoeval", actualOptions.getProtoEvalModel());
            effective.addProperty("max_instructions", actualOptions.getMaxInstructions());
            effective.addProperty("max_jumptable", actualOptions.getMaxJumpTableEntries());
            effective.addProperty("simplification", engine.getSimplificationStyle());
            effective.addProperty("c_code", true);
            effective.addProperty("syntax_tree", true);
            require(effective.equals(expected), "effective options mismatch");
            result.add("effective_options", effective);
            JsonArray methods = request.getAsJsonArray("methods");
            JsonArray rows = new JsonArray();
            result.add("methods", rows);
            int timeout = (int) number(request, "timeout_seconds", 30);
            require(timeout > 0, "inner timeout");
            for (int index = 0; index < functions.size(); index++) {
                rows.add(decompile(engine, functions.get(index), methods.get(index).getAsJsonObject(), timeout));
            }
            validateMemory(request, result);
            result.addProperty("ok", true);
        }
        finally {
            engine.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        require(getScriptArgs().length == 2, "request path and export path required");
        Path requestPath = Path.of(getScriptArgs()[0]);
        Path output = Path.of(getScriptArgs()[1]);
        require(!Files.exists(output), "export must be new runner-owned scratch");
        JsonObject result = new JsonObject();
        result.addProperty("schema", "rampage-cpp-virtual-reference-v1");
        result.addProperty("ok", false);
        try {
            JsonObject request = JsonParser.parseString(new String(boundedRead(requestPath, 4 * LIMIT),
                StandardCharsets.UTF_8)).getAsJsonObject();
            executeRequest(request, result);
        }
        catch (Exception error) {
            result.addProperty("error", error.toString());
        }
        byte[] bytes = JSON.toJson(result).getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= 4 * LIMIT, "export bound");
        Path temporary = output.resolveSibling(output.getFileName() + ".partial");
        Files.write(temporary, bytes);
        Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
    }
}

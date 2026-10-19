/* SPDX-License-Identifier: Apache-2.0 */
import com.google.gson.GsonBuilder;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import java.nio.file.*;
import java.util.*;

public class ExtendedSleighOracleRetry extends ExtendedSleighOracle {
    public static void main(String[] args) throws Exception {
        require(args.length == 3, "fixed retry key, owned directory, new output required");
        require(args[0].equals("SuperH-v2") || args[0].equals("Hexagon-v2"), "unreleased retry profile");
        String originalKey = args[0].replace("-v2", "-v1");
        Owned original = Arrays.stream(OWNED).filter(item -> item.name().equals(originalKey))
            .findFirst().orElseThrow();
        Owned owned = new Owned(args[0], original.language(), original.base(), original.hex(),
            original.callee(), original.mainEnd(), original.starts());
        Path input = Path.of(args[1]).resolve(owned.name() + ".bin");
        byte[] bytes = readOwned(input);
        require(Arrays.equals(bytes, HexFormat.of().parseHex(owned.hex())), "fixed retry bytes differ");
        ApplicationConfiguration configuration = new ApplicationConfiguration();
        configuration.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(SDK.toFile()), configuration);
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
        require(Arrays.equals(bytes, readOwned(input)), "owned retry bytes changed");
        String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create()
            .toJson(result) + "\n";
        require(json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 4 * 1024 * 1024, "result cap");
        Files.writeString(Path.of(args[2]), json, StandardOpenOption.CREATE_NEW);
    }
}

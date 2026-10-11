import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class ghidra_decompile extends GhidraScript {
    public void run() throws Exception {
        if (getScriptArgs().length != 2) throw new IllegalArgumentException("output path and function name required");
        String name = getScriptArgs()[1];
        DecompInterface engine = new DecompInterface();
        try {
            if (!engine.openProgram(currentProgram)) throw new IllegalStateException(engine.getLastMessage());
            Function selected = null;
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                if (function.getName().equals(name)) { selected = function; break; }
            }
            if (selected == null) throw new IllegalArgumentException("function not found: " + name);
            DecompileResults result = engine.decompileFunction(selected, 30, monitor);
            if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
            Path output = Path.of(getScriptArgs()[0]);
            Path temporary = output.resolveSibling(output.getFileName() + ".partial");
            try (Writer writer = new FileWriter(temporary.toFile())) {
                writer.write(result.getDecompiledFunction().getC());
            }
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            engine.dispose();
        }
    }
}

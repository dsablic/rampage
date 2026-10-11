// Ghidra headless script: writes the entry address of every non-external, non-thunk function, one hex address
// per line, to the file named in the first script argument. Used to build an accuracy reference for
// `rampage compare` (see tools/benchmark.sh).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ghidra_function_starts extends GhidraScript {
    public void run() throws Exception {
        String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/function_starts.txt";
        PrintWriter writer = new PrintWriter(new FileWriter(out));
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.isExternal() || function.isThunk()) {
                continue;
            }
            writer.println("0x" + function.getEntryPoint().getOffsetAsBigInteger().toString(16));
        }
        writer.close();
        println("wrote function starts to " + out);
    }
}

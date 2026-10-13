// Ghidra headless script: writes, for every non-external, non-thunk function, its basic blocks (BasicBlockModel),
// intra-function successor edges and call references as JSON to the file named in the first script argument. Thunk
// entries are listed separately so call targets that land on them can be recognised. Used by
// tools/cfg-benchmark.py to compare rampage's CFG and call graph against Ghidra's.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ghidra_cfg_export extends GhidraScript {
    private static String hex(Address address) {
        return "\"0x" + address.getOffsetAsBigInteger().toString(16) + "\"";
    }

    public void run() throws Exception {
        String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/ghidra_cfg.json";
        PrintWriter writer = new PrintWriter(new FileWriter(out));
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        writer.print("{\"thunks\":[");
        boolean first = true;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.isExternal() || !function.isThunk()) {
                continue;
            }
            writer.print((first ? "" : ",") + hex(function.getEntryPoint()));
            first = false;
        }
        writer.print("],\"functions\":[");
        first = true;
        functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.isExternal() || function.isThunk()) {
                continue;
            }
            AddressSetView body = function.getBody();
            writer.print((first ? "" : ",") + "{\"address\":" + hex(function.getEntryPoint()));
            writer.print(",\"noreturn\":" + function.hasNoReturn() + ",\"blocks\":[");
            first = false;
            boolean firstBlock = true;
            CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                writer.print((firstBlock ? "" : ",") + "{\"start\":" + hex(block.getFirstStartAddress()));
                writer.print(",\"end\":" + hex(block.getMaxAddress().next()) + ",\"successors\":[");
                firstBlock = false;
                boolean firstEdge = true;
                CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                while (destinations.hasNext()) {
                    CodeBlockReference destination = destinations.next();
                    FlowType flow = destination.getFlowType();
                    Address target = destination.getDestinationAddress();
                    if (flow.isCall() || target == null || !body.contains(target)) {
                        continue;
                    }
                    writer.print((firstEdge ? "" : ",") + "[" + hex(target) + ",\"" + flow + "\"]");
                    firstEdge = false;
                }
                writer.print("]}");
            }
            writer.print("],\"calls\":[");
            boolean firstCall = true;
            InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getReferenceType().isCall() || !reference.getToAddress().isMemoryAddress()) {
                        continue;
                    }
                    writer.print((firstCall ? "" : ",") + "[" + hex(instruction.getAddress()) + ","
                        + hex(reference.getToAddress()) + ",\"" + reference.getReferenceType() + "\"]");
                    firstCall = false;
                }
            }
            writer.print("]}");
        }
        writer.println("]}");
        writer.close();
        println("wrote CFG export to " + out);
    }
}

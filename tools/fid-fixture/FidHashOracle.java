/* SPDX-License-Identifier: Apache-2.0
 * Owned semantic-feature oracle. Calls the actual Ghidra 12.1.4 hasher, not a second
 * implementation of its mixing. No input program is loaded or executed.
 */
import generic.hash.FNV1a64MessageDigestFactory;
import ghidra.feature.fid.hash.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import java.lang.reflect.*;
import java.util.*;

public class FidHashOracle {
    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    static FidHashQuad hash(int value) throws Exception {
        AddressSpace space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
        Address at = space.getAddress(0x401000);
        Mask mask = new MaskImpl(new byte[]{(byte) 0xff});
        InstructionPrototype prototype = proxy(InstructionPrototype.class, (p, method, args) -> {
            return switch (method.getName()) {
                case "getInstructionMask", "getOperandValueMask" -> mask;
                default -> throw new UnsupportedOperationException(method.getName());
            };
        });
        Instruction instruction = proxy(Instruction.class, (p, method, args) -> {
            return switch (method.getName()) {
                case "getMinAddress", "getMaxAddress" -> at;
                case "getLength", "getNumOperands" -> 1;
                case "getFlowType" -> RefType.FALL_THROUGH;
                case "getPrototype" -> prototype;
                case "getOpObjects" -> new Object[]{new Scalar(32, value)};
                case "getOperandType" -> OperandType.SCALAR;
                default -> throw new UnsupportedOperationException(method.getName());
            };
        });
        RelocationTable relocations = proxy(RelocationTable.class, (p, method, args) -> {
            if (method.getName().equals("getRelocations")) return Collections.emptyIterator();
            throw new UnsupportedOperationException(method.getName());
        });
        Memory memory = proxy(Memory.class, (p, method, args) -> {
            if (method.getName().equals("getBytes")) {
                byte[] bytes = (byte[]) args[1];
                int offset = (int) args[2];
                int length = (int) args[3];
                Arrays.fill(bytes, offset, offset + length, (byte) 0x90);
                return length;
            }
            throw new UnsupportedOperationException(method.getName());
        });
        Program program = proxy(Program.class, (p, method, args) -> {
            return switch (method.getName()) {
                case "getMemory" -> memory;
                case "getRelocationTable" -> relocations;
                default -> throw new UnsupportedOperationException(method.getName());
            };
        });
        Function function = proxy(Function.class, (p, method, args) -> {
            if (method.getName().equals("getProgram")) return program;
            throw new UnsupportedOperationException(method.getName());
        });
        List<CodeUnit> extent = Collections.nCopies(4, instruction);
        MessageDigestFidHasher hasher = new MessageDigestFidHasher(
            ignored -> extent, (byte) 4, new FNV1a64MessageDigestFactory(), Collections.emptyList());
        return hasher.hash(function);
    }

    public static void main(String[] args) throws Exception {
        for (int value : new int[]{7, 9, -256, 256}) {
            FidHashQuad hash = hash(value);
            System.out.printf("%d %d %016x %d %016x%n", value, hash.getCodeUnitSize(),
                hash.getFullHash(), hash.getSpecificHashAdditionalSize(), hash.getSpecificHash());
        }
    }
}

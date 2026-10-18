/* SPDX-License-Identifier: Apache-2.0
 * Verifies actual Ghidra-produced FID records against stripped held-out machine-code analyses.
 * No target binary is executed; all input files are owned generated test fixtures.
 */
import db.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class FidNativeFixtureTest {
    record Quad(int size, long full, int additional, long specific) {}
    record Function(long address, Quad hash, int flags, List<Long> callees) {}

    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    static String text(DataInputStream input) throws IOException {
        int size = input.readInt();
        check(size >= 0 && size <= 4096, "text size");
        return new String(input.readNBytes(size), java.nio.charset.StandardCharsets.UTF_8);
    }

    static List<Function> features(Path path, Path binary) throws Exception {
        try (DataInputStream input = new DataInputStream(Files.newInputStream(path))) {
            check(Arrays.equals(input.readNBytes(8), "RPFPG001".getBytes()), "feature header");
            check(input.readInt() == 6, "feature schema");
            check(Arrays.equals(input.readNBytes(32), MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(binary))), "exact binary SHA binding");
            check(text(input).equals("12.1.4"), "actual Ghidra profile");
            check(text(input).equals("ghidra-12.1.4-x86-elf-minimal-v1"), "owned no-external-analysis controls");
            check(text(input).equals("x86:LE:64:default"), "actual language profile");
            input.readInt();
            input.readInt();
            check(text(input).equals("gcc"), "actual compiler profile");
            int count = input.readInt();
            List<Function> functions = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                long address = input.readLong();
                Quad hash = new Quad(input.readUnsignedShort(), input.readLong(), input.readUnsignedByte(),
                    input.readLong());
                int flags = input.readUnsignedByte();
                int ranges = input.readInt();
                for (int j = 0; j < ranges; j++) { input.readLong(); input.readLong(); }
                int edges = input.readInt();
                List<Long> callees = new ArrayList<>();
                for (int j = 0; j < edges; j++) callees.add(input.readLong());
                functions.add(new Function(address, hash, flags, callees));
            }
            check(input.read() == -1, "trailing feature bytes");
            return functions;
        }
    }

    static int matching(DBHandle db, List<Function> functions) throws Exception {
        int matched = 0;
        RecordIterator records = db.getTable("Functions Table").iterator();
        while (records.hasNext()) {
            DBRecord record = records.next();
            Quad hash = new Quad(record.getShortValue(0), record.getLongValue(1), record.getByteValue(2),
                record.getLongValue(3));
            for (Function function : functions) {
                if (!function.hash.equals(hash) || (function.flags & 2) != 0) continue;
                check((record.getByteValue(8) & 1) == (function.flags & 1), "terminator feature");
                if ((record.getByteValue(8) & 16) != 0) {
                    boolean related = false;
                    for (long callee : function.callees) for (Function child : functions) {
                        if (child.address != callee) continue;
                        long smash = record.getKey() * 1099511628211L ^ child.hash.full;
                        related |= db.getTable("Superior Table").getRecord(smash) != null;
                    }
                    check(related, "actual mandatory callee relation");
                }
                matched++;
            }
        }
        return matched;
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "explicit owned fixture root required");
        Path root = Path.of(args[0]);
        DBHandle db = new DBHandle(root.resolve("native.fidbf").toFile());
        try {
            FidExport.validate(db);
            List<Function> positive = features(root.resolve("native-heldout.features"),
                root.resolve("native-heldout.elf"));
            List<Function> negative = features(root.resolve("native-negative.features"),
                root.resolve("native-negative.elf"));
            check(matching(db, positive) == 2, "real FID positive holdout did not match both owned functions");
            check(matching(db, negative) == 0, "altered scalar negative matched a real FID record: " + negative
                + "; positive=" + positive);
        }
        finally { db.close(); }
        System.out.println("Actual Ghidra native FID fixtures passed: 2 stripped holdout matches, 0 altered matches");
    }
}

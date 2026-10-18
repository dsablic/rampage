/* SPDX-License-Identifier: Apache-2.0
 * Owned corruption/transaction tests. Run with explicit trusted Java and Ghidra framework jars.
 */
import db.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class FidExportTest {
    static int assertions;

    static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    static byte[] export(Path path) throws Exception {
        PrintStream original = System.out;
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        FidExport.outputBytes = 0;
        try {
            System.setOut(new PrintStream(capture));
            FidExport.export(path);
        }
        finally { System.setOut(original); }
        return capture.toByteArray();
    }

    interface Action { void run() throws Exception; }

    static void rejects(Action action, String message) throws Exception {
        boolean rejected = false;
        try { action.run(); }
        catch (IOException expected) { rejected = true; }
        check(rejected, message);
    }

    static void corrupt(Path path, byte[] original, int offset, int value) throws Exception {
        byte[] bytes = original.clone();
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
        Files.write(path, bytes, StandardOpenOption.CREATE_NEW);
        rejects(() -> export(path), "accepted corrupt header at " + offset);
        Files.delete(path);
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "explicit temporary root required");
        Path root = Files.createTempDirectory(Path.of(args[0]), "fid-export-test-");
        Path database = root.resolve("owned.fidbf");
        Path malformed = root.resolve("malformed.fidbf");
        Path modified = root.resolve("modified.fidbf");
        try {
            FidExport.fixture(database);
            byte[] original = Files.readAllBytes(database);
            byte[] exported = export(database);
            check(Arrays.equals(Arrays.copyOf(exported, 8), "RPFID001".getBytes()), "bridge magic");
            check(exported.length > 100 && exported.length < 4096, "bounded fixture output");
            check(Arrays.equals(original, Files.readAllBytes(database)), "reader modified input");
            rejects(() -> FidExport.fixture(database), "fixture overwrote existing file");
            corrupt(malformed, original, 0, 0); // Wrong raw magic; not JSON pretending to be FID.
            corrupt(malformed, original, 16, 2); // Unknown raw header version.
            corrupt(malformed, original, 20, 0); // Zero block size before modulo/allocation.
            corrupt(malformed, original, 24, Integer.MAX_VALUE); // Free-block pointer out of range.
            corrupt(malformed, original, 24, -2); // Invalid negative free-block pointer.
            corrupt(malformed, original, 28, Integer.MAX_VALUE); // Header parameter budget.
            byte[] cycle = original.clone();
            ByteBuffer header = ByteBuffer.wrap(cycle);
            int blockSize = header.getInt(20);
            header.putInt(24, 0);
            cycle[blockSize] = 1;
            header.putInt(blockSize + 1, 0);
            Files.write(malformed, cycle, StandardOpenOption.CREATE_NEW);
            rejects(() -> export(malformed), "free-block cycle accepted");
            Files.delete(malformed);
            byte[] allocatedFlags = original.clone();
            for (int offset = blockSize; offset < allocatedFlags.length; offset += blockSize) {
                if ((allocatedFlags[offset] & 1) == 0) {
                    allocatedFlags[offset] |= (byte) 0x80;
                    break;
                }
            }
            Files.write(malformed, allocatedFlags, StandardOpenOption.CREATE_NEW);
            rejects(() -> export(malformed), "unknown allocated-block flag accepted");
            Files.delete(malformed);
            Files.write(malformed, Arrays.copyOf(original, original.length - 1), StandardOpenOption.CREATE_NEW);
            rejects(() -> export(malformed), "truncated raw block accepted");
            Files.delete(malformed);
            Files.writeString(malformed, "{\"functions\":[]}", StandardOpenOption.CREATE_NEW);
            rejects(() -> export(malformed), "renamed JSON accepted as fidbf");
            Files.delete(malformed);

            // Raw DBHandle supports private transactional edits, saved to a DIFFERENT new file.
            DBHandle db = new DBHandle(database.toFile());
            try {
                long tx = db.startTransaction();
                Table functions = db.getTable("Functions Table");
                DBRecord function = functions.getRecord(100);
                function.setLongValue(4, 999); // Dangling library FK, structurally valid database.
                functions.putRecord(function);
                db.endTransaction(tx, true);
                db.saveAs(modified.toFile(), false, TaskMonitor.DUMMY);
            }
            finally { db.close(); }
            rejects(() -> export(modified), "dangling FID library reference accepted");
            Files.delete(modified);

            db = new DBHandle(database.toFile());
            try {
                long tx = db.startTransaction();
                db.deleteTable("Libraries Table");
                db.createTable("Libraries Table", new Schema(7, "Library ID", FidExport.FIELDS[0],
                    FidExport.NAMES[0]));
                db.endTransaction(tx, true);
                db.saveAs(modified.toFile(), false, TaskMonitor.DUMMY);
            }
            finally { db.close(); }
            rejects(() -> export(modified), "unknown FID schema accepted");
            Files.delete(modified);
            for (int[] indexes : new int[][]{new int[]{}, new int[]{1}}) {
                db = new DBHandle(database.toFile());
                try {
                    long tx = db.startTransaction();
                    db.deleteTable("Functions Table");
                    db.createTable("Functions Table", new Schema(6, "Function ID", FidExport.FIELDS[2],
                        FidExport.NAMES[2]), indexes);
                    db.endTransaction(tx, true);
                    db.saveAs(modified.toFile(), false, TaskMonitor.DUMMY);
                }
                finally { db.close(); }
                rejects(() -> export(modified), "missing or wrong indexes accepted");
                Files.delete(modified);
            }
            check(MessageDigest.isEqual(original, Files.readAllBytes(database)), "fixture changed during tests");
        }
        finally {
            for (Path path : new Path[]{database, malformed, modified}) Files.deleteIfExists(path);
            Files.delete(root);
        }
        System.out.println("FID real-database bridge checks passed: " + assertions);
    }
}

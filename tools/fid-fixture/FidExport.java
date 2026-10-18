/*
 * SPDX-License-Identifier: Apache-2.0
 * Schema and relation definitions adapted from Ghidra 12.1.4, IP: GHIDRA.
 * https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.1.4_build/
 * Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/db
 * Licensed under the Apache License, Version 2.0:
 * https://www.apache.org/licenses/LICENSE-2.0
 * Distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 *
 * Owned bridge, not a Ghidra script: only DBHandle(File)'s read-only raw database
 * reader runs. No project, program, loader, analyzer, source path, or target runs.
 * stdout is a private, bounded big-endian transport, NOT the .fidbf format.
 */
import db.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.UniversalIdGenerator;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class FidExport {
    static final int VERSION = 6;
    static final long MAX_FILE = 128L << 20;
    static final long MAX_OUTPUT = 128L << 20;
    static final int MAX_STRING = 4096;
    static final String[] TABLES = {
        "Libraries Table", "Strings Table", "Functions Table", "Inferior Table", "Superior Table"
    };
    static final String[] KEYS = {"Library ID", "String ID", "Function ID", "Relation Smash", "Relation Smash"};
    static final Field[][] FIELDS = {
        {StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
         StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE},
        {StringField.INSTANCE},
        {ShortField.INSTANCE, LongField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
         LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, ByteField.INSTANCE},
        {}, {}
    };
    static final String[][] NAMES = {
        {"Library Family Name", "Library Version", "Library Variant", "Ghidra Version", "Ghidra Language ID",
         "Ghidra Language Version", "Ghidra Language Minor Version", "Ghidra Compiler Spec ID"},
        {"String Value"},
        {"Code Unit Size", "Full Hash", "Specific Hash Additional Size", "Specific Hash", "Library ID",
         "Name ID", "Entry Point", "Domain Path ID", "Flags"},
        {}, {}
    };
    static final int[] LIMITS = {10000, 1000000, 500000, 2000000, 2000000};
    static final int[][] INDEXES = {{0, 1}, {0}, {1, 5}, {}, {}};
    static long outputBytes;

    static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    static void text(DataOutputStream out, String value) throws IOException {
        require(value != null && value.length() <= MAX_STRING, "null or oversized string");
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= MAX_STRING, "oversized UTF-8 string");
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    static Table[] validate(DBHandle db) throws Exception {
        require(db.getTables().length == TABLES.length, "unsupported table inventory");
        Table[] tables = new Table[TABLES.length];
        for (int i = 0; i < TABLES.length; i++) {
            Table table = db.getTable(TABLES[i]);
            require(table != null, "missing FID table");
            Schema schema = table.getSchema();
            require(schema.getVersion() == VERSION && schema.getKeyFieldType() instanceof LongField,
                "unsupported FID schema version or key");
            require(schema.getKeyName().equals(KEYS[i]) && !schema.hasSparseColumns(),
                "unsupported FID key name or sparse columns");
            int[] indexes = table.getIndexedColumns();
            Arrays.sort(indexes);
            require(Arrays.equals(indexes, INDEXES[i]), "missing or unexpected FID indexes");
            require(schema.getFieldCount() == FIELDS[i].length
                && Arrays.equals(schema.getFieldNames(), NAMES[i]), "unsupported FID columns");
            Field[] actual = schema.getFields();
            for (int j = 0; j < actual.length; j++) {
                require(actual[j].getClass() == FIELDS[i][j].getClass(), "unsupported FID field type");
            }
            require(table.getRecordCount() >= 0 && table.getRecordCount() <= LIMITS[i], "record budget");
            tables[i] = table;
        }
        require(db.isConsistent(TaskMonitor.DUMMY), "inconsistent database pages or indexes");
        return tables;
    }

    static String referencedString(Table strings, long key) throws IOException {
        DBRecord record = strings.getRecord(key);
        require(record != null, "dangling string reference");
        return record.getString(0);
    }

    // Ghidra Framework/DB db/buffers/LocalBufferFile.java (12.1.4, Apache-2.0).
    // Validate allocation sizes and the free chain BEFORE the upstream reader allocates/traverses.
    // Raw header v1 is big endian; each user block has a one-byte flag and four-byte ID/free link.
    static void rawHeader(Path input) throws IOException {
        try (RandomAccessFile file = new RandomAccessFile(input.toFile(), "r")) {
            long length = file.length();
            require(length >= 32 && length <= MAX_FILE, "raw file length");
            require(file.readLong() == 0x2f30312c34292c2aL, "not a raw Ghidra buffer database");
            file.readLong(); // Database file identity, not source authentication.
            require(file.readInt() == 1, "unsupported raw buffer header version");
            int blockSize = file.readInt();
            require(blockSize >= 128 && blockSize <= (1 << 20) && length % blockSize == 0,
                "unsupported block size or truncated block");
            int blocks = (int) (length / blockSize) - 1;
            int firstFree = file.readInt();
            int parameters = file.readInt();
            require(parameters >= 0 && parameters <= (blockSize - 32) / 8, "header parameter count");
            Set<String> names = new HashSet<>();
            for (int i = 0; i < parameters; i++) {
                require(file.getFilePointer() + 4 <= blockSize, "header parameter range");
                int size = file.readInt();
                require(size >= 0 && size <= MAX_STRING && file.getFilePointer() + size + 4 <= blockSize,
                    "header parameter size");
                byte[] name = new byte[size];
                file.readFully(name);
                require(names.add(new String(name, StandardCharsets.UTF_8)), "duplicate header parameter");
                file.readInt();
            }
            for (int block = 0; block < blocks; block++) {
                file.seek((long) (block + 1) * blockSize);
                require((file.readUnsignedByte() & ~1) == 0, "unsupported physical block flags");
            }
            BitSet visited = new BitSet(blocks);
            int next = firstFree;
            while (next != -1) {
                require(next >= 0 && next < blocks && !visited.get(next), "free pointer range or cycle");
                visited.set(next);
                file.seek((long) (next + 1) * blockSize);
                require((file.readByte() & 1) != 0, "free pointer targets allocated block");
                next = file.readInt();
            }
        }
    }

    static void export(Path input) throws Exception {
        require(Files.isRegularFile(input, LinkOption.NOFOLLOW_LINKS)
            && Files.size(input) > 0 && Files.size(input) <= MAX_FILE, "input must be bounded regular raw fidbf");
        rawHeader(input);
        DBHandle db = new DBHandle(input.toFile());
        try {
            Table[] tables = validate(db);
            OutputStream bounded = new FilterOutputStream(System.out) {
                @Override public void write(int b) throws IOException {
                    require(++outputBytes <= MAX_OUTPUT, "output budget");
                    out.write(b);
                }
                @Override public void write(byte[] bytes, int offset, int length) throws IOException {
                    require(length <= MAX_OUTPUT - outputBytes, "output budget");
                    outputBytes += length;
                    out.write(bytes, offset, length);
                }
            };
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(bounded));
            out.writeBytes("RPFID001");
            out.writeInt(VERSION);
            out.writeInt(tables[0].getRecordCount());
            RecordIterator libraries = tables[0].iterator();
            while (libraries.hasNext()) {
                DBRecord record = libraries.next();
                out.writeLong(record.getKey());
                for (int i = 0; i < 5; i++) text(out, record.getString(i));
                out.writeInt(record.getIntValue(5));
                out.writeInt(record.getIntValue(6));
                text(out, record.getString(7));
            }
            // Validate even strings not referenced by any function, without retaining a map.
            RecordIterator strings = tables[1].iterator();
            long stringBytes = 0;
            while (strings.hasNext()) {
                String value = strings.next().getString(0);
                require(value != null && value.length() <= MAX_STRING, "invalid string record");
                int size = value.getBytes(StandardCharsets.UTF_8).length;
                require(size <= MAX_STRING && (stringBytes += size) <= (32L << 20), "string budget");
            }
            out.writeInt(tables[2].getRecordCount());
            RecordIterator functions = tables[2].iterator();
            while (functions.hasNext()) {
                DBRecord record = functions.next();
                require(tables[0].getRecord(record.getLongValue(4)) != null, "dangling library reference");
                require(record.getShortValue(0) >= 0 && record.getByteValue(2) >= 0,
                    "invalid FID feature counts");
                require((record.getByteValue(8) & ~31) == 0, "unsupported FID flags");
                out.writeLong(record.getKey());
                out.writeShort(record.getShortValue(0));
                out.writeLong(record.getLongValue(1));
                out.writeByte(record.getByteValue(2));
                out.writeLong(record.getLongValue(3));
                out.writeLong(record.getLongValue(4));
                text(out, referencedString(tables[1], record.getLongValue(5)));
                out.writeLong(record.getLongValue(6));
                text(out, referencedString(tables[1], record.getLongValue(7)));
                out.writeByte(record.getByteValue(8));
            }
            for (int i = 3; i < 5; i++) {
                out.writeInt(tables[i].getRecordCount());
                RecordIterator relations = tables[i].iterator();
                while (relations.hasNext()) out.writeLong(relations.next().getKey());
            }
            out.flush();
        }
        finally {
            db.close();
        }
    }

    // Generates an owned, genuine raw Ghidra database; no imported commercial signature data.
    static void fixture(Path destination) throws Exception {
        require(!Files.exists(destination, LinkOption.NOFOLLOW_LINKS), "fixture destination exists");
        UniversalIdGenerator.initialize();
        DBHandle db = new DBHandle();
        try {
            long transaction = db.startTransaction();
            Table[] tables = new Table[5];
            for (int i = 0; i < 5; i++) {
                Schema schema = new Schema(VERSION, KEYS[i], FIELDS[i], NAMES[i]);
                int[] indexes = i == 0 ? new int[]{0, 1} : i == 1 ? new int[]{0}
                    : i == 2 ? new int[]{1, 5} : new int[]{};
                tables[i] = db.createTable(TABLES[i], schema, indexes);
            }
            DBRecord library = tables[0].getSchema().createRecord(1);
            String[] metadata = {"rampage-owned-fid", "1.0", "fixture", "12.1.4", "x86:LE:64:default"};
            for (int i = 0; i < metadata.length; i++) library.setString(i, metadata[i]);
            library.setIntValue(5, 4);
            library.setIntValue(6, 6);
            library.setString(7, "gcc");
            tables[0].putRecord(library);
            for (int i = 0; i < 3; i++) {
                DBRecord string = tables[1].getSchema().createRecord(i + 1);
                string.setString(0, new String[]{"owned_fid_mix", "/untrusted/not-opened.c", "owned_fid_leaf"}[i]);
                tables[1].putRecord(string);
            }
            for (int i = 0; i < 2; i++) {
                DBRecord function = tables[2].getSchema().createRecord(100 + i);
                function.setShortValue(0, (short) 8);
                function.setLongValue(1, 0x9a12345678123456L + i);
                function.setByteValue(2, (byte) 2);
                function.setLongValue(3, 0xbc12345678123456L + i);
                function.setLongValue(4, 1);
                function.setLongValue(5, i == 0 ? 1 : 3);
                function.setLongValue(6, 0x401000 + i * 32);
                function.setLongValue(7, 2);
                function.setByteValue(8, (byte) (i == 0 ? 17 : 1));
                tables[2].putRecord(function);
            }
            tables[3].putRecord(tables[3].getSchema().createRecord(
                101L * 1099511628211L ^ 0x9a12345678123456L));
            tables[4].putRecord(tables[4].getSchema().createRecord(
                100L * 1099511628211L ^ 0x9a12345678123457L));
            db.endTransaction(transaction, true);
            db.saveAs(destination.toFile(), false, TaskMonitor.DUMMY);
        }
        finally {
            db.close();
        }
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 2, "usage: FidExport export|fixture explicit-path");
        if (args[0].equals("export")) export(Path.of(args[1]));
        else if (args[0].equals("fixture")) fixture(Path.of(args[1]));
        else throw new IOException("unsupported operation");
    }
}

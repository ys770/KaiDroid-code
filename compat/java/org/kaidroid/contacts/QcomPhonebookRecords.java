package org.kaidroid.contacts;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Raw field decoder for the pinned convertAdnRecords format, not a charset decoder. */
public final class QcomPhonebookRecords {
    public static final class Record {
        public final int id;
        private final byte[] first, second;
        private final List<byte[]> firstList, secondList;

        private Record(int id, byte[] first, byte[] second, List<byte[]> firstList, List<byte[]> secondList) {
            this.id = id;
            this.first = first;
            this.second = second;
            this.firstList = firstList;
            this.secondList = secondList;
        }
        // Semantic labels and character encoding await modem population evidence.
        public byte[] firstField() { return first.clone(); }
        public byte[] secondField() { return second.clone(); }
        public List<byte[]> firstList() { return copy(firstList); }
        public List<byte[]> secondList() { return copy(secondList); }
    }

    public static final class Batch {
        public final List<Record> records;
        private final byte[] padding;
        private Batch(List<Record> records, byte[] padding) {
            this.records = Collections.unmodifiableList(records);
            this.padding = padding;
        }
        /** Preserve extra allocation bytes without treating them as fields or text. */
        public byte[] padding() { return padding.clone(); }
    }

    private static List<byte[]> copy(List<byte[]> values) {
        List<byte[]> result = new ArrayList<>(values.size());
        for (byte[] value : values) result.add(value.clone());
        return Collections.unmodifiableList(result);
    }

    /** Limits are caller budgets, not measured modem capabilities. */
    public static Batch decode(byte[] payload, int maxRecords, int maxFieldBytes, int maxListEntries) {
        if (payload == null || maxRecords < 0 || maxFieldBytes < 0 || maxListEntries < 0) {
            throw new IllegalArgumentException("Missing payload or negative budget");
        }
        Reader reader = new Reader(payload, maxFieldBytes, maxListEntries);
        int count = reader.u16();
        // Each record requires at least 10 field-header bytes and one padding byte.
        if (count > maxRecords || count > reader.remaining() / 11) {
            throw new IllegalArgumentException("Record count exceeds budget or payload");
        }
        List<Record> records = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            records.add(new Record(reader.u16(), reader.field(), reader.field(), reader.list(), reader.list()));
        }
        if (reader.remaining() != count) {
            throw new IllegalArgumentException("Unexpected serializer padding length");
        }
        byte[] padding = Arrays.copyOfRange(payload, reader.offset, payload.length);
        // Original code explicitly writes the first zero only. Remaining bytes
        // depend on the allocator and must not be assumed to be zero-filled.
        if (count > 0 && padding[0] != 0) {
            throw new IllegalArgumentException("Missing serializer terminator");
        }
        return new Batch(records, padding);
    }

    private static final class Reader {
        private final byte[] bytes;
        private final int maxFieldBytes;
        private int listBudget;
        private int offset;
        Reader(byte[] bytes, int maxFieldBytes, int listBudget) {
            this.bytes = bytes;
            this.maxFieldBytes = maxFieldBytes;
            this.listBudget = listBudget;
        }
        int remaining() { return bytes.length - offset; }
        int u16() {
            if (remaining() < 2) throw new IllegalArgumentException("Truncated integer");
            int value = (bytes[offset] & 255) | ((bytes[offset + 1] & 255) << 8);
            offset += 2;
            return value;
        }
        byte[] field() {
            int length = u16();
            if (length > maxFieldBytes || length > remaining()) {
                throw new IllegalArgumentException("Field exceeds budget or payload");
            }
            byte[] result = Arrays.copyOfRange(bytes, offset, offset + length);
            offset += length;
            return result;
        }
        List<byte[]> list() {
            int count = u16();
            if (count > listBudget || count > remaining() / 2) {
                throw new IllegalArgumentException("List exceeds budget or payload");
            }
            listBudget -= count;
            List<byte[]> result = new ArrayList<>(count);
            for (int i = 0; i < count; i++) result.add(field());
            return result;
        }
    }

    private QcomPhonebookRecords() {}
}

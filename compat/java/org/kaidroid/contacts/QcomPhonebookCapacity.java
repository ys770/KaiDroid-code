package org.kaidroid.contacts;

/** Solicited 40-byte response decoder; not a notification or request parser. */
public final class QcomPhonebookCapacity {
    private final int[] counts;
    private final long[] rawLengthLimits;

    public static final class ModemError extends Exception {
        public final int code;
        private ModemError(int code) {
            super("Phonebook response error " + code);
            this.code = code;
        }
    }

    private QcomPhonebookCapacity(int[] counts, long[] lengths) {
        this.counts = counts;
        this.rawLengthLimits = lengths;
    }

    /** Caller must associate the response with the correct request and card generation.
     * A successful decode alone does not prove subscription scope or card presence.
     */
    public static QcomPhonebookCapacity decode(int responseError, byte[] payload)
            throws ModemError {
        // Original callback can forward full data with an error. Never consume it.
        if (responseError != 0) throw new ModemError(responseError);
        if (payload == null || payload.length != 40) {
            throw new IllegalArgumentException("Expected exactly 40 capacity bytes");
        }
        int[] counts = new int[6];
        for (int i = 0; i < counts.length; i++) {
            long value = word(payload, i);
            if (value > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Count outside supported nonnegative range");
            }
            counts[i] = (int) value;
        }
        for (int i = 0; i < counts.length; i += 2) {
            if (counts[i + 1] > counts[i]) {
                throw new IllegalArgumentException("Used capacity exceeds total");
            }
        }
        long[] lengths = new long[4];
        for (int i = 0; i < lengths.length; i++) lengths[i] = word(payload, i + 6);
        return new QcomPhonebookCapacity(counts, lengths);
    }

    /** Total/used ADN, total/used email, total/used additional numbers. */
    public int[] measuredCounts() { return counts.clone(); }

    /** Name, number, email, ANR words, preserved unsigned without interpreting units.
     * Do not use these as UI character limits until encoding and sentinel semantics
     * are verified. They are not part of TCL's successful six-count contract.
     */
    public long[] rawLengthLimits() { return rawLengthLimits.clone(); }

    private static long word(byte[] data, int index) {
        int p = index * 4;
        return (data[p] & 255L) | ((data[p + 1] & 255L) << 8)
                | ((data[p + 2] & 255L) << 16) | ((data[p + 3] & 255L) << 24);
    }
}

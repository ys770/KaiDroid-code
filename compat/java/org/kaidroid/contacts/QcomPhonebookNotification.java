package org.kaidroid.contacts;

import java.util.Arrays;

/** Parser for the complete envelope produced by the pinned Qualcomm serializer.
 * Not a request builder, capacity decoder, or inner contact-record decoder.
 */
public final class QcomPhonebookNotification {
    private static final byte[] MARKER = {'Q', 'O', 'E', 'M', 'H', 'O', 'O', 'K'};
    private static final int HEADER_BYTES = 20;
    private static final long RECORD_NOTIFICATION = 0x8040bL;

    private QcomPhonebookNotification() {}

    /**
     * Returns an isolated copy of the still-encoded records payload.
     * maxPayloadBytes is a caller resource limit, not an inferred modem maximum.
     * Requires the full 20-byte envelope: callers must not add guessed prefixes
     * to a callback with a different representation.
     */
    public static byte[] recordsPayload(byte[] envelope, int maxPayloadBytes) {
        if (maxPayloadBytes < 0) throw new IllegalArgumentException("Negative payload limit");
        if (envelope == null || envelope.length < HEADER_BYTES) {
            throw new IllegalArgumentException("Truncated notification header");
        }
        if (unsignedInt(envelope, 0) != 0x404L) {
            throw new IllegalArgumentException("Unexpected notification prefix");
        }
        for (int i = 0; i < MARKER.length; i++) {
            if (envelope[i + 4] != MARKER[i]) {
                throw new IllegalArgumentException("Unexpected OEM marker");
            }
        }
        if (unsignedInt(envelope, 12) != RECORD_NOTIFICATION) {
            throw new IllegalArgumentException("Not an ADN records notification");
        }
        long payloadLength = unsignedInt(envelope, 16);
        if (payloadLength > maxPayloadBytes) {
            throw new IllegalArgumentException("Notification exceeds caller limit");
        }
        if (payloadLength != envelope.length - HEADER_BYTES) {
            throw new IllegalArgumentException("Notification length mismatch");
        }
        return Arrays.copyOfRange(envelope, HEADER_BYTES, envelope.length);
    }

    private static long unsignedInt(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8)
                | ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }
}

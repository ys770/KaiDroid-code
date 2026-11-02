/** Exercises the actual helper's mutation eligibility without Android Binder. */
public final class ContactsPermissionStateHostTest {
    public static void main(String[] args) throws Exception {
        int checks = 0;
        // Every non-user bit is preserved, including unknown future bits.
        for (int bit = 2; bit < 32; bit++) {
            int mask = 1 << bit;
            if (ContactsPermissionState.restorable(mask, 0, false, true)
                    || ContactsPermissionState.restorable(0, mask, false, true))
                throw new AssertionError("Protected flag accepted: " + bit);
            checks += 2;
        }
        for (int before = 0; before < 4; before++) {
            for (int after = 0; after < 4; after++) {
                for (boolean baseGrant : new boolean[]{false, true}) {
                    for (boolean nowGrant : new boolean[]{false, true}) {
                        boolean expected = !baseGrant || nowGrant;
                        // Preserve a non-user default-grant flag in both states.
                        boolean actual = ContactsPermissionState.restorable(32 | before,
                                32 | after, baseGrant, nowGrant);
                        if (actual != expected) throw new AssertionError("Grant/flag eligibility mismatch");
                        checks++;
                    }
                }
            }
        }
        java.nio.file.Path sample = java.nio.file.Files.createTempFile("contacts-hash-", ".bin");
        try {
            for (int size : new int[]{0, 1, 16383, 16384, 16385, 12300407}) {
                byte[] data = new byte[size];
                new java.util.Random(42).nextBytes(data);
                java.nio.file.Files.write(sample, data);
                byte[] expected = java.security.MessageDigest.getInstance("SHA-256").digest(data);
                if (!java.util.Arrays.equals(expected, ContactsPermissionState.sha256(sample)))
                    throw new AssertionError("Streaming hash differs at size " + size);
            }
        } finally {
            java.nio.file.Files.delete(sample);
        }
        System.out.println("6 streaming hash equivalence cases passed");
        System.out.println(checks + " mutation eligibility assertions passed; Binder/runtime untested");
    }
}

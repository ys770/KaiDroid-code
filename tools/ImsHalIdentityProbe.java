import dalvik.system.DexClassLoader;
import java.util.List;

/** Read-only HIDL base calls using the candidate's actual generated client. */
public final class ImsHalIdentityProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("candidate.apk cache");
        DexClassLoader loader = new DexClassLoader(args[0], args[1], null,
                ImsHalIdentityProbe.class.getClassLoader());
        for (String version : new String[]{"V1_0", "V1_4"}) {
            String name = "vendor.qti.hardware.radio.ims." + version + ".IImsRadio";
            Class<?> type = loader.loadClass(name);
            if (type.getClassLoader() != loader) throw new AssertionError("Not candidate client");
            Object service = type.getMethod("getService", String.class, boolean.class)
                    .invoke(null, "imsradio0", false);
            if (service == null) throw new AssertionError("Missing " + version + " service");
            System.out.println("CLIENT " + version + " " + service.getClass().getName());
            List<?> chain = (List<?>) type.getMethod("interfaceChain").invoke(service);
            String expected = "vendor.qti.hardware.radio.ims@" + version.substring(1).replace('_', '.')
                    + "::IImsRadio";
            if (!chain.contains(expected)) throw new AssertionError("Missing expected interface");
            System.out.println("CHAIN " + chain);
            List<?> hashes = (List<?>) type.getMethod("getHashChain").invoke(service);
            if (hashes.size() != chain.size()) throw new AssertionError("Hash chain size mismatch");
            for (Object value : hashes) {
                byte[] hash = (byte[]) value;
                if (hash.length != 32) throw new AssertionError("Wrong hash size");
                StringBuilder hex = new StringBuilder();
                for (byte b : hash) hex.append(String.format("%02x", b & 255));
                System.out.println("HASH " + hex);
            }
            type.getMethod("ping").invoke(service);
            System.out.println("PING_PASS " + version);
        }
        System.out.println("PASS base-interface identity only; no radio operation or callback registration");
        System.exit(0);
    }
}

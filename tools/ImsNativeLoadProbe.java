import dalvik.system.DexClassLoader;
import java.lang.reflect.InvocationTargetException;

/** Loads one candidate JNI library in a disposable process; no IMS service start. */
public final class ImsNativeLoadProbe {
    public static final class Call {
        public static void load(String library) {
            System.out.println("LOAD_BEGIN " + library);
            System.loadLibrary(library);
            System.out.println("LOAD_RETURNED " + library);
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("probe apk libs cache library");
        if (!args[4].equals("imscamera_jni") && !args[4].equals("imsmedia_jni")) {
            throw new IllegalArgumentException("Unexpected library");
        }
        final String child = "ImsNativeLoadProbe$Call";
        DexClassLoader loader = new DexClassLoader(args[0] + ":" + args[1], args[3], args[2],
                ImsNativeLoadProbe.class.getClassLoader()) {
            @Override protected synchronized Class<?> loadClass(String name, boolean resolve)
                    throws ClassNotFoundException {
                if (!name.equals(child)) return super.loadClass(name, resolve);
                Class<?> c = findLoadedClass(name);
                if (c == null) c = findClass(name);
                if (resolve) resolveClass(c);
                return c;
            }
        };
        Class<?> call = loader.loadClass(child);
        if (call.getClassLoader() != loader) throw new AssertionError("Wrong loader");
        try {
            call.getMethod("load", String.class).invoke(null, args[4]);
        } catch (InvocationTargetException error) {
            error.getCause().printStackTrace();
            System.exit(2);
        }
        System.out.println("LOAD_ONLY_PASS; shell UID/namespace, not installed IMS process");
        System.exit(0);
    }
}

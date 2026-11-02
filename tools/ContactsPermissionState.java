import android.app.AppOpsManager;
import android.os.IBinder;
import android.content.pm.PackageInfo;
import org.json.JSONObject;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.TreeSet;

/** Root app_process helper for one reviewed Contacts trial. No grant operation. */
public final class ContactsPermissionState {
    static final String PKG = "com.android.contacts";
    static final int UID = 10073, USER = 0, USER_FLAGS = 3;
    static final String[] PERMS = {"GET_ACCOUNTS", "READ_CONTACTS", "WRITE_CONTACTS",
            "CALL_PHONE", "READ_CALL_LOG", "READ_PHONE_STATE", "READ_SMS"};
    static Object permission, ops, packages;

    static Object call(Object object, String iface, String name, Class<?>[] types,
                       Object... args) throws Exception {
        return Class.forName(iface).getMethod(name, types).invoke(object, args);
    }
    static Object service(String name, String iface) throws Exception {
        Object binder = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, name);
        if (binder == null) throw new IllegalStateException("Missing service " + name);
        return Class.forName(iface + "$Stub").getMethod("asInterface", IBinder.class)
                .invoke(null, binder);
    }
    static String prop(String key) throws Exception {
        return (String) Class.forName("android.os.SystemProperties")
                .getMethod("get", String.class).invoke(null, key);
    }
    static String boot() throws Exception {
        return new String(Files.readAllBytes(Paths.get("/proc/sys/kernel/random/boot_id")), "UTF-8").trim();
    }
    static int opFunction(String name, Class<?> type, Object value) throws Exception {
        return (Integer) AppOpsManager.class.getMethod(name, type).invoke(null, value);
    }
    static TreeSet<Integer> codes() throws Exception {
        TreeSet<Integer> result = new TreeSet<>();
        for (String shortName : PERMS) {
            int code = opFunction("permissionToOpCode", String.class, "android.permission." + shortName);
            if (code < 0) throw new IllegalStateException("Permission has no op");
            result.add(opFunction("opToSwitch", int.class, code));
        }
        return result;
    }
    static byte[] sha256(java.nio.file.Path path) throws Exception {
        java.security.MessageDigest hash = java.security.MessageDigest.getInstance("SHA-256");
        try (java.io.InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[16384];
            int count;
            while ((count = input.read(buffer)) != -1) hash.update(buffer, 0, count);
        }
        return hash.digest();
    }
    static void guard() throws Exception {
        if (android.os.Process.myUid() != 0 || !"1".equals(prop("ro.debuggable"))
                || !"36".equals(prop("ro.kaidroid.image"))) throw new IllegalStateException("Wrong root/image");
        String[] names = (String[]) call(packages, "android.content.pm.IPackageManager", "getPackagesForUid",
                new Class[]{int.class}, UID);
        if (names == null || names.length != 1 || !PKG.equals(names[0]))
            throw new IllegalStateException("Unexpected/shared UID");
        PackageInfo info = (PackageInfo) call(packages, "android.content.pm.IPackageManager", "getPackageInfo",
                new Class[]{String.class, int.class, int.class}, PKG, 0, USER);
        if (info == null || info.getLongVersionCode() != 122209261L)
            throw new IllegalStateException("Candidate is not installed");
        byte[] digest = sha256(Paths.get(info.applicationInfo.sourceDir));
        StringBuilder hex = new StringBuilder();
        for (byte value : digest) hex.append(String.format("%02x", value & 255));
        if (!hex.toString().equals("20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248"))
            throw new IllegalStateException("Unexpected candidate APK");
    }
    static JSONObject modes(boolean uid) throws Exception {
        TreeSet<Integer> wanted = codes();
        int[] filter = new int[wanted.size()]; int i = 0;
        JSONObject result = new JSONObject();
        for (int code : wanted) {
            filter[i++] = code;
            result.put(Integer.toString(code), opFunction("opToDefaultMode", int.class, code));
        }
        List<?> rows = (List<?>) (uid
                ? call(ops, "com.android.internal.app.IAppOpsService", "getUidOps",
                        new Class[]{int.class, int[].class}, UID, filter)
                : call(ops, "com.android.internal.app.IAppOpsService", "getOpsForPackage",
                        new Class[]{int.class, String.class, int[].class}, UID, PKG, filter));
        if (rows != null) for (Object row : rows) {
            List<?> entries = (List<?>) row.getClass().getMethod("getOps").invoke(row);
            for (Object entry : entries) {
                int code = (Integer) entry.getClass().getMethod("getOp").invoke(entry);
                if (!wanted.contains(code)) throw new IllegalStateException("Unexpected op");
                result.put(Integer.toString(code), entry.getClass().getMethod("getMode").invoke(entry));
            }
        }
        return result;
    }
    static JSONObject snapshot() throws Exception {
        guard();
        JSONObject result = new JSONObject().put("package", PKG).put("uid", UID)
                .put("boot", boot()).put("image", prop("ro.kaidroid.image"));
        JSONObject permissions = new JSONObject();
        for (String name : PERMS) {
            String full = "android.permission." + name;
            int flags = (Integer) call(permission, "android.permission.IPermissionManager", "getPermissionFlags",
                    new Class[]{String.class, String.class, int.class}, full, PKG, USER);
            int granted = (Integer) call(permission, "android.permission.IPermissionManager", "checkPermission",
                    new Class[]{String.class, String.class, int.class}, full, PKG, USER);
            permissions.put(name, new JSONObject().put("flags", flags).put("granted", granted == 0));
        }
        return result.put("permissions", permissions).put("uid_modes", modes(true)).put("package_modes", modes(false));
    }
    static void validate(JSONObject base, JSONObject now) throws Exception {
        for (String key : new String[]{"package", "uid", "boot", "image"})
            if (!base.get(key).equals(now.get(key))) throw new IllegalStateException("Identity mismatch " + key);
        JSONObject bp = base.getJSONObject("permissions"), np = now.getJSONObject("permissions");
        if (bp.length() != PERMS.length) throw new IllegalStateException("Invalid permission scope");
        for (String name : PERMS) {
            JSONObject b = bp.getJSONObject(name), n = np.getJSONObject(name);
            if (!restorable(b.getInt("flags"), n.getInt("flags"),
                    b.getBoolean("granted"), n.getBoolean("granted")))
                throw new IllegalStateException("Non-user flag changed or baseline grant lost: " + name);
        }
        for (String key : new String[]{"uid_modes", "package_modes"}) {
            JSONObject bm = base.getJSONObject(key);
            if (bm.length() != codes().size()) throw new IllegalStateException("Invalid op scope");
            for (int code : codes()) {
                int value = bm.getInt(Integer.toString(code));
                if (value < 0 || value > 4) throw new IllegalStateException("Invalid op mode");
            }
        }
    }
    static boolean restorable(int baselineFlags, int currentFlags,
                              boolean baselineGranted, boolean currentGranted) {
        return ((baselineFlags ^ currentFlags) & ~USER_FLAGS) == 0
                && (!baselineGranted || currentGranted);
    }
    static void restore(JSONObject base, boolean requireNoop) throws Exception {
        JSONObject now = snapshot();
        validate(base, now); // Validate every entry before the first mutation.
        if (requireNoop && !equal(base, now)) throw new IllegalStateException("No-op baseline changed");
        for (String name : PERMS) {
            JSONObject b = base.getJSONObject("permissions").getJSONObject(name);
            JSONObject n = now.getJSONObject("permissions").getJSONObject(name);
            if (!b.getBoolean("granted") && n.getBoolean("granted"))
                call(permission, "android.permission.IPermissionManager", "revokeRuntimePermission",
                        new Class[]{String.class, String.class, int.class, String.class},
                        PKG, "android.permission." + name, USER, "Restore bounded Contacts trial baseline");
        }
        // Revocation schedules permission-policy synchronization. Do not race it
        // with app-op writes: this helper verifies modes, and never resets them.
        Thread.sleep(1500);
        now = snapshot();
        validate(base, now);
        if (requireNoop && !equal(base, now)) throw new IllegalStateException("No-op baseline changed while settling");
        for (String name : PERMS) {
            int wanted = base.getJSONObject("permissions").getJSONObject(name).getInt("flags");
            int current = now.getJSONObject("permissions").getJSONObject(name).getInt("flags");
            if (wanted != current)
                call(permission, "android.permission.IPermissionManager", "updatePermissionFlags",
                        new Class[]{String.class, String.class, int.class, int.class, boolean.class, int.class},
                        "android.permission." + name, PKG, USER_FLAGS, wanted & USER_FLAGS, false, USER);
        }
    }
    static boolean equal(JSONObject a, JSONObject b) throws Exception {
        if (a.length() != b.length()) return false;
        java.util.Iterator<String> keys = a.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object av = a.get(key), bv = b.get(key);
            if (av instanceof JSONObject ? !(bv instanceof JSONObject) || !equal((JSONObject) av, (JSONObject) bv)
                    : !av.equals(bv)) return false;
        }
        return true;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !(args[0].equals("capture") || args[0].equals("verify")
                || args[0].equals("restore") || args[0].equals("restore-noop")))
            throw new IllegalArgumentException("capture|verify|restore|restore-noop BASELINE_JSON");
        permission = service("permissionmgr", "android.permission.IPermissionManager");
        ops = service("appops", "com.android.internal.app.IAppOpsService");
        packages = service("package", "android.content.pm.IPackageManager");
        if (args[0].equals("capture")) {
            JSONObject state = snapshot();
            Files.write(Paths.get(args[1]), state.toString(2).getBytes("UTF-8"), java.nio.file.StandardOpenOption.CREATE_NEW);
            System.out.println(state.toString(2)); return;
        }
        JSONObject base = new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])), "UTF-8"));
        validate(base, snapshot());
        if (args[0].equals("restore") || args[0].equals("restore-noop"))
            restore(base, args[0].equals("restore-noop"));
        JSONObject after = snapshot();
        System.out.println(after.toString(2));
        if (!equal(base, after)) throw new IllegalStateException("Baseline mismatch; preserve evidence and stop");
        System.out.println("Scoped grants, flags and normalized app-op modes match baseline");
    }
}

import android.content.res.Resources;
import android.os.SystemClock;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Bounded, read-only resource JNI timing. Not a boot or UI benchmark. */
public final class ResourceJniProbe36 {
    private static String prop(String name) throws Exception {
        return (String) Class.forName("android.os.SystemProperties")
            .getMethod("get", String.class).invoke(null, name);
    }
    public static void main(String[] args) throws Exception {
        String boot = new String(Files.readAllBytes(Paths.get("/proc/sys/kernel/random/boot_id")), "UTF-8").trim();
        if (!"36".equals(prop("ro.kaidroid.image")) ||
            !"00000000-0000-0000-0000-000000000014".equals(boot))
            throw new IllegalStateException("Wrong image/boot");
        Resources resources = Resources.getSystem();
        int checksum = 0;
        for (int i=0; i<1000; i++) checksum += resources.getResourceTypeName(android.R.id.content).length();
        long wall = SystemClock.elapsedRealtimeNanos();
        long cpu = SystemClock.currentThreadTimeMillis();
        for (int i=0; i<20000; i++) checksum += resources.getResourceTypeName(android.R.id.content).length();
        long elapsed = SystemClock.elapsedRealtimeNanos()-wall;
        long cpuMs = SystemClock.currentThreadTimeMillis()-cpu;
        if (checksum != 42000) throw new IllegalStateException("Unexpected lookup result");
        System.out.println(new JSONObject().put("boot", boot).put("iterations", 20000)
            .put("wall_ms", elapsed/1000000.0).put("thread_cpu_ms", cpuMs)
            .put("checkjni_override", prop("dalvik.vm.checkjni"))
            .put("kernel_checkjni", prop("ro.kernel.android.checkjni")));
    }
}

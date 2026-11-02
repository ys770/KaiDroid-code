import android.os.SystemClock;
import android.view.InputEvent;
import android.view.KeyEvent;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;

/** One VM, three bounded sleep/wake cycles. No settings or credential changes. */
public final class WakeLatencyProbe {
    static Object manager;
    static Method inject;
    static String boot;
    static void guard() throws Exception {
        String current = new String(Files.readAllBytes(Paths.get(
                "/proc/sys/kernel/random/boot_id")), "UTF-8").trim();
        String image = (String) Class.forName("android.os.SystemProperties")
                .getMethod("get", String.class).invoke(null, "ro.kaidroid.image");
        if (!boot.equals(current) || !"34".equals(image))
            throw new IllegalStateException("Unexpected image or boot");
    }
    static void key(int code, int cycle) throws Exception {
        guard();
        long start = SystemClock.uptimeMillis();
        for (int action : new int[]{KeyEvent.ACTION_DOWN, KeyEvent.ACTION_UP}) {
            KeyEvent event = new KeyEvent(start, SystemClock.uptimeMillis(), action,
                    code, 0, 0, -1, 0, 0, 0x101);
            if (!(Boolean) inject.invoke(manager, event, 2))
                throw new IllegalStateException("Injection rejected");
        }
        System.out.println(new JSONObject().put("cycle", cycle).put("key", code)
                .put("start_uptime_ms", start)
                .put("dispatch_finished_ms", SystemClock.uptimeMillis() - start));
        System.out.flush();
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !args[0].matches("[0-9a-f-]{36}"))
            throw new IllegalArgumentException("Expected boot UUID");
        boot = args[0]; guard();
        Class<?> cls = Class.forName("android.hardware.input.InputManager");
        manager = cls.getMethod("getInstance").invoke(null);
        inject = cls.getMethod("injectInputEvent", InputEvent.class, int.class);
        SystemClock.sleep(5000);
        for (int cycle = 1; cycle <= 3; cycle++) {
            key(KeyEvent.KEYCODE_SLEEP, cycle);
            SystemClock.sleep(3000);
            key(KeyEvent.KEYCODE_WAKEUP, cycle);
            SystemClock.sleep(5000);
        }
        System.out.println("COMPLETE");
    }
}

import android.os.SystemClock;
import android.view.InputEvent;
import android.view.KeyEvent;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

/** One 3-second power hold; never selects an action in the resulting menu. */
public final class PowerHoldProbe35 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected boot UUID");
        String boot = new String(Files.readAllBytes(Paths.get(
                "/proc/sys/kernel/random/boot_id")), "UTF-8").trim();
        Method prop = Class.forName("android.os.SystemProperties").getMethod("get", String.class);
        if (!boot.equals(args[0]) || !"35".equals(prop.invoke(null, "ro.kaidroid.image"))
                || !"true".equals(prop.invoke(null, "ro.kaidroid.power_endcall")))
            throw new IllegalStateException("Unexpected boot or policy");
        Class<?> cls = Class.forName("android.hardware.input.InputManager");
        Object manager = cls.getMethod("getInstance").invoke(null);
        Method inject = cls.getMethod("injectInputEvent", InputEvent.class, int.class);
        long start = SystemClock.uptimeMillis();
        KeyEvent down = new KeyEvent(start, start, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_POWER,
                0, 0, -1, 0, 0, 0x101);
        try {
            if (!(Boolean) inject.invoke(manager, down, 2))
                throw new IllegalStateException("Down rejected");
            SystemClock.sleep(3000);
        } finally {
            KeyEvent up = new KeyEvent(start, SystemClock.uptimeMillis(), KeyEvent.ACTION_UP,
                    KeyEvent.KEYCODE_POWER, 0, 0, -1, 0, 0, 0x101);
            if (!(Boolean) inject.invoke(manager, up, 2))
                throw new IllegalStateException("Up rejected");
        }
        System.out.println("POWER_RELEASED duration_ms=" + (SystemClock.uptimeMillis() - start));
    }
}

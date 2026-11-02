import android.animation.Animator;
import android.animation.Animator$AnimatorListener$DCC;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.ServiceConnection$DCC;
import android.os.IBinder;

public class DefaultCallbackBridgeTest {
    public static void main(String[] args) {
        final int[] counts = new int[4];
        Animator.AnimatorListener listener = new Animator.AnimatorListener() {
            public void onAnimationStart(Animator value) { counts[0]++; }
            public void onAnimationEnd(Animator value) { counts[1]++; }
            public void onAnimationCancel(Animator value) { throw new AssertionError(); }
            public void onAnimationRepeat(Animator value) { throw new AssertionError(); }
            // Calling the reverse-aware overload would recurse through donor bridges.
            public void onAnimationStart(Animator value, boolean reverse) { throw new AssertionError(); }
            public void onAnimationEnd(Animator value, boolean reverse) { throw new AssertionError(); }
        };
        for (boolean reverse : new boolean[] {false, true}) {
            Animator$AnimatorListener$DCC.$default$onAnimationStart(listener, null, reverse);
            Animator$AnimatorListener$DCC.$default$onAnimationEnd(listener, null, reverse);
        }
        ServiceConnection connection = new ServiceConnection() {
            public void onServiceConnected(ComponentName name, IBinder binder) { counts[2]++; }
            public void onServiceDisconnected(ComponentName name) { counts[3]++; }
            public void onBindingDied(ComponentName name) { throw new AssertionError(); }
            public void onNullBinding(ComponentName name) { throw new AssertionError(); }
        };
        ServiceConnection$DCC.$default$onBindingDied(connection, null);
        ServiceConnection$DCC.$default$onNullBinding(connection, null);
        if (counts[0] != 2 || counts[1] != 2 || counts[2] != 0 || counts[3] != 0) {
            throw new AssertionError(java.util.Arrays.toString(counts));
        }
        System.out.println("Default callbacks: reverse overloads delegate once; service defaults remain empty");
    }
}

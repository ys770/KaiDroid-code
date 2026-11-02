package android.content;

/** Original bridge retaining Android11's empty default callbacks.
 * Does not simulate a service connection, binding result or hardware operation.
 */
public final class ServiceConnection$DCC {
    private ServiceConnection$DCC() { }

    public static void $default$onBindingDied(ServiceConnection connection, ComponentName name) {
        // Android11 default body is empty; do not synthesize onServiceDisconnected.
    }

    public static void $default$onNullBinding(ServiceConnection connection, ComponentName name) {
        // Android11 default body is empty; caller remains responsible for unbinding.
    }
}

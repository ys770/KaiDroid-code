package android.widget;

/**
 * Immutable display values in center/left/right order. Original KaiDroid code.
 * Icon payloads are borrowed, not modified; their owner must keep them stable.
 * @hide
 */
public final class KeypadSoftkeyState<T> {
    public static final int CENTER = 0;
    public static final int LEFT = 1;
    public static final int RIGHT = 2;
    public static final String AUTO = "@SK_AUTO";

    public static final class Slot<T> {
        public final String text;
        public final String readout;
        public final T icon;
        public final boolean enabled;

        public Slot(String text, String readout, T icon, boolean enabled) {
            this.text = text == null ? "" : text;
            this.readout = readout == null ? this.text : readout;
            this.icon = icon;
            this.enabled = enabled;
        }
    }

    private final Slot<T> center;
    private final Slot<T> left;
    private final Slot<T> right;

    public KeypadSoftkeyState(Slot<T> center, Slot<T> left, Slot<T> right) {
        if (center == null || left == null || right == null) {
            throw new IllegalArgumentException("All three soft-key slots are required");
        }
        this.center = center;
        this.left = left;
        this.right = right;
    }

    public Slot<T> get(int index) {
        switch (index) {
            case CENTER: return center;
            case LEFT: return left;
            case RIGHT: return right;
            default: throw new IndexOutOfBoundsException("soft-key index " + index);
        }
    }

    /**
     * Select the window supplying the bar, preserving full per-slot values.
     * A null focused state means no update, not an instruction to clear the bar.
     * Special labels other than AUTO are resolved by the later display stage.
     * Caller supplies the visible IME and whether focus is an IME dialog.
     */
    public static <T> KeypadSoftkeyState<T> resolve(KeypadSoftkeyState<T> focused,
            KeypadSoftkeyState<T> ime, boolean imeDialog, boolean merge) {
        if (focused == null) return null;
        if (ime == null || imeDialog) return focused;
        if (!merge) return ime;
        return new KeypadSoftkeyState<T>(inherit(focused.center, ime.center),
                inherit(focused.left, ime.left), inherit(focused.right, ime.right));
    }

    private static <T> Slot<T> inherit(Slot<T> app, Slot<T> ime) {
        return AUTO.equals(ime.text) ? app : ime;
    }
}

package android.widget;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Original state policy for the observed TCL keyboard mode protocol.
 * The framework adapter must supply current editor ownership and IMMS status;
 * broadcasts are display data, never proof of that ownership. Main-thread only.
 * @hide
 */
public final class KeypadImeModeState {
    public static final String IME =
            "com.iqqijni.dvt912key/.keyboard_service.view.HDKeyboardService";
    private static final String FULL_IME =
            "com.iqqijni.dvt912key/com.iqqijni.dvt912key.keyboard_service.view.HDKeyboardService";
    private static final String ON = "kika.ime.state.on.";
    private static final String OFF = "kika.ime.state.off";
    private Object editor;
    private boolean displayEligible;
    private long generation;
    private String label;
    private List<String> available = Collections.emptyList();

    static boolean isSupportedIme(String ime) { return IME.equals(ime) || FULL_IME.equals(ime); }

    /** editorToken is identity-stable for one focused editor, not its package name. */
    public long updateOwner(Object editorToken, String selectedIme, int imeStatus,
            boolean windowFocused, boolean interactive) {
        boolean eligible = editorToken != null && interactive
                && isSupportedIme(selectedIme)
                && imeStatus > 0 && imeStatus <= 3;
        Object next = eligible ? editorToken : null;
        if (next != editor) {
            editor = next;
            invalidate();
        }
        boolean show = eligible && windowFocused;
        if (displayEligible != show) {
            displayEligible = show;
            // Reject queued work across focus transitions without discarding the
            // last mode of the same independently validated IME client/editor.
            generation++;
        }
        return generation;
    }

    private void invalidate() {
        generation++;
        label = null;
        available = Collections.emptyList();
    }

    /** Capture this when queuing local work; old-owner delayed work is rejected. */
    public long generation() { return generation; }

    /** Accept only observed protocol values while independently eligible. */
    public boolean accept(long queuedGeneration, String action, String modes) {
        if (editor == null || queuedGeneration != generation) return false;
        if (OFF.equals(action)) {
            invalidate();
            return true;
        }
        if (action == null || !action.startsWith(ON)) return false;
        String value = action.substring(ON.length());
        String command = commandMode(value);
        if (command == null || modes == null || modes.length() > 128) return false;
        List<String> parsed = new ArrayList<>();
        for (String token : modes.split(":", -1)) {
            String mode = commandMode(token);
            if (mode == null) return false;
            if (!parsed.contains(mode)) parsed.add(mode);
        }
        // Current display state and selectable modes are separate. In the donor,
        // Symbols can be displayed without appearing in the availability list.
        label = value;
        available = Collections.unmodifiableList(parsed);
        return true;
    }

    private static String commandMode(String value) {
        if ("kt9".equals(value) || "Kt9".equals(value) || "KT9".equals(value))
            return "Kt9";
        if ("abc".equals(value) || "Abc".equals(value) || "ABC".equals(value)
                || "123".equals(value) || "Symbols".equals(value)) return value;
        return null;
    }

    public String label() { return displayEligible ? label : null; }
    public List<String> availableModes() {
        return displayEligible ? available : Collections.emptyList();
    }

    /** Only explicit supported selections produce actions; this method sends nothing. */
    public String selectionAction(String requested) {
        String mode = commandMode(requested);
        if (!displayEligible || editor == null || label == null || !available.contains(mode)) return null;
        return "kika.ime.change.to." + mode;
    }

    /** Overlay only the left label, leaving the immutable app state recoverable. */
    public <T> KeypadSoftkeyState<T> display(KeypadSoftkeyState<T> app) {
        if (app == null || !displayEligible || editor == null || label == null) return app;
        return new KeypadSoftkeyState<>(app.get(KeypadSoftkeyState.CENTER),
                new KeypadSoftkeyState.Slot<T>(label, label, null, true),
                app.get(KeypadSoftkeyState.RIGHT));
    }
}

package android.widget;

import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/** Window-local owner of the observed keyboard mode protocol. @hide */
final class KeypadImeController {
    // Image23 recorded focus handover exceeding 500 ms after show() returned.
    // This bounds only attachment; actions still require actual picker focus.
    private static final long PICKER_FOCUS_TIMEOUT_MS = 2000;
    private static final String PACKAGE = "com.iqqijni.dvt912key";
    private static final String[] MODES = {"kt9", "Kt9", "KT9", "abc", "Abc", "ABC", "123", "Symbols"};
    private final MenuBar bar;
    private final Context context;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final KeypadImeModeState state = new KeypadImeModeState();
    private final InputMethodManager imm;
    private final PowerManager power;
    private final KeyguardManager keyguard;
    private final Method statusMethod;
    private boolean attached;
    private ViewTreeObserver tree;
    private View editor;
    private AlertDialog picker;
    private long pickerFocusDeadline;
    private String renderedLabel;
    private long renderedGeneration = -1;
    private final Runnable refresh = () -> refreshOwner();
    private final Runnable pickerFocusTimeout = () -> {
        if (picker != null && pickerFocusDeadline > 0
                && SystemClock.uptimeMillis() >= pickerFocusDeadline && !pickerFocused()) {
            dismissPicker();
            refreshOwner();
        }
    };
    private final ViewTreeObserver.OnGlobalFocusChangeListener focusListener =
            (oldFocus, newFocus) -> requestRefresh();
    private final ContentObserver settingsObserver = new ContentObserver(handler) {
        @Override public void onChange(boolean selfChange) { requestRefresh(); }
    };
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context ignored, Intent intent) {
            if (!attached) return;
            refreshOwner();
            String action = intent.getAction();
            if (action != null && action.startsWith("kika.ime.state.")) {
                // Broadcast contents are display data. Ownership is checked independently.
                if (state.accept(state.generation(), action, intent.getStringExtra("available"))) {
                    if (state.label() == null) dismissPicker();
                    render();
                }
            }
        }
    };

    KeypadImeController(MenuBar bar) {
        this.bar = bar;
        context = bar.getContext();
        imm = context.getSystemService(InputMethodManager.class);
        power = context.getSystemService(PowerManager.class);
        keyguard = context.getSystemService(KeyguardManager.class);
        // Resolve once so the same original source can run in an SDK diagnostic
        // on older images. No bridge means no ownership, never an assumed status.
        Method method;
        try { method = InputMethodManager.class.getMethod("getImeClientWindowStatus"); }
        catch (NoSuchMethodException missing) { method = null; }
        statusMethod = method;
    }

    void attach() {
        if (attached || statusMethod == null) return;
        IntentFilter filter = new IntentFilter();
        for (String mode : MODES) filter.addAction("kika.ime.state.on." + mode);
        filter.addAction("kika.ime.state.off");
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_USER_PRESENT);
        context.registerReceiver(receiver, filter, null, handler);
        context.getContentResolver().registerContentObserver(
                Settings.Secure.getUriFor(Settings.Secure.DEFAULT_INPUT_METHOD), false, settingsObserver);
        tree = bar.getViewTreeObserver();
        tree.addOnGlobalFocusChangeListener(focusListener);
        attached = true;
        requestRefresh();
    }

    void detach() {
        if (attached) {
            attached = false;
            context.unregisterReceiver(receiver);
            context.getContentResolver().unregisterContentObserver(settingsObserver);
            if (tree != null && tree.isAlive()) tree.removeOnGlobalFocusChangeListener(focusListener);
        }
        handler.removeCallbacks(refresh);
        dismissPicker();
        editor = null;
        state.updateOwner(null, null, 0, false, false);
        render();
    }

    void windowFocusChanged(boolean focused) {
        // An SDK host without the framework bridge still constructs this
        // controller, but attach() cannot register an owner. Clear any stale
        // presentation just as MenuBar does before a controller exists.
        if (!attached && !focused) bar.clearImeMode();
        // Refresh synchronously; picker focus callbacks also trigger a fresh evaluation.
        refreshOwner();
    }

    void requestRefresh() {
        if (!attached) return;
        handler.removeCallbacks(refresh);
        handler.post(refresh);
    }

    private int status() {
        if (statusMethod == null || imm == null) return 0;
        try { return (Integer) statusMethod.invoke(imm); }
        catch (ReflectiveOperationException | RuntimeException failure) { return 0; }
    }

    private String selectedIme() {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
    }

    private boolean pickerFocused() {
        return picker != null && picker.isShowing() && picker.getWindow() != null
                && picker.getWindow().getDecorView().hasWindowFocus();
    }

    private void refreshOwner() {
        handler.removeCallbacks(refresh);
        if (!attached) return;
        View focused = bar.getRootView().findFocus();
        boolean interactive = power != null && power.isInteractive()
                && keyguard != null && !keyguard.isKeyguardLocked();
        boolean pickerHasFocus = pickerFocused();
        if (pickerHasFocus) {
            pickerFocusDeadline = 0;
            handler.removeCallbacks(pickerFocusTimeout);
        }
        // A newly added picker receives focus asynchronously. Preserve ownership
        // briefly while that known window is being attached, but never allow a
        // selection until pickerFocused() independently confirms actual focus.
        boolean pickerAttaching = picker != null && picker.isShowing()
                && SystemClock.uptimeMillis() < pickerFocusDeadline;
        boolean windowFocused = bar.hasWindowFocus() || pickerHasFocus || pickerAttaching;
        String selected = selectedIme();
        boolean candidate = bar.hasVisibleContent() && bar.isEnabled() && interactive
                && KeypadImeModeState.isSupportedIme(selected)
                && focused != null && focused.onCheckIsTextEditor() && focused.isAttachedToWindow()
                && imm != null && imm.isActive(focused);
        View next = candidate ? focused : null;
        long before = state.generation();
        state.updateOwner(next, selected, candidate ? status() : 0, windowFocused, interactive);
        editor = next;
        if (before != state.generation()) dismissPicker();
        render();
        // Only a focused editor needs bounded polling: IMMS has no public status
        // callback for app windows. Never perform Binder calls on every draw.
        if (candidate) handler.postDelayed(refresh, 250);
    }

    private void render() {
        String label = state.label();
        if (label == null) {
            bar.clearImeMode();
            renderedLabel = null;
            renderedGeneration = -1;
        } else if (!label.equals(renderedLabel) || state.generation() != renderedGeneration) {
            bar.setImeMode(label, () -> showPicker());
            renderedLabel = label;
            renderedGeneration = state.generation();
        }
    }

    private void dismissPicker() {
        handler.removeCallbacks(pickerFocusTimeout);
        AlertDialog old = picker;
        picker = null;
        pickerFocusDeadline = 0;
        if (old != null) old.dismiss();
    }

    private void showPicker() {
        refreshOwner();
        if (picker != null || editor == null || state.label() == null) return;
        final List<String> choices = new ArrayList<>(state.availableModes());
        if (choices.isEmpty()) return;
        final View owner = editor;
        final long generation = state.generation();
        final AlertDialog dialog = new AlertDialog.Builder(context).setTitle("Input mode")
                .setItems(choices.toArray(new String[0]), (ignored, index) -> {
                    refreshOwner();
                    if (editor != owner || state.generation() != generation || !pickerFocused()) return;
                    String action = state.selectionAction(choices.get(index));
                    if (action != null) context.sendBroadcast(new Intent(action).setPackage(PACKAGE));
                }).create();
        // Preserve the existing editor as the IME target while this list owns keys.
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
        final View decor = dialog.getWindow().getDecorView();
        final ViewTreeObserver.OnWindowFocusChangeListener pickerFocusListener = focused -> {
            if (picker != dialog) return;
            if (focused) {
                pickerFocusDeadline = 0;
                handler.removeCallbacks(pickerFocusTimeout);
            }
            requestRefresh();
        };
        decor.getViewTreeObserver().addOnWindowFocusChangeListener(pickerFocusListener);
        dialog.setOnDismissListener(ignored -> {
            if (decor.getViewTreeObserver().isAlive()) {
                decor.getViewTreeObserver().removeOnWindowFocusChangeListener(pickerFocusListener);
            }
            // A delayed callback from an older dialog must not affect a new one.
            if (picker == dialog) {
                picker = null;
                pickerFocusDeadline = 0;
                handler.removeCallbacks(pickerFocusTimeout);
                handler.removeCallbacks(refresh);
                if (attached) handler.postDelayed(refresh, 100);
            }
        });
        picker = dialog;
        try {
            dialog.show();
            // Inflation/window creation can take longer than the handover grace
            // on this low-RAM device. Start the focus allowance only once show()
            // returns, before queued focus/refresh callbacks can run. Otherwise
            // the first app-window focus loss can dismiss the new picker before
            // its own focus event is dispatched (image21 trace trial06).
            pickerFocusDeadline = pickerFocused() ? 0
                    : SystemClock.uptimeMillis() + PICKER_FOCUS_TIMEOUT_MS;
            if (pickerFocusDeadline > 0) {
                handler.postAtTime(pickerFocusTimeout, pickerFocusDeadline);
            }
            dialog.getListView().setSelection(0);
            dialog.getListView().requestFocus();
        } catch (WindowManager.BadTokenException removedWindow) {
            decor.getViewTreeObserver().removeOnWindowFocusChangeListener(pickerFocusListener);
            dismissPicker();
            requestRefresh();
        }
    }
}

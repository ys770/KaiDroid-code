package android.widget;

import android.content.Context;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import java.util.ArrayList;
import java.util.List;

/**
 * Original KaiDroid soft-key view. Work in progress, not donor-compatible yet.
 * Window decoration is integrated; full resource/IME compatibility is pending.
 * @hide
 */
public class MenuBar extends FrameLayout {
    public static final int LEFT_SOFT_KEY = 0;
    public static final int CENTER_SOFT_KEY = 1;
    public static final int RIGHT_SOFT_KEY = 2;
    private final TextView[] labels = new TextView[3];
    private final KeypadSoftkeyBar row;
    private final String[] appNames = {"", "", ""};
    private final Drawable[] images = new Drawable[3];
    private final Drawable[] tips = new Drawable[3];
    private final boolean[] pressed = new boolean[3];
    private long forwardedDownTime = -1, forwardedEventTime = -1;
    private int forwardedKeyCode = -1, forwardedDeviceId = -1, forwardedRepeat = -1;
    private MenuBarListener listener;
    private final List<Pair<Integer, Integer>> options = new ArrayList<>();
    private Dialog optionDialog;
    private ListView optionList;
    private int optionBackground;
    private String imeModeLabel;
    private Runnable imeModeAction;
    private KeypadImeController imeController;
    private boolean imeModeEnabled = true;

    public interface MenuBarListener {
        boolean onClickLSK();
        boolean onClickCSK();
        boolean onClickRSK();
        void onOptionMenuClick(int id);
        void onOptionMenuDismiss();
        void onOptionMenuShow();
    }

    public MenuBar(Context context) { this(context, null); }

    public MenuBar(Context context, AttributeSet attrs) {
        super(context, attrs);
        // One renderer, retaining TCL's left/center/right public index order.
        // Background stays on this view so existing donor background setters work.
        setBackgroundColor(Color.WHITE);
        // Donor menu containers begin hidden. Unused XML placeholders must not
        // measure as a second bar inside an app's content.
        setMinimumHeight(0);
        row = new KeypadSoftkeyBar(context);
        row.setVisibility(GONE);
        row.setBackgroundColor(Color.TRANSPARENT);
        addView(row, new FrameLayout.LayoutParams(-1, -1));
        int[] renderIndexes = {KeypadSoftkeyState.LEFT, KeypadSoftkeyState.CENTER,
                KeypadSoftkeyState.RIGHT};
        for (int i = 0; i < labels.length; i++) {
            final int slot = i;
            TextView label = row.labelAt(renderIndexes[i]);
            label.setOnClickListener(v -> activate(slot));
            label.setFocusable(false);
            labels[i] = label;
        }
    }

    @Override public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        if (row != null) row.setVisibility(visibility);
        if (imeController != null) imeController.requestRefresh();
    }

    boolean hasVisibleContent() { return row != null && row.isShown(); }

    private int check(int slot) {
        if (slot < 0 || slot >= labels.length) throw new IndexOutOfBoundsException("soft-key slot " + slot);
        return slot;
    }

    public void setMenuBarListener(MenuBarListener value) { listener = value; }
    public void setSoftKeyName(int slot, String value) {
        appNames[check(slot)] = value == null ? "" : value;
        images[slot] = null;
        renderSlot(slot);
    }
    public void setSoftKeyName(int slot, int resource) {
        setSoftKeyName(slot, resource > 0 ? getResources().getString(resource) : "");
    }
    public String getSoftKeyName(int slot) { return labels[check(slot)].getText().toString(); }
    public void setSoftKeyImage(int slot, Drawable image) {
        images[check(slot)] = image;
        if (image != null) appNames[slot] = "";
        renderSlot(slot);
    }
    private void renderSlot(int slot) {
        if (slot == LEFT_SOFT_KEY && imeModeLabel != null) {
            labels[slot].setText(imeModeLabel);
            labels[slot].setCompoundDrawablesWithIntrinsicBounds(null, null, null, null);
            return;
        }
        labels[slot].setText(appNames[slot]);
        labels[slot].setCompoundDrawablesWithIntrinsicBounds(tips[slot], images[slot], null, null);
    }

    // Window/controller-owned overlay. Never write the app's labels or callbacks.
    // Reset pending key gestures even if a new owner supplies the same label.
    void setImeMode(String label, Runnable action) {
        if (label == null || label.isEmpty() || action == null)
            throw new IllegalArgumentException("IME mode requires a label and action");
        if (!imeModeEnabled) return;  // Ignore stale callbacks after an owner opts out.
        resetPresses();
        imeModeLabel = label;
        imeModeAction = action;
        renderSlot(LEFT_SOFT_KEY);
    }

    /** Reserve an owned dialog's explicit app actions; ordinary windows default on. @hide */
    public void setImeModeEnabled(boolean enabled) {
        if (imeModeEnabled == enabled) return;
        resetPresses();
        imeModeEnabled = enabled;
        if (!enabled) {
            if (imeController != null) imeController.detach();
            clearImeMode();
        } else if (isAttachedToWindow()) {
            if (imeController == null) imeController = new KeypadImeController(this);
            imeController.attach();
        }
    }

    void clearImeMode() {
        if (imeModeLabel == null) return;
        resetPresses();
        imeModeLabel = null;
        imeModeAction = null;
        renderSlot(LEFT_SOFT_KEY);
    }
    public void setSoftKeyTipsImage(int slot, Drawable image) {
        check(slot);
        // The observed donor method only renders the left-slot tip.
        if (slot == LEFT_SOFT_KEY) { tips[slot] = image; renderSlot(slot); }
    }
    public Drawable getSoftKeyImage(int slot) { return images[check(slot)]; }
    // Donor signature uses color first and position second.
    public void setSoftKeyTextColor(int color, int slot) { labels[check(slot)].setTextColor(color); }
    public void setMenuBarBackground(int resource) { setBackgroundResource(resource); }
    public void setMenuBarBackgroundColor(int color) { setBackgroundColor(color); }
    public void hideMenuBar() { resetPresses(); clearImeMode(); setVisibility(GONE); }
    public void refreshMenuBar() { requestLayout(); invalidate(); }

    public void setOptionMenu(List<Pair<Integer, Integer>> entries) {
        List<Pair<Integer, Integer>> copy = checkedOptions(entries);
        options.clear();
        options.addAll(copy);
    }
    private List<Pair<Integer, Integer>> checkedOptions(List<Pair<Integer, Integer>> entries) {
        List<Pair<Integer, Integer>> result = new ArrayList<>();
        if (entries != null) for (Pair<Integer, Integer> entry : entries) {
            if (entry == null || entry.first == null || entry.second == null)
                throw new IllegalArgumentException("Option requires action ID and string resource");
            // Resolve before replacing an existing menu so invalid resources fail early.
            getResources().getString(entry.second);
            result.add(entry);
        }
        return result;
    }
    public void setOptionMenuItemBackground(int resource) { optionBackground = resource; }
    public void updateMenuBar(int left, int center, int right, List<Pair<Integer, Integer>> entries) {
        updateMenuBar(left > 0 ? getResources().getString(left) : "",
                center > 0 ? getResources().getString(center) : "",
                right > 0 ? getResources().getString(right) : "", entries);
    }
    public void updateMenuBar(String left, String center, String right,
                              List<Pair<Integer, Integer>> entries) {
        setOptionMenu(entries);
        setSoftKeyName(LEFT_SOFT_KEY, left);
        setSoftKeyName(CENTER_SOFT_KEY, center);
        setSoftKeyName(RIGHT_SOFT_KEY, right);
    }
    public void dismissOptionMenu() {
        Dialog old = optionDialog;
        if (old == null) return;
        optionDialog = null;
        optionList = null;
        // Clear first: a callback is allowed to open another menu.
        old.setOnDismissListener(null);
        old.dismiss();
        if (listener != null) listener.onOptionMenuDismiss();
    }
    public void showOptionMenu(String title, List<Pair<Integer, Integer>> entries, int selected) {
        final List<Pair<Integer, Integer>> snapshot = checkedOptions(entries);
        if (snapshot.isEmpty()) { dismissOptionMenu(); return; }
        List<String> names = new ArrayList<>();
        for (int i = 0; i < snapshot.size(); i++)
            names.add((i + 1) + ". " + getResources().getString(snapshot.get(i).second));
        dismissOptionMenu();
        // A dismissal callback may have opened its own menu; preserve it.
        if (optionDialog != null) return;
        // The donor uses 34dp rows, 1dp dividers and a bottom-anchored window.
        // Keep the user's Kyocera renderer for the independent Select footer.
        final Dialog dialog = new Dialog(getContext(), com.android.internal.R.style.TctDialogStyle);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        // This compact bottom window already owns its footer. PhoneWindow's
        // legacy content-insets applier otherwise adds the status-bar inset to
        // its wrap-content height, leaving a blank strip below the footer.
        dialog.getWindow().setDecorFitsSystemWindows(false);
        LinearLayout content = new LinearLayout(dialog.getContext()) {
            private final Path menuClip = new Path();
            @Override protected void dispatchDraw(Canvas canvas) {
                float radius = menuDp(4);
                menuClip.reset();
                menuClip.addRoundRect(new RectF(0,0,getWidth(),getHeight()),
                        new float[]{radius,radius,radius,radius,0,0,0,0}, Path.Direction.CW);
                int save = canvas.save();
                canvas.clipPath(menuClip);
                super.dispatchDraw(canvas);
                canvas.restoreToCount(save);
            }
        };
        content.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.WHITE);
        float radius = menuDp(4);
        background.setCornerRadii(new float[]{radius,radius,radius,radius,0,0,0,0});
        content.setBackground(background);
        content.setClipToOutline(true);
        if (title != null && title.length() > 0) {
            TextView heading = new TextView(dialog.getContext());
            heading.setText(title); heading.setTextSize(18);
            heading.setTextColor(Color.BLACK); heading.setGravity(Gravity.CENTER);
            content.addView(heading, new LinearLayout.LayoutParams(-1, menuDp(36)));
        }
        final ListView list = new ListView(dialog.getContext());
        final int[] selection = {Math.max(0, Math.min(selected, snapshot.size() - 1))};
        list.setPadding(0,0,0,0);
        list.setDivider(new ColorDrawable(0xfff0f0f0));
        list.setDividerHeight(menuDp(1));
        list.setCacheColorHint(Color.TRANSPARENT);
        // Donor option_menu_item_selector uses fixed framework colors rather
        // than the caller's accent. An explicit caller drawable still wins.
        StateListDrawable defaultSelector = new StateListDrawable();
        defaultSelector.addState(new int[]{android.R.attr.state_focused}, new ColorDrawable(0xff4484cc));
        defaultSelector.addState(new int[]{}, new ColorDrawable(Color.WHITE));
        list.setSelector(optionBackground > 0
                ? getResources().getDrawable(optionBackground, getContext().getTheme())
                : defaultSelector);
        list.setDrawSelectorOnTop(false);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(dialog.getContext(),
                android.R.layout.simple_list_item_1, names) {
            @Override public View getView(int position, View convert, ViewGroup parent) {
                TextView row = convert instanceof TextView ? (TextView) convert
                        : new TextView(getContext());
                row.setText(getItem(position)); row.setTextSize(16);
                row.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
                row.setPadding(menuDp(10),0,menuDp(10),0);
                row.setSingleLine(true); row.setEllipsize(TextUtils.TruncateAt.MARQUEE);
                row.setMarqueeRepeatLimit(-1);
                boolean focused = position == selection[0] && list.hasFocus();
                row.setTextColor(focused ? Color.WHITE : Color.BLACK);
                row.setSelected(focused);
                row.setBackgroundColor(Color.TRANSPARENT);
                row.setLayoutParams(new AbsListView.LayoutParams(-1, menuDp(34)));
                return row;
            }
        };
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, index, id) -> selectOption(snapshot, index));
        Runnable updateRowFocus = () -> {
            for (int i=0; i<list.getChildCount(); i++) {
                TextView row = (TextView) list.getChildAt(i);
                boolean active = list.hasFocus() && list.getFirstVisiblePosition()+i == selection[0];
                row.setTextColor(active ? Color.WHITE : Color.BLACK); row.setSelected(active);
            }
        };
        list.setOnFocusChangeListener((view, focused) -> updateRowFocus.run());
        list.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selection[0] = position;
                updateRowFocus.run();
            }
            public void onNothingSelected(AdapterView<?> parent) { }
        });
        int count = Math.min(snapshot.size(), title == null || title.length() == 0 ? 6 : 5);
        content.addView(list, new LinearLayout.LayoutParams(-1,
                count*menuDp(34)+Math.max(0,count-1)*menuDp(1)));
        MenuBar footer = new MenuBar(dialog.getContext());
        footer.setVisibility(View.VISIBLE);
        int selectName = getResources().getIdentifier("menu_bar_select", "string", "android");
        footer.setSoftKeyName(CENTER_SOFT_KEY, selectName != 0
                ? getResources().getString(selectName) : "Select");
        footer.setMenuBarListener(new MenuBarListener() {
            public boolean onClickLSK() { return false; }
            public boolean onClickCSK() { selectOption(snapshot, selection[0]); return true; }
            public boolean onClickRSK() { return false; }
            public void onOptionMenuClick(int id) { }
            public void onOptionMenuDismiss() { }
            public void onOptionMenuShow() { }
        });
        content.addView(footer, new LinearLayout.LayoutParams(-1, menuDp(30)));
        dialog.setContentView(content);
        optionDialog = dialog;
        optionList = list;
        dialog.setOnDismissListener(d -> {
            if (optionDialog == dialog) {
                optionDialog = null;
                optionList = null;
                if (listener != null) listener.onOptionMenuDismiss();
            }
        });
        final boolean[] digitDown = new boolean[10];
        final boolean[] wrappedDirection = new boolean[2];
        dialog.setOnKeyListener((d, code, event) -> {
            if (code == KeyEvent.KEYCODE_DPAD_UP || code == KeyEvent.KEYCODE_DPAD_DOWN) {
                int direction = code == KeyEvent.KEYCODE_DPAD_UP ? 0 : 1;
                if (event.getAction() == KeyEvent.ACTION_DOWN && list.hasFocus()) {
                    int current = list.getSelectedItemPosition();
                    int target = code == KeyEvent.KEYCODE_DPAD_UP && current == 0
                            ? snapshot.size()-1 : code == KeyEvent.KEYCODE_DPAD_DOWN
                            && current == snapshot.size()-1 ? 0 : -1;
                    if (target >= 0) {
                        wrappedDirection[direction] = true;
                        selection[0] = target;
                        list.setSelection(target);
                        return true;
                    }
                } else if (event.getAction() == KeyEvent.ACTION_UP && wrappedDirection[direction]) {
                    wrappedDirection[direction] = false;
                    return true;
                }
                return false;
            }
            int digit = code >= KeyEvent.KEYCODE_0 && code <= KeyEvent.KEYCODE_9
                    ? code - KeyEvent.KEYCODE_0 : -1;
            if (digit < 0) return false;
            int index = digit == 0 ? 9 : digit - 1;
            if (index >= snapshot.size()) return false;
            if (event.getAction() == KeyEvent.ACTION_DOWN && event.getRepeatCount() == 0)
                digitDown[digit] = true;
            else if (event.getAction() == KeyEvent.ACTION_UP) {
                boolean armed = digitDown[digit];
                digitDown[digit] = false;
                if (armed && !event.isCanceled()) selectOption(snapshot, index);
            }
            return true;
        });
        try { dialog.show(); }
        catch (RuntimeException error) { optionDialog = null; optionList = null; throw error; }
        Window window = dialog.getWindow();
        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        window.getDecorView().setPadding(0,0,0,0);
        window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        WindowManager.LayoutParams params = window.getAttributes();
        params.gravity = Gravity.BOTTOM; params.width = ViewGroup.LayoutParams.MATCH_PARENT;
        params.height = ViewGroup.LayoutParams.WRAP_CONTENT; params.dimAmount = 0.5f;
        window.setAttributes(params);
        list.setSelection(selection[0]); list.requestFocus();
        if (listener != null) listener.onOptionMenuShow();
    }
    private int menuDp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
    private void selectOption(List<Pair<Integer, Integer>> entries, int index) {
        int id = entries.get(index).first;
        dismissOptionMenu();
        if (listener != null) listener.onOptionMenuClick(id);
    }

    private int slotFor(int code) {
        switch (code) {
            case KeyEvent.KEYCODE_SOFT_LEFT: return LEFT_SOFT_KEY;
            case KeyEvent.KEYCODE_DPAD_CENTER: return CENTER_SOFT_KEY;
            case KeyEvent.KEYCODE_SOFT_RIGHT: return RIGHT_SOFT_KEY;
            default: return -1;
        }
    }

    private boolean available(int slot) {
        return (listener != null || (slot == LEFT_SOFT_KEY && imeModeAction != null))
                && isShown() && isEnabled()
                && (labels[slot].length() > 0 || images[slot] != null);
    }

    private boolean activate(int slot) {
        if (!available(slot)) return false;
        if (slot == LEFT_SOFT_KEY && imeModeAction != null) {
            imeModeAction.run();
            return true;
        }
        if (slot == LEFT_SOFT_KEY) return listener.onClickLSK();
        if (slot == RIGHT_SOFT_KEY) {
            if (!options.isEmpty()) { showOptionMenu(null, options, 0); return true; }
            return listener.onClickRSK();
        }
        return listener.onClickCSK();
    }

    @Override public boolean onKeyDown(int code, KeyEvent event) {
        int slot = slotFor(code);
        if (slot < 0 || !available(slot)) return super.onKeyDown(code, event);
        if (event.getRepeatCount() == 0) {
            pressed[slot] = true;
            labels[slot].setPressed(true);
        }
        if (pressed[slot]) {
            forwardedDownTime = event.getDownTime();
            forwardedEventTime = event.getEventTime();
            forwardedKeyCode = code;
            forwardedDeviceId = event.getDeviceId();
            forwardedRepeat = event.getRepeatCount();
        }
        return true;
    }

    @Override public boolean onKeyUp(int code, KeyEvent event) {
        int slot = slotFor(code);
        if (slot < 0 || !pressed[slot]) return super.onKeyUp(code, event);
        pressed[slot] = false;
        labels[slot].setPressed(false);
        if (!event.isCanceled()) activate(slot);
        return true;
    }

    /** Preserve only a down event already forwarded here by the window callback. */
    public void onWindowCallbackHandledKey(KeyEvent event) {
        int slot = slotFor(event.getKeyCode());
        if (event.getAction() == KeyEvent.ACTION_DOWN && slot >= 0 && pressed[slot]
                && event.getKeyCode() == forwardedKeyCode
                && event.getDeviceId() == forwardedDeviceId
                && event.getRepeatCount() == forwardedRepeat
                && event.getDownTime() == forwardedDownTime
                && event.getEventTime() == forwardedEventTime) return;
        resetPresses();
    }

    private void resetPresses() {
        forwardedDownTime = forwardedEventTime = -1;
        forwardedKeyCode = forwardedDeviceId = forwardedRepeat = -1;
        for (int i = 0; i < pressed.length; i++) {
            pressed[i] = false;
            labels[i].setPressed(false);
        }
    }
    /** Cancel a gesture when a surrounding window intercepts its remainder. */
    public void clearSoftKeyState() { resetPresses(); }
    @Override protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (imeModeEnabled) {
            if (imeController == null) imeController = new KeypadImeController(this);
            imeController.attach();
        }
    }
    @Override protected void onVisibilityChanged(View changedView, int visibility) {
        super.onVisibilityChanged(changedView, visibility);
        if (imeController != null) imeController.requestRefresh();
    }
    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused) resetPresses();
        if (imeController != null) imeController.windowFocusChanged(focused);
        else if (!focused) clearImeMode();
    }
    @Override protected void onDetachedFromWindow() {
        resetPresses();
        if (imeController != null) imeController.detach();
        clearImeMode();
        dismissOptionMenu();
        super.onDetachedFromWindow();
    }
}

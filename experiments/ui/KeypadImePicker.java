package android.widget;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntConsumer;

/** Original TCL titleless keyboard menu geometry; independent Kyocera footer. @hide */
final class KeypadImePicker extends Dialog {
    private final ListView list;
    private final MenuBar footer;
    private final IntConsumer selected;
    private final boolean[] digits = new boolean[10];
    private int selection;
    private boolean dispatched;

    KeypadImePicker(Context context, List<String> choices, IntConsumer selected) {
        super(context, com.android.internal.R.style.TctDialogStyle);
        if (choices.isEmpty() || choices.size() > 8 || selected == null)
            throw new IllegalArgumentException("Keyboard choices and callback required");
        this.selected = selected;
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setDecorFitsSystemWindows(false);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM
                | WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        getWindow().getDecorView().setPadding(0, 0, 0, 0);
        LinearLayout content = new LinearLayout(getContext()) {
            private final Path clip = new Path();
            @Override protected void dispatchDraw(Canvas canvas) {
                float r = dp(4);
                clip.reset();
                clip.addRoundRect(new RectF(0, 0, getWidth(), getHeight()),
                        new float[]{r, r, r, r, 0, 0, 0, 0}, Path.Direction.CW);
                int save = canvas.save(); canvas.clipPath(clip);
                super.dispatchDraw(canvas); canvas.restoreToCount(save);
            }
        };
        content.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.WHITE);
        float r = dp(4);
        background.setCornerRadii(new float[]{r, r, r, r, 0, 0, 0, 0});
        content.setBackground(background);
        list = new ListView(getContext());
        list.setPadding(0, 0, 0, 0);
        list.setDivider(new ColorDrawable(0xfff0f0f0));
        list.setDividerHeight(dp(1));
        list.setCacheColorHint(Color.TRANSPARENT);
        StateListDrawable focus = new StateListDrawable();
        focus.addState(new int[]{android.R.attr.state_focused}, new ColorDrawable(0xff4484cc));
        focus.addState(new int[]{}, new ColorDrawable(Color.WHITE));
        list.setSelector(focus);
        list.setDrawSelectorOnTop(false);
        List<String> names = new ArrayList<>();
        for (int i = 0; i < choices.size(); i++) names.add((i + 1) + ". " + choices.get(i));
        list.setAdapter(new ArrayAdapter<String>(getContext(), android.R.layout.simple_list_item_1, names) {
            @Override public View getView(int position, View convert, ViewGroup parent) {
                TextView row = convert instanceof TextView ? (TextView) convert : new TextView(getContext());
                row.setText(getItem(position)); row.setTextSize(16);
                row.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
                row.setPadding(dp(10), 0, dp(10), 0);
                row.setSingleLine(true); row.setEllipsize(TextUtils.TruncateAt.MARQUEE);
                row.setMarqueeRepeatLimit(-1);
                boolean active = list.hasFocus() && position == selection;
                row.setTextColor(active ? Color.WHITE : Color.BLACK); row.setSelected(active);
                row.setBackgroundColor(Color.TRANSPARENT);
                row.setLayoutParams(new AbsListView.LayoutParams(-1, dp(34)));
                return row;
            }
        });
        list.setOnItemClickListener((parent, view, index, id) -> choose(index));
        list.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selection = position; updateRows();
            }
            public void onNothingSelected(AdapterView<?> parent) { }
        });
        list.setOnFocusChangeListener((view, focused) -> updateRows());
        int rows = Math.min(choices.size(), 6);
        content.addView(list, new LinearLayout.LayoutParams(-1, rows * dp(34) + (rows - 1) * dp(1)));
        footer = new MenuBar(getContext());
        footer.setImeModeEnabled(false);
        footer.setVisibility(View.VISIBLE);
        int name = getContext().getResources().getIdentifier("menu_bar_select", "string", "android");
        footer.setSoftKeyName(MenuBar.CENTER_SOFT_KEY, name == 0 ? "Select" : getContext().getString(name));
        footer.setMenuBarListener(new MenuBar.MenuBarListener() {
            public boolean onClickLSK() { return false; }
            public boolean onClickCSK() { choose(selection); return true; }
            public boolean onClickRSK() { return false; }
            public void onOptionMenuClick(int id) { }
            public void onOptionMenuDismiss() { }
            public void onOptionMenuShow() { }
        });
        content.addView(footer, new LinearLayout.LayoutParams(-1, dp(30)));
        setContentView(content);
        WindowManager.LayoutParams params = getWindow().getAttributes();
        params.width = -1; params.height = -2; params.gravity = Gravity.BOTTOM; params.dimAmount = 0.5f;
        getWindow().setAttributes(params);
    }

    private int dp(int value) { return Math.round(value * getContext().getResources().getDisplayMetrics().density); }
    private void updateRows() {
        for (int i = 0; i < list.getChildCount(); i++) {
            TextView row = (TextView) list.getChildAt(i);
            boolean active = list.hasFocus() && list.getFirstVisiblePosition() + i == selection;
            row.setTextColor(active ? Color.WHITE : Color.BLACK); row.setSelected(active);
        }
    }
    void focusFirstChoice() { list.setSelection(0); list.requestFocus(); }
    public MenuBar getMenuBar() { return footer; }
    private void choose(int index) {
        if (dispatched || !isShowing() || !getWindow().getDecorView().hasWindowFocus()
                || index < 0 || index >= list.getCount()) return;
        dispatched = true;
        selected.accept(index);
        dismiss();
    }
    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused) { Arrays.fill(digits, false); footer.clearSoftKeyState(); }
    }
    @Override public boolean onKeyDown(int code, KeyEvent event) {
        int digit = code - KeyEvent.KEYCODE_0;
        if (digit >= 1 && digit <= list.getCount()) {
            if (event.getRepeatCount() == 0) digits[digit] = true;
            return true;
        }
        return footer.onKeyDown(code, event) || super.onKeyDown(code, event);
    }
    @Override public boolean onKeyUp(int code, KeyEvent event) {
        int digit = code - KeyEvent.KEYCODE_0;
        if (digit >= 1 && digit <= list.getCount()) {
            boolean armed = digits[digit]; digits[digit] = false;
            if (armed && !event.isCanceled()) choose(digit - 1);
            return true;
        }
        return footer.onKeyUp(code, event) || super.onKeyUp(code, event);
    }
}

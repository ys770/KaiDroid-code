package android.app;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.Window;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.AbsListView;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.MenuBar;
import android.widget.ScrollView;
import android.widget.TctDialogMessage;
import android.widget.TextView;

/** Original dialog implementation, pending TCL resource/window compatibility.
 * @hide
 */
public class TctDialog extends Dialog {
    private final MenuBar bar;
    private final DialogInterface.OnClickListener[] buttons = new DialogInterface.OnClickListener[3];
    private LinearLayout root;
    private LinearLayout body;
    private TextView heading;
    private CharSequence title;
    private CharSequence message;
    private CharSequence editLabel;
    private CharSequence editValue;
    private CharSequence[] checkedItems;
    private CharSequence[] listItems;
    private boolean checked = true;
    private boolean padded;
    private CompoundButton.OnCheckedChangeListener checkedListener;
    private DialogInterface.OnClickListener listListener;
    private EditText editor;
    private CheckBox checkbox;
    private ListView list;
    private View custom;
    private DialogInterface.OnKeyListener keyListener;

    public TctDialog(Context context) { this(context, com.android.internal.R.style.TctDialogStyle); }
    public TctDialog(Context context, int theme) {
        super(context, theme);
        bar = new MenuBar(getContext());
        // This dialog owns explicit callback slots, including editor Cancel.
        bar.setImeModeEnabled(false);
        // XML placeholders begin hidden; this is the dialog's owned footer.
        bar.setVisibility(View.VISIBLE);
        bar.setMenuBarListener(new MenuBar.MenuBarListener() {
            public boolean onClickLSK() { return click(0); }
            public boolean onClickCSK() { return click(1); }
            public boolean onClickRSK() { return click(2); }
            public void onOptionMenuClick(int id) { }
            public void onOptionMenuDismiss() { }
            public void onOptionMenuShow() { }
        });
    }

    private boolean click(int slot) {
        // Donor callbacks use slot 0/1/2, not DialogInterface BUTTON_* values.
        if (buttons[slot] != null) { buttons[slot].onClick(this, slot); return true; }
        if (slot == 0 && checkbox != null && checkedListener != null) {
            checkbox.toggle(); return true;
        }
        return false;
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        root = new LinearLayout(getContext()) {
            @Override protected void onMeasure(int widthSpec, int heightSpec) {
                int limit = Math.round(getContext().getResources().getDisplayMetrics().heightPixels * 0.85f);
                int mode = View.MeasureSpec.getMode(heightSpec);
                if (mode != View.MeasureSpec.UNSPECIFIED)
                    limit = Math.min(limit, View.MeasureSpec.getSize(heightSpec));
                super.onMeasure(widthSpec, View.MeasureSpec.makeMeasureSpec(limit,
                        mode == View.MeasureSpec.EXACTLY ? mode : View.MeasureSpec.AT_MOST));
            }
        };
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackground(panelBackground(0xfff0f0f0, true));
        heading = new TextView(getContext());
        heading.setTextSize(18);
        heading.setTextColor(Color.BLACK);
        heading.setTypeface(heading.getTypeface(), Typeface.BOLD);
        heading.setGravity(Gravity.CENTER);
        heading.setMinHeight(dp(36));
        root.addView(heading);
        body = new LinearLayout(getContext());
        body.setOrientation(LinearLayout.VERTICAL);
        // Only content shrinks when the window is height-constrained; keep
        // title and soft keys outside that weighted region.
        root.addView(body, new LinearLayout.LayoutParams(-1, -2, 1));
        root.addView(bar, new LinearLayout.LayoutParams(-1, dp(30)));
        FrameLayout windowContent = new FrameLayout(getContext());
        windowContent.addView(root, new FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM));
        setContentView(windowContent);
        render();
    }

    private int dp(int value) {
        return Math.round(value * getContext().getResources().getDisplayMetrics().density);
    }

    private GradientDrawable panelBackground(int color, boolean roundedTop) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(color);
        float radius = roundedTop ? dp(4) : 0;
        background.setCornerRadii(new float[]{radius, radius, radius, radius, 0, 0, 0, 0});
        return background;
    }

    private StateListDrawable stateBackground(int state, int active, int idle, boolean roundedTop) {
        StateListDrawable background = new StateListDrawable();
        background.addState(new int[]{state}, panelBackground(active, roundedTop));
        background.addState(new int[]{}, panelBackground(idle, roundedTop));
        return background;
    }

    private GradientDrawable editBackground(boolean focused) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.WHITE);
        background.setCornerRadius(2);
        background.setStroke(1, focused ? Color.WHITE : 0xff999999);
        return background;
    }

    private void render() {
        if (root == null) return;
        if (editor != null) editValue = editor.getText().toString();
        editor = null;
        checkbox = null;
        list = null;
        body.removeAllViews();
        heading.setText(title);
        heading.setVisibility(title == null || title.length() == 0 ? View.GONE : View.VISIBLE);
        boolean titled = title != null && title.length() != 0;
        root.setPadding(0, 0, 0, 0);
        body.setBackground(panelBackground(Color.WHITE, !titled));
        body.setPadding(0, 0, 0, padded ? dp(30) : 0);
        if (custom != null) {
            body.addView(custom);
        } else if (checkedItems != null || message != null) {
            final int maxHeight = checkedItems == null ? (titled ? 154 : 200) : (titled ? 116 : 146);
            ScrollView scroll = new ScrollView(getContext()) {
                @Override protected void onMeasure(int widthSpec, int heightSpec) {
                    super.onMeasure(widthSpec, heightSpec);
                    setMeasuredDimension(getMeasuredWidth(), Math.min(getMeasuredHeight(), maxHeight));
                }
            };
            // Donor's focused/unfocused selector uses the same white fill.
            // Avoid the platform's extra gray default focus highlight.
            scroll.setDefaultFocusHighlightEnabled(false);
            int[] inset = checkedItems == null ? (titled ? new int[]{15,12,15,12} : new int[]{16,19,16,13})
                    : (titled ? new int[]{15,12,15,8} : new int[]{14,18,16,8});
            scroll.setPadding(dp(inset[0]), dp(inset[1]), dp(inset[2]), dp(inset[3]));
            LinearLayout content = new LinearLayout(getContext());
            content.setOrientation(LinearLayout.VERTICAL);
            TctDialogMessage text = new TctDialogMessage(getContext());
            text.setTextSize(titled ? 16 : 18);
            text.setTextColor(Color.BLACK);
            text.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            text.setTitle(titled || checkedItems != null);
            text.setText(checkedItems != null ? checkedItems[0] : message);
            content.addView(text);
            scroll.addView(content);
            body.addView(scroll, new LinearLayout.LayoutParams(-1, -2));
            if (checkedItems != null) {
                checkbox = new CheckBox(getContext());
                checkbox.setTextSize(18);
                ColorStateList colors = new ColorStateList(new int[][]{
                        new int[]{android.R.attr.state_focused},new int[]{}},new int[]{Color.WHITE,Color.BLACK});
                checkbox.setTextColor(colors);
                checkbox.setBackground(stateBackground(android.R.attr.state_focused,0xff008caa,Color.WHITE,false));
                checkbox.setDefaultFocusHighlightEnabled(false);
                checkbox.setGravity(Gravity.CENTER_VERTICAL);
                checkbox.setPadding(dp(10),dp(10),dp(10),dp(10));
                checkbox.setMinHeight(0);
                // Keep the native check artwork until the separate original
                // donor artwork port; match its measured18dp slot and spacing.
                Drawable icon = checkbox.getButtonDrawable();
                checkbox.setButtonDrawable((Drawable)null);
                if (icon != null) {
                    icon.setBounds(0,0,dp(18),dp(18));
                    icon.setTintList(colors);
                    checkbox.setCompoundDrawables(icon,null,null,null);
                }
                checkbox.setCompoundDrawablePadding(dp(8));
                checkbox.setText(checkedItems[1]);
                checkbox.setChecked(checked);
                checkbox.setOnCheckedChangeListener((button, value) -> {
                    checked = value;
                    if (checkedListener != null) checkedListener.onCheckedChanged(button, value);
                });
                body.addView(checkbox,new LinearLayout.LayoutParams(-1,-2));
            }
        } else if (listItems != null) {
            list = new DialogListView(getContext());
            list.setPadding(0,0,0,0);
            list.setSelector(new ColorDrawable(Color.TRANSPARENT));
            list.setDivider(new ColorDrawable(0xffd3d3d3));
            list.setDividerHeight(dp(1));
            list.setDefaultFocusHighlightEnabled(false);
            list.setAdapter(new ArrayAdapter<CharSequence>(getContext(),
                    android.R.layout.simple_list_item_1, listItems) {
                @Override public View getView(int position, View recycled, ViewGroup parent) {
                    TextView row = new TextView(getContext());
                    boolean top = position == 0 && !titled;
                    row.setLayoutParams(new AbsListView.LayoutParams(-1,dp(top ? 35 : 34)));
                    row.setTextSize(16);
                    row.setTextColor(new ColorStateList(new int[][]{
                            new int[]{android.R.attr.state_selected},new int[]{}},new int[]{Color.WHITE,Color.BLACK}));
                    row.setBackground(stateBackground(android.R.attr.state_selected,0xff008caa,Color.WHITE,top));
                    row.setPadding(dp(10),0,dp(10),0);
                    row.setGravity(Gravity.CENTER_VERTICAL);
                    row.setSingleLine(true);
                    row.setEllipsize(TextUtils.TruncateAt.MARQUEE);
                    row.setMarqueeRepeatLimit(1);
                    row.setText(getItem(position));
                    return row;
                }
            });
            list.setOnItemClickListener((parent, view, position, id) -> {
                if (listListener != null) listListener.onClick(this, position);
            });
            ((DialogListView)list).maxHeight = titled ? 170 : 205;
            body.addView(list, new LinearLayout.LayoutParams(-1,-2));
        } else if (editLabel != null) {
            TextView label = new TextView(getContext());
            label.setTextSize(16);
            label.setTextColor(Color.BLACK);
            label.setPadding(dp(14),dp(19),dp(6),dp(11));
            label.setText(editLabel);
            body.addView(label,new LinearLayout.LayoutParams(-1,-2));
            LinearLayout input = new LinearLayout(getContext());
            input.setOrientation(LinearLayout.VERTICAL);
            input.setGravity(Gravity.CENTER_VERTICAL);
            input.setPadding(dp(10),0,dp(10),0);
            input.setBackgroundColor(0xff008caa);
            body.addView(input,new LinearLayout.LayoutParams(-1,dp(38)));
            editor = new EditText(getContext());
            editor.setTextSize(14);
            editor.setTextColor(Color.BLACK);
            editor.setHintTextColor(0xff808080);
            editor.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            StateListDrawable background = new StateListDrawable();
            background.addState(new int[]{android.R.attr.state_selected},editBackground(true));
            background.addState(new int[]{android.R.attr.state_focused},editBackground(true));
            background.addState(new int[]{},editBackground(false));
            editor.setBackground(background);
            editor.setBackgroundTintList(null);
            editor.setPadding(dp(8),0,0,0);
            editor.setText(editValue);
            input.addView(editor,new LinearLayout.LayoutParams(-1,dp(28)));
        }
    }

    private static final class DialogListView extends ListView {
        int maxHeight;
        DialogListView(Context context) { super(context); }
        @Override protected void onMeasure(int widthSpec, int heightSpec) {
            super.onMeasure(widthSpec,heightSpec);
            setMeasuredDimension(getMeasuredWidth(),Math.min(getMeasuredHeight(),maxHeight));
        }
        @Override public boolean onKeyDown(int code, KeyEvent event) {
            int count = getAdapter() == null ? 0 : getAdapter().getCount();
            int selected = getSelectedItemPosition();
            if (count > 0 && code == KeyEvent.KEYCODE_DPAD_UP && selected == 0) {
                setSelection(count - 1);
                return true;
            }
            if (count > 0 && code == KeyEvent.KEYCODE_DPAD_DOWN && selected == count - 1) {
                setSelection(0);
                return true;
            }
            return super.onKeyDown(code, event);
        }
    }

    public MenuBar getMenuBar() { return bar; }
    public EditText getEditText() { return editor; }
    public CharSequence getEditContent() { return editor == null ? null : editor.getText().toString(); }
    public TctDialog setDialogTitle(int resource) { return setDialogTitle(getContext().getText(resource)); }
    public TctDialog setDialogTitle(CharSequence value) { setTitle(value); return this; }
    @Override public void setTitle(CharSequence value) {
        title = value;
        super.setTitle(value);
        if (heading != null) {
            heading.setText(value);
            // Original dialog retains its initially allocated heading space.
            // Late title text changes do not rerender message geometry.
        }
    }
    public TctDialog setMessage(int resource) { return setMessage(getContext().getText(resource)); }
    public TctDialog setMessage(CharSequence value) { message = value; render(); return this; }
    public TctDialog setEditMessage(CharSequence label, CharSequence value) {
        editLabel = label;
        editValue = value;
        if (editor != null) editor.setText(value);
        render(); return this;
    }
    public TctDialog setListItems(CharSequence[] values, DialogInterface.OnClickListener listener) {
        listItems = values == null ? null : values.clone(); listListener = listener;
        render(); return this;
    }
    public TctDialog setCheckedItems(CharSequence[] values, CompoundButton.OnCheckedChangeListener listener) {
        if (values != null && values.length < 2)
            throw new IllegalArgumentException("Checked content requires message and checkbox label");
        checkedItems = values == null ? null : values.clone(); checkedListener = listener;
        render(); return this;
    }
    public TctDialog setChecked(boolean value) {
        checked = value;
        if (checkbox != null) checkbox.setChecked(value);
        return this;
    }
    public TctDialog setView(View view) { custom = view; render(); return this; }
    public TctDialog setPadding(boolean value) { padded = value; render(); return this; }
    private TctDialog button(int slot, CharSequence label, DialogInterface.OnClickListener listener) {
        buttons[slot] = listener;
        bar.setSoftKeyName(slot, label == null ? "" : label.toString());
        return this;
    }
    public TctDialog setLeftButton(int resource, DialogInterface.OnClickListener listener) {
        return setLeftButton(resource > 0 ? getContext().getText(resource) : "", listener);
    }
    public TctDialog setLeftButton(CharSequence label, DialogInterface.OnClickListener listener) {
        return button(0, label, listener);
    }
    public TctDialog setCenterButton(int resource, DialogInterface.OnClickListener listener) {
        return setCenterButton(resource > 0 ? getContext().getText(resource) : "", listener);
    }
    public TctDialog setCenterButton(CharSequence label, DialogInterface.OnClickListener listener) {
        return button(1, label, listener);
    }
    public TctDialog setRightButton(int resource, DialogInterface.OnClickListener listener) {
        return setRightButton(resource > 0 ? getContext().getText(resource) : "", listener);
    }
    public TctDialog setRightButton(CharSequence label, DialogInterface.OnClickListener listener) {
        return button(2, label, listener);
    }
    @Override public void setOnKeyListener(DialogInterface.OnKeyListener listener) {
        // Dispatch here before the soft-key bar; do not register it a second
        // time with Dialog, which would deliver unconsumed events twice.
        keyListener = listener;
        super.setOnKeyListener(null);
        bar.clearSoftKeyState();
    }
    @Override public boolean dispatchKeyEvent(KeyEvent event) {
        int code = event.getKeyCode();
        if (keyListener != null && keyListener.onKey(this, code, event)) {
            bar.clearSoftKeyState();
            return true;
        }
        // Lists own Center. A focused donor checkbox keeps Center inert unless
        // the caller explicitly supplies a center action; left Check toggles.
        boolean checkboxCenter = code == KeyEvent.KEYCODE_DPAD_CENTER
                && checkbox != null && checkbox.hasFocus();
        boolean contentCenter = code == KeyEvent.KEYCODE_DPAD_CENTER
                && list != null && list.hasFocus();
        if (contentCenter) bar.clearSoftKeyState();
        if (!contentCenter) {
            if (event.getAction() == KeyEvent.ACTION_DOWN && bar.onKeyDown(code, event)) return true;
            if (event.getAction() == KeyEvent.ACTION_UP && bar.onKeyUp(code, event)) return true;
        }
        if (checkboxCenter) {
            bar.clearSoftKeyState();
            return true;
        }
        return super.dispatchKeyEvent(event);
    }
    @Override public void onStart() {
        super.onStart();
        getWindow().setGravity(Gravity.BOTTOM);
        getWindow().getDecorView().setPadding(0, 0, 0, 0);
        getWindow().setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
    }
    @Override public void onStop() {
        bar.clearSoftKeyState();
        bar.dismissOptionMenu();
        super.onStop();
    }
}

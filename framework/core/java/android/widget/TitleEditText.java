package android.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import com.android.internal.R;

/** Labeled keypad editor matching the observed TCL widget contract. @hide */
public class TitleEditText extends LinearLayout {
    private final TextView label;
    private final EditText editor;
    private String title;
    private OnEditTextFocusChangeListener focusListener;

    public interface OnEditTextFocusChangeListener {
        void onEditTextFocusChange(View view, boolean focused);
    }

    public TitleEditText(Context context) { this(context, null); }
    public TitleEditText(Context context, AttributeSet attrs) { this(context, attrs, 0); }
    public TitleEditText(Context context, AttributeSet attrs, int style) {
        this(context, attrs, style, 0);
    }
    public TitleEditText(Context context, AttributeSet attrs, int style, int resource) {
        super(context, attrs, style, resource);
        LinearLayout content = new LinearLayout(context);
        content.setOrientation(VERTICAL);
        content.setDuplicateParentStateEnabled(true);
        content.setPaddingRelative(dp(10), 0, dp(10), 0);
        // These two heights and the bottom margin are px in the donor layout.
        addView(content, new LayoutParams(LayoutParams.MATCH_PARENT, 58));
        label = new TextView(context);
        label.setId(R.id.title_edit_text_label);
        TypedArray appearance = context.obtainStyledAttributes(
                new int[] {android.R.attr.textAppearanceSmall});
        int appearanceId = appearance.getResourceId(0, 0);
        appearance.recycle();
        if (appearanceId != 0) label.setTextAppearance(context, appearanceId);
        label.setTextSize(16);
        label.setTextColor(Color.BLACK);
        label.setGravity(Gravity.CENTER_VERTICAL);
        label.setSingleLine(true);
        label.setEllipsize(TextUtils.TruncateAt.MARQUEE);
        label.setMarqueeRepeatLimit(-1);
        content.addView(label, new LayoutParams(LayoutParams.MATCH_PARENT, 25));
        editor = new EditText(context);
        editor.setId(R.id.title_edit_text_content);
        editor.setTextSize(14);
        editor.setTextColor(Color.BLACK);
        editor.setHintTextColor(0xff808080);
        StateListDrawable background = new StateListDrawable();
        background.addState(new int[] {android.R.attr.state_selected}, editorBorder(true));
        background.addState(new int[] {android.R.attr.state_focused}, editorBorder(true));
        background.addState(new int[0], editorBorder(false));
        editor.setBackground(background);
        editor.setPadding(dp(8), editor.getPaddingTop(), editor.getPaddingRight(),
                editor.getPaddingBottom());
        editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        LayoutParams editorParams = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
        editorParams.bottomMargin = 5;
        content.addView(editor, editorParams);

        TypedArray attributes = context.obtainStyledAttributes(attrs, R.styleable.TitleEditText);
        try {
            title = attributes.getString(R.styleable.TitleEditText_editTextTitle);
            label.setText(title);
            if (!attributes.getBoolean(R.styleable.TitleEditText_editTextNeedFocus, true)) {
                handlerEditTextWithNoNeedForFocus();
            }
            int size = attributes.getDimensionPixelSize(R.styleable.TitleEditText_titleTextSize, -1);
            // Donor passes the resolved dimension to the SP setter; preserve that behavior.
            if (size != -1) label.setTextSize(size);
            int length = attributes.getInt(R.styleable.TitleEditText_editTextMaxLength, -1);
            if (length != -1) editor.setFilters(new InputFilter[] {new InputFilter.LengthFilter(length)});
            int lines = attributes.getInt(R.styleable.TitleEditText_editTextMaxLine, -1);
            if (lines != -1) editor.setMaxLines(lines);
        } finally {
            attributes.recycle();
        }
        editor.setOnFocusChangeListener((view, focused) -> {
            setBackgroundColor(focused ? 0xff008caa : 0xfff1f2f5);
            label.setTextColor(focused ? Color.WHITE : Color.BLACK);
            label.setSelected(focused);
            if (focusListener != null) focusListener.onEditTextFocusChange(view, focused);
        });
        editor.setAccessibilityDelegate(new View.AccessibilityDelegate() {
            @Override public boolean dispatchPopulateAccessibilityEvent(View view, AccessibilityEvent event) {
                super.dispatchPopulateAccessibilityEvent(view, event);
                int type = event.getEventType();
                if (type == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED
                        || type == AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED) return true;
                int position = type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                        && !event.getText().isEmpty() ? 1 : 0;
                if (!TextUtils.isEmpty(label.getText())) event.getText().add(position, label.getText());
                return true;
            }
        });
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private static GradientDrawable editorBorder(boolean selected) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(Color.WHITE);
        drawable.setCornerRadius(2);
        drawable.setStroke(1, selected ? Color.WHITE : 0xff999999);
        return drawable;
    }
    public void handlerEditTextWithNoNeedForFocus() {
        editor.setCursorVisible(false);
        editor.setEnabled(false);
        editor.setInputType(InputType.TYPE_NULL);
    }
    public String getText() { return editor.getEditableText().toString().trim(); }
    public String getTitle() { return title; }
    public void setText(String value) {
        // The donor's getter tracks this value; the displayed label stays unchanged.
        title = value;
        editor.setText(value);
        if (value != null) editor.setSelection(value.length());
    }
    public void setHintText(String value) { editor.setHint(value); }
    public void setInputType(int value) { editor.setInputType(value); }
    public EditText getEditText() { return editor; }
    public TextView getTextView() { return label; }
    public void setOnEditTextFocusChangeListener(OnEditTextFocusChangeListener value) {
        focusListener = value;
    }
}

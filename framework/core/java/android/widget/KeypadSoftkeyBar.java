package android.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;

/**
 * Original light soft-key renderer, informed by the E4810 layout measurements.
 * Display only: the owning window/input policy is responsible for activation.
 * Receives resolved labels, never donor resource IDs or special label tokens.
 * @hide
 */
public final class KeypadSoftkeyBar extends LinearLayout {
    private final TextView[] labels = new TextView[3];
    private final Paint divider = new Paint();

    public KeypadSoftkeyBar(Context context) {
        super(context);
        setOrientation(HORIZONTAL);
        setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        setBackgroundColor(Color.WHITE);
        setMinimumHeight(25);
        setWillNotDraw(false);
        divider.setColor(0xff999999);
        // Keep physical left/right placement even for RTL label text.
        for (int index : new int[] {KeypadSoftkeyState.LEFT,
                KeypadSoftkeyState.CENTER, KeypadSoftkeyState.RIGHT}) {
            TextView text = new TextView(context);
            text.setTextColor(Color.BLACK);
            text.setMaxLines(1);
            text.setEllipsize(TextUtils.TruncateAt.END);
            text.setIncludeFontPadding(false);
            text.setGravity(Gravity.CENTER_VERTICAL | (index == KeypadSoftkeyState.LEFT
                    ? Gravity.LEFT : index == KeypadSoftkeyState.RIGHT ? Gravity.RIGHT
                    : Gravity.CENTER_HORIZONTAL));
            text.setPadding(4, 0, 4, 0);
            text.setFocusable(false);
            text.setClickable(false);
            text.setAutoSizeTextTypeUniformWithConfiguration(8, 17, 1,
                    TypedValue.COMPLEX_UNIT_PX);
            labels[index] = text;
            addView(text, new LayoutParams(0, LayoutParams.MATCH_PARENT,
                    index == KeypadSoftkeyState.CENTER ? 106 : 107));
        }
    }

    // The TCL-compatible MenuBar owns callbacks and setters; reuse these views
    // instead of maintaining a second copy of labels or an overlapping bar.
    TextView labelAt(int index) {
        if (index < 0 || index >= labels.length) throw new IndexOutOfBoundsException();
        return labels[index];
    }

    public void showState(KeypadSoftkeyState<Drawable> state) {
        if (state == null) return;
        // Validate before updating any slot to avoid a half-rendered state.
        for (int i = 0; i < labels.length; i++) {
            if (state.get(i).text.startsWith("@SK_")) {
                throw new IllegalArgumentException("Unresolved soft-key label");
            }
        }
        for (int i = 0; i < labels.length; i++) {
            KeypadSoftkeyState.Slot<Drawable> slot = state.get(i);
            labels[i].setText(slot.text);
            labels[i].setContentDescription(slot.readout);
            labels[i].setEnabled(slot.enabled);
            labels[i].setCompoundDrawablesWithIntrinsicBounds(slot.icon, null, null, null);
        }
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawLine(0, 0, getWidth(), 0, divider);
        float top = getHeight() * 0.16f;
        float bottom = getHeight() * 0.84f;
        for (int i = 0; i < 2; i++) {
            float x = getChildAt(i).getRight();
            canvas.drawLine(x, top, x, bottom, divider);
        }
    }
}

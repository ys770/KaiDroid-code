package android.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.text.Layout;
import android.view.Gravity;

/** Message measurement observed in the TCL framework and live dialog captures.
 * @hide
 */
public class TctDialogMessage extends TextView {
    private boolean hasTitle = true;
    public TctDialogMessage(Context context) { super(context); }
    public TctDialogMessage(Context context, AttributeSet attrs) { super(context, attrs); }
    public void setTitle(boolean value) { hasTitle = value; }
    @Override protected void onMeasure(int widthSpec, int heightSpec) {
        super.onMeasure(widthSpec, heightSpec);
        Layout layout = getLayout();
        if (layout != null && layout.getLineCount() < 3) {
            setGravity(Gravity.CENTER);
            if (layout.getLineCount() == 1 && !hasTitle) {
                int height = Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                        38, getResources().getDisplayMetrics()));
                setMeasuredDimension(getMeasuredWidth(), height);
            }
        }
    }
}

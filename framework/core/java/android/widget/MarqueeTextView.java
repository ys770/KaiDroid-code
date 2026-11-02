package android.widget;

import android.content.Context;
import android.util.AttributeSet;

/** TextView whose marquee lifetime can be owned by a keypad application's row.
 * @hide
 */
public class MarqueeTextView extends TextView {
    public MarqueeTextView(Context context) {
        this(context, null);
    }

    public MarqueeTextView(Context context, AttributeSet attributes) {
        this(context, attributes, 0);
    }

    public MarqueeTextView(Context context, AttributeSet attributes, int style) {
        super(context, attributes, style);
        setManualMarquee(true);
    }

    public void startMarquee() {
        forceStartStopMarquee(true);
    }

    public void stopMarquee() {
        forceStartStopMarquee(false);
    }
}

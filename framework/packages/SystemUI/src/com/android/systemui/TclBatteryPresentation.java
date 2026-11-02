package com.android.systemui;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.text.NumberFormat;

/**
 * TCL presentation with explicit inputs from the host battery controller.
 * Original artwork/layout is staged separately from the pinned donor APK.
 * This view neither fabricates battery state nor registers a second controller.
 */
public final class TclBatteryPresentation extends LinearLayout {
    private final FrameLayout container;
    private final ImageView fill;
    private final ImageView bolt;
    private final TextView percent;
    private final View spacing;
    private final int lowLevel;
    private final int containerWidth, containerHeight, regularText, soloText, lightTint, darkTint;
    private String outlineKey, fillKey, boltKey;
    private TextView statusPercent, qsPercent;
    private int level, style = -1;
    private boolean charging, plugged, fast, saver, low, foldable, thermalWarning;
    private float darkIntensity;

    public TclBatteryPresentation(Context context) {
        super(context);
        setOrientation(HORIZONTAL);
        setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
        container = (FrameLayout) LayoutInflater.from(context).inflate(
                R.layout.kaidroid_tcl_battery_container, this, false);
        fill = container.findViewById(R.id.kaidroid_tcl_battery_container_background);
        bolt = container.findViewById(R.id.kaidroid_tcl_bolt_img);
        percent = container.findViewById(R.id.kaidroid_tcl_battery_container_percent);
        spacing = container.findViewById(R.id.kaidroid_tcl_text_img_space);
        lowLevel = getResources().getInteger(R.integer.kaidroid_tcl_low_battery_level);
        containerWidth=dimension("battery_container_width");containerHeight=dimension("battery_container_height");
        regularText=dimension("battery_text");soloText=dimension("battery_text_solo");
        lightTint=context.getColor(resource("color","light_mode_icon_color_single_tone"));
        darkTint=context.getColor(resource("color","dark_mode_icon_color_single_tone"));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                containerWidth, containerHeight);
        int left = dimension("battery_container_margin_left");
        if (getResources().getConfiguration().densityDpi <= 240) left--;
        int top = dimension(getResources().getConfiguration().densityDpi >= 480
                ? "battery_container_margin_top_ext" : "battery_container_margin_top");
        params.setMargins(left, top, 0, 0);
        addView(container, params);
        updatePresentation();
    }

    private int resource(String type, String name) {
        // Direct R references also retain artwork under resource shrinking.
        switch(type+"/"+name) {
            case "drawable/ic_battery_normal_white": return R.drawable.kaidroid_tcl_ic_battery_normal_white;
            case "drawable/ic_battery_charging_percentage_white": return R.drawable.kaidroid_tcl_ic_battery_charging_percentage_white;
            case "drawable/ic_battery_fast_charging_white": return R.drawable.kaidroid_tcl_ic_battery_fast_charging_white;
            case "drawable/ic_battery_charging_white": return R.drawable.kaidroid_tcl_ic_battery_charging_white;
            case "drawable/ic_percentage_red": return R.drawable.kaidroid_tcl_ic_percentage_red;
            case "drawable/ic_percentage_foldable": return R.drawable.kaidroid_tcl_ic_percentage_foldable;
            case "drawable/ic_percentage_black_ext": return R.drawable.kaidroid_tcl_ic_percentage_black_ext;
            case "drawable/ic_percentage_black": return R.drawable.kaidroid_tcl_ic_percentage_black;
            case "drawable/ic_percentage_white_ext": return R.drawable.kaidroid_tcl_ic_percentage_white_ext;
            case "drawable/ic_percentage_white": return R.drawable.kaidroid_tcl_ic_percentage_white;
            case "drawable/ic_battery_saving_yellow": return R.drawable.kaidroid_tcl_ic_battery_saving_yellow;
            case "drawable/ic_percentage_green_black": return R.drawable.kaidroid_tcl_ic_percentage_green_black;
            case "drawable/ic_battery_fast_green_black": return R.drawable.kaidroid_tcl_ic_battery_fast_green_black;
            case "drawable/ic_percentage_green": return R.drawable.kaidroid_tcl_ic_percentage_green;
            case "drawable/ic_battery_fast_green": return R.drawable.kaidroid_tcl_ic_battery_fast_green;
            case "drawable/ic_battery_green_black": return R.drawable.kaidroid_tcl_ic_battery_green_black;
            case "drawable/ic_battery_green": return R.drawable.kaidroid_tcl_ic_battery_green;
            case "drawable/ic_percentage_fast_bolt": return R.drawable.kaidroid_tcl_ic_percentage_fast_bolt;
            case "drawable/ic_percentage_bolt": return R.drawable.kaidroid_tcl_ic_percentage_bolt;
            case "dimen/battery_container_width": return R.dimen.kaidroid_tcl_battery_container_width;
            case "dimen/battery_container_height": return R.dimen.kaidroid_tcl_battery_container_height;
            case "dimen/battery_container_margin_left": return R.dimen.kaidroid_tcl_battery_container_margin_left;
            case "dimen/battery_container_margin_top": return R.dimen.kaidroid_tcl_battery_container_margin_top;
            case "dimen/battery_container_margin_top_ext": return R.dimen.kaidroid_tcl_battery_container_margin_top_ext;
            case "dimen/battery_text": return R.dimen.kaidroid_tcl_battery_text;
            case "dimen/battery_text_solo": return R.dimen.kaidroid_tcl_battery_text_solo;
            case "dimen/tct_status_bar_battery_icon_width": return R.dimen.kaidroid_tcl_tct_status_bar_battery_icon_width;
            case "dimen/tct_status_bar_battery_icon_height": return R.dimen.kaidroid_tcl_tct_status_bar_battery_icon_height;
            case "color/light_mode_icon_color_single_tone": return R.color.kaidroid_tcl_light_mode_icon_color_single_tone;
            case "color/dark_mode_icon_color_single_tone": return R.color.kaidroid_tcl_dark_mode_icon_color_single_tone;
            default: throw new android.content.res.Resources.NotFoundException(type+"/"+name);
        }
    }
    private int dimension(String name) {
        return getResources().getDimensionPixelSize(resource("dimen", name));
    }
    private Drawable artwork(String name) {
        return getResources().getDrawable(resource("drawable", name), getContext().getTheme()).mutate();
    }
    private int tint() {
        return darkIntensity == 0f ? lightTint : darkTint;
    }
    private boolean insidePercent() { return style == 1 && !foldable; }

    /** Pass actual controller flags, including charging separately from plugged. */
    public void setBatteryState(int value, boolean isPlugged, boolean isCharging) {
        if (value < 0 || value > 100) throw new IllegalArgumentException("Battery level outside 0..100");
        level = value;
        plugged = isPlugged;
        charging = isPlugged && isCharging && value < 100;
        low = value <= lowLevel;
        updatePresentation();
        updateThermalAnimation(isCharging);
    }
    public void setFastCharging(boolean value) { fast = value; updatePresentation(); }
    public void setPowerSaveEnabled(boolean value) { saver = value; updatePresentation(); }
    public void setPercentStyle(int value) {
        style = value; updatePresentation(); requestLayout();
    }
    public void setDarkIntensity(float value) {
        darkIntensity = value; updatePresentation();
    }
    public void setFoldable(boolean value) { foldable = value; updatePresentation(); }
    public void setThermalWarning(boolean value) {
        thermalWarning = value;
        // A fresh controller sample supplies the charging flag for starting a warning.
        if (!value && getAnimation() != null) clearAnimation();
    }
    public void setStatusPercentView(TextView value) { statusPercent = value; updateExternalPercent(); }
    public void setQsPercentView(TextView value) { qsPercent = value; updateExternalPercent(); }

    private void updateExternalPercent() {
        String text = NumberFormat.getPercentInstance().format(level / 100f);
        for (TextView view : new TextView[]{statusPercent, qsPercent}) {
            if (view != null) {
                view.setText(text);
                view.setTextColor(tint());
                view.setVisibility(style == 2 ? VISIBLE : GONE);
            }
        }
    }

    private void updatePresentation() {
        boolean inside = insidePercent();
        String outline = charging ? inside ? "ic_battery_charging_percentage_white"
                : fast ? "ic_battery_fast_charging_white" : "ic_battery_charging_white"
                : "ic_battery_normal_white";
        if(!outline.equals(outlineKey)){setBackground(artwork(outline));outlineKey=outline;}
        Drawable border = getBackground();
        border.setTintList(ColorStateList.valueOf(tint()));

        String image;
        if (low) image = "ic_percentage_red";
        else if (foldable) image = "ic_percentage_foldable";
        else image = "ic_percentage_" + (darkIntensity == 1f ? "black" : "white")
                + (style == 0 || style == 2 ? "_ext" : "");
        if (saver) image = "ic_battery_saving_yellow";
        if (charging) {
            image = inside ? "ic_percentage_green" : fast ? "ic_battery_fast_green" : "ic_battery_green";
            if (darkIntensity == 1f) image += "_black";
        }
        if(!image.equals(fillKey)){fill.setImageDrawable(artwork(image));fillKey=image;}
        fill.setClipBounds(level == 100 ? null : new Rect(0, 0,
                (int) (containerWidth * (level < 15 ? .15f : level / 100f)), containerHeight));
        String boltImage=fast ? "ic_percentage_fast_bolt" : "ic_percentage_bolt";
        if(!boltImage.equals(boltKey)){bolt.setImageDrawable(artwork(boltImage));boltKey=boltImage;}
        bolt.setImageTintList(ColorStateList.valueOf(tint()));
        bolt.setVisibility(charging && inside ? VISIBLE : INVISIBLE);
        spacing.setVisibility(inside && charging ? VISIBLE : GONE);
        percent.setText(String.valueOf(level));
        percent.setTextColor(tint());
        percent.setTextSize(TypedValue.COMPLEX_UNIT_PX,
                inside && !charging ? soloText : regularText);
        percent.setVisibility(inside ? VISIBLE : GONE);
        updateExternalPercent();
        invalidate();
    }

    private void updateThermalAnimation(boolean actualCharging) {
        if (plugged && thermalWarning && !actualCharging && level < 100) {
            startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.kaidroid_tcl_battery_flash));
        } else if (getAnimation() != null) clearAnimation();
    }

    @Override protected void onDetachedFromWindow() {
        clearAnimation();
        super.onDetachedFromWindow();
    }
}

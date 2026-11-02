package com.android.systemui;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.widget.TextView;

/** Original TCL presentation, subscribed through the existing target BatteryController. */
public final class TclBatteryMeterView extends BatteryMeterView {
    private TclBatteryInfo info=TclBatteryInfo.UNKNOWN;
    private boolean plugged;
    private final int slowThreshold, fastThreshold;
    public TclBatteryMeterView(Context context,AttributeSet attrs){this(context,attrs,0);}
    public TclBatteryMeterView(Context context,AttributeSet attrs,int style){
        super(context,attrs,style);
        slowThreshold=getResources().getInteger(R.integer.kaidroid_tcl_config_chargingSlowlyThreshold);
        fastThreshold=getResources().getInteger(R.integer.kaidroid_tcl_config_chargingFastThreshold);
        installTclBatteryPresentation();
        // The donor widget ignores icon-blacklist tuner updates, independently
        // of normal status-bar disable flags, which remain handled by the host.
        setIgnoreTunerUpdates(true);
    }
    @Override public void onTclBatteryInfoChanged(TclBatteryInfo value){
        info=value;
        getTclBatteryPresentation().setFastCharging(info.chargingSpeed(slowThreshold,fastThreshold)==2);
        getTclBatteryPresentation().setThermalWarning(info.temperatureWarning(plugged));
    }
    @Override public void onBatteryLevelChanged(int level,boolean isPlugged,boolean charging){
        plugged=isPlugged;
        getTclBatteryPresentation().setThermalWarning(info.temperatureWarning(plugged));
        super.onBatteryLevelChanged(level,isPlugged,charging);
    }
    @Override public void onDarkChanged(Rect area,float intensity,int tint){
        super.onDarkChanged(area,intensity,tint);
        // The superclass constructor invokes this before installing the view.
        if(getTclBatteryPresentation()!=null)getTclBatteryPresentation().setDarkIntensity(intensity);
    }
    public void setPercentView(TextView view){getTclBatteryPresentation().setStatusPercentView(view);}
    public void setQsPercentView(TextView view){getTclBatteryPresentation().setQsPercentView(view);}
}

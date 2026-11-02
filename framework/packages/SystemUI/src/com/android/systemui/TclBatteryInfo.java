package com.android.systemui;

import android.content.Intent;

/** Actual sticky-broadcast metadata not carried by BatteryController's level callback. */
public final class TclBatteryInfo {
    public static final int TEMPERATURE_UNKNOWN = Integer.MIN_VALUE;
    public static final TclBatteryInfo UNKNOWN = new TclBatteryInfo(TEMPERATURE_UNKNOWN, -1, -1);
    public final int temperatureDeciC, maximumCurrentMicroAmp, maximumVoltageMicroVolt;

    public TclBatteryInfo(int temperature, int current, int voltage) {
        temperatureDeciC=temperature;maximumCurrentMicroAmp=current;maximumVoltageMicroVolt=voltage;
    }
    public static TclBatteryInfo fromIntent(Intent intent) {
        return new TclBatteryInfo(intent.getIntExtra("temperature",TEMPERATURE_UNKNOWN),
                intent.getIntExtra("max_charging_current",-1),intent.getIntExtra("max_charging_voltage",-1));
    }
    public int chargingSpeed(int slowThreshold, int fastThreshold) {
        if(maximumCurrentMicroAmp<=0)return -1;
        int voltage=maximumVoltageMicroVolt>0?maximumVoltageMicroVolt:5000000;
        int wattage=(maximumCurrentMicroAmp/1000)*(voltage/1000);
        if(wattage<=0)return -1;
        return wattage<slowThreshold?0:wattage>fastThreshold?2:1;
    }
    /** Donor USCC icon-warning conditions only; never a shutdown or charging policy. */
    public boolean temperatureWarning(boolean plugged) {
        if(temperatureDeciC==TEMPERATURE_UNKNOWN)return false;
        return temperatureDeciC>=580 || temperatureDeciC<=-180
                || (plugged && (temperatureDeciC>=530 || temperatureDeciC<=0));
    }
}

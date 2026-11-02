"""Prepare a narrow offline SystemUI overlay; never change shared source or phones."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

INPUTS = {
    'AospBatteryMeterView.java': ('src/com/android/systemui/BatteryMeterView.java', 'c49da7f1e428f6897bab572af933be58fedfb502670b7c7679ab12aca838fd08'),
    'AospBatteryController.java': ('src/com/android/systemui/statusbar/policy/BatteryController.java', '2193220d329e484be6326e7de21806f245b452e5b5debec34c739c204171f06c'),
    'AospBatteryControllerImpl.java': ('src/com/android/systemui/statusbar/policy/BatteryControllerImpl.java', '8cdb0af0f674f5e1e0ba8106265ff850bd3f534929968e89a76eaf261eff72a8'),
    'AospSystemIcons.xml': ('res/layout/system_icons.xml', '9e305b936f24f2d4b1b217a7da203b028a182ecb5611159d460d16e12475a795'),
}


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Unexpected source anchor: ' + before[:100])
    return text.replace(before, after)


def prepare(inputs, resources, output):
    if output.exists():
        raise FileExistsError(output)
    resource_files=[p for p in resources.rglob('*') if p.is_file()]
    if not resource_files or any(p.is_symlink() or not p.name.startswith('kaidroid_tcl_') for p in resource_files):
        raise ValueError('Require only staged namespaced battery assets')
    before = {}
    for name, (target, expected) in INPUTS.items():
        raw = (inputs/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed target source: ' + name)
        before[target] = raw.decode().replace('\r\n','\n')
    after = dict(before)
    target = INPUTS['AospBatteryMeterView.java'][0]
    text = before[target]
    text = replace(text, '    private final ThemedBatteryDrawable mDrawable;', '''    private TclBatteryPresentation mTclBatteryPresentation;

    protected final TclBatteryPresentation getTclBatteryPresentation() { return mTclBatteryPresentation; }

    protected final void installTclBatteryPresentation() {
        if (mTclBatteryPresentation != null) throw new IllegalStateException("Battery presentation already installed");
        mTclBatteryPresentation = new TclBatteryPresentation(getContext());
        removeAllViews();
        mBatteryPercentView = null;
        addView(mTclBatteryPresentation, new LinearLayout.LayoutParams(
                getResources().getDimensionPixelSize(R.dimen.kaidroid_tcl_tct_status_bar_battery_icon_width),
                getResources().getDimensionPixelSize(R.dimen.kaidroid_tcl_tct_status_bar_battery_icon_height)));
        updateShowPercent();
    }

    private final ThemedBatteryDrawable mDrawable;''')
    text = replace(text, '    private void updateShowPercent() {', '''    private void updateShowPercent() {
        if (mTclBatteryPresentation != null) {
            mTclBatteryPresentation.setPercentStyle(Settings.Global.getInt(
                    getContext().getContentResolver(), "status_bar_battery_percent_styles", -1));
            return;
        }''')
    text = replace(text, '    private void scaleBatteryMeterViews() {', '''    private void scaleBatteryMeterViews() {
        if (mTclBatteryPresentation != null) return;''')
    text = replace(text, '    public void onBatteryLevelChanged(int level, boolean pluggedIn, boolean charging) {', '''    public void onBatteryLevelChanged(int level, boolean pluggedIn, boolean charging) {
        if (mTclBatteryPresentation != null) mTclBatteryPresentation.setBatteryState(level, pluggedIn, charging);''')
    text = replace(text, '    public void onPowerSaveChanged(boolean isPowerSave) {', '''    public void onPowerSaveChanged(boolean isPowerSave) {
        if (mTclBatteryPresentation != null) mTclBatteryPresentation.setPowerSaveEnabled(isPowerSave);''')
    anchor = '                updateShowPercent();\n            }\n        };'
    text = replace(text, anchor, '''                if (mTclBatteryPresentation != null) getContext().getContentResolver().registerContentObserver(
                        Settings.Global.getUriFor("status_bar_battery_percent_styles"), false, mSettingObserver, newUserId);
''' + anchor)
    anchor = '        updateShowPercent();\n        subscribeForTunerUpdates();'
    text = replace(text, anchor, '''        if (mTclBatteryPresentation != null) getContext().getContentResolver().registerContentObserver(
                Settings.Global.getUriFor("status_bar_battery_percent_styles"), false, mSettingObserver);
''' + anchor)
    after[target] = text

    target = INPUTS['AospBatteryController.java'][0]
    text = replace(before[target], 'package com.android.systemui.statusbar.policy;',
                   'package com.android.systemui.statusbar.policy;\n\nimport com.android.systemui.TclBatteryInfo;')
    text = replace(text, '    interface BatteryStateChangeCallback {', '''    interface BatteryStateChangeCallback {
        /** Optional presentation metadata from the same actual battery broadcast. */
        default void onTclBatteryInfoChanged(TclBatteryInfo info) { }
''')
    after[target] = text

    target = INPUTS['AospBatteryControllerImpl.java'][0]
    text = replace(before[target], 'package com.android.systemui.statusbar.policy;',
                   'package com.android.systemui.statusbar.policy;\n\nimport com.android.systemui.TclBatteryInfo;')
    text = replace(text, '    protected int mLevel;', '    private TclBatteryInfo mTclBatteryInfo = TclBatteryInfo.UNKNOWN;\n    protected int mLevel;')
    text = replace(text, '            mHasReceivedBattery = true;',
                   '            mTclBatteryInfo = TclBatteryInfo.fromIntent(intent);\n            mHasReceivedBattery = true;')
    text = replace(text, '        cb.onBatteryLevelChanged(mLevel, mPluggedIn, mCharging);',
                   '        cb.onTclBatteryInfoChanged(mTclBatteryInfo);\n        cb.onBatteryLevelChanged(mLevel, mPluggedIn, mCharging);')
    text = replace(text, '                mChangeCallbacks.get(i).onBatteryLevelChanged(mLevel, mPluggedIn, mCharging);',
                   '                mChangeCallbacks.get(i).onTclBatteryInfoChanged(mTclBatteryInfo);\n                mChangeCallbacks.get(i).onBatteryLevelChanged(mLevel, mPluggedIn, mCharging);')
    after[target] = text

    target = INPUTS['AospSystemIcons.xml'][0]
    text = replace(before[target], '<com.android.systemui.BatteryMeterView android:id="@+id/battery"',
                   '<com.android.systemui.TclBatteryMeterView android:id="@+id/battery"')
    text = replace(text, '        android:layout_height="match_parent"\n        android:layout_width="wrap_content"',
                   '        android:layout_height="@dimen/kaidroid_tcl_tct_status_bar_battery_icon_height"\n        android:layout_width="@dimen/kaidroid_tcl_tct_status_bar_battery_icon_width"')
    after[target] = text

    root = Path(__file__).resolve().parents[1]
    output.mkdir(parents=True)
    overlay = output/'overlay'
    for name, text in after.items():
        p = overlay/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,newline='\n')
    new_sources = root/'framework/packages/SystemUI/src/com/android/systemui'
    for name in ('TclBatteryPresentation.java','TclBatteryInfo.java','TclBatteryMeterView.java'):
        p=new_sources/name
        shutil.copyfile(p, overlay/'src/com/android/systemui'/p.name)
    shutil.copytree(resources, overlay/'res', dirs_exist_ok=True)
    patch = ''.join(''.join(difflib.unified_diff(before[name].splitlines(True), text.splitlines(True),
                    fromfile='a/'+name, tofile='b/'+name)) for name,text in after.items())
    (output/'binding.patch').write_text(patch,newline='\n')
    report = dict(inputs={k:v[1] for k,v in INPUTS.items()},
        overlay={p.relative_to(overlay).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(overlay.rglob('*')) if p.is_file()},
        existing_controller_reused=True,extra_battery_receivers=0,extra_system_service_dependencies=0,
        vendor_or_shutdown_policy_changes=False,platform_compiled=False,installed=False)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inputs','resources','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();r=prepare(a.inputs,a.resources,a.output)
    print(json.dumps(dict(files=len(r['overlay']),platform_compiled=False,installed=False)))

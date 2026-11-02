"""Prepare opt-in POWER routing through AOSP's end-call/Home policy.

Candidate only: build, screenshot-chord parity, and physical validation pending.
"""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = 'c0447dbc88cb823fc41e50d69419c0094646fa4eecc1a03db438cf7309b5b8ef'


HANDLER = '''                if (kaiDroidPowerEndCall) {
                    result &= ~ACTION_PASS_TO_USER;
                    if (!interactive && !isScreenOn()) {
                        isWakeKey = true;
                    }
                    if (down) {
                        AudioManager audio = mContext.getSystemService(AudioManager.class);
                        if (audio != null) audio.playSoundEffect(AudioManager.FX_KEY_CLICK);
                        TelecomManager telecom = getTelecommService();
                        boolean hungUp = telecom != null
                                && !mScreenshotChordVolumeDownKeyTriggered && telecom.endCall();
                        if (interactive && !hungUp) {
                            mEndCallKeyHandled = false;
                            mHandler.postDelayed(mEndCallLongPress, 2500);
                        } else {
                            mEndCallKeyHandled = true;
                        }
                        mPowerKeyHandled = hungUp || mScreenshotChordVolumeDownKeyTriggered
                                || mA11yShortcutChordVolumeUpKeyTriggered;
                        if (interactive && !mScreenshotChordPowerKeyTriggered
                                && (event.getFlags() & KeyEvent.FLAG_FALLBACK) == 0) {
                            mScreenshotChordPowerKeyTriggered = true;
                            mScreenshotChordPowerKeyTime = event.getDownTime();
                            interceptScreenshotChord();
                        }
                    } else {
                        mScreenshotChordPowerKeyTriggered = false;
                        if (!mEndCallKeyHandled && !mPowerKeyHandled) {
                            mHandler.removeCallbacks(mEndCallLongPress);
                            if (!canceled) {
                                if ((mEndcallBehavior & Settings.System.END_BUTTON_BEHAVIOR_HOME)
                                        != 0 && goHome()) {
                                    break;
                                }
                                if ((mEndcallBehavior & Settings.System.END_BUTTON_BEHAVIOR_SLEEP)
                                        != 0) {
                                    goToSleep(event.getEventTime(),
                                            PowerManager.GO_TO_SLEEP_REASON_POWER_BUTTON, 0);
                                    isWakeKey = false;
                                }
                            }
                        }
                    }
                    break;
                }
'''

def prepare(source, output):
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('Unexpected PhoneWindowManager source')
    text = raw.decode()
    start = text.index('    public int interceptKeyBeforeQueueing(KeyEvent event, int policyFlags) {')
    anchor = '        final int keyCode = event.getKeyCode();'
    pos = text.index(anchor, start)
    text = text[:pos] + text[pos:].replace(anchor, anchor + "\n        final boolean kaiDroidPowerEndCall =\n                SystemProperties.getBoolean(\"ro.kaidroid.power_endcall\", false);", 1)
    # Preserve original identity for wake/global-key/haptic preprocessing.
    switch = '        // Handle special keys.\n        switch (keyCode) {'
    if text.count(switch) != 1:
        raise ValueError('Ambiguous special-key switch')
    text = text.replace(switch, '        // Route only policy dispatch; retain the original event/key identity.\n'
                        '        switch (kaiDroidPowerEndCall && keyCode == KeyEvent.KEYCODE_POWER\n'
                        '                ? KeyEvent.KEYCODE_ENDCALL : keyCode) {')
    branch = '            case KeyEvent.KEYCODE_ENDCALL: {\n'
    if text.count(branch) != 1:
        raise ValueError('Ambiguous ENDCALL branch')
    text = text.replace(branch, branch + HANDLER)
    output.mkdir(exist_ok=False, parents=True)
    candidate = text.encode()
    (output / 'PhoneWindowManager.java').write_bytes(candidate)
    report = dict(source_sha256=SOURCE_SHA,
                  candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                  enable_property='ro.kaidroid.power_endcall=true',
                  required_user_setting='system end_button_behavior=1',
                  compiled=False, installed=False,
                  donor_powerkey_volume_up=False,
                  unresolved=[
                              'physical call/ringing/longpress/cancel/wake validation'])
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.source, a.output)))

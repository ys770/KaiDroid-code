"""Prepare an Android11 center-key route through the existing keyguard action."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = '0140e987d6cdc9b2ed68b1ab6da8aa29858444947f7b15c2cb00192b81df911a'
ANCHOR = '''                switch (event.getKeyCode()) {
                    case KeyEvent.KEYCODE_BACK:'''
REPLACEMENT = '''                switch (event.getKeyCode()) {
                    case KeyEvent.KEYCODE_DPAD_CENTER:
                        // Use the existing swipe/Space keyguard route. Once the
                        // credential UI is showing, leave center to that view.
                        if (mKeyguardStateController.isShowing()
                                && !mService.isBouncerShowing()) {
                            if (!down && !event.isCanceled()) {
                                return mService.onSpacePressed();
                            }
                            return true;
                        }
                        break;
                    case KeyEvent.KEYCODE_BACK:'''


def prepare(source, output):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Unexpected SystemUI source')
    text = data.decode('utf-8')
    if text.count(ANCHOR) != 1:
        raise ValueError('Unexpected dispatch anchor')
    result = text.replace(ANCHOR, REPLACEMENT).encode('utf-8')
    output.mkdir(parents=True, exist_ok=False)
    (output / source.name).write_bytes(result)
    report = dict(source_sha256=SOURCE_SHA,
                  candidate_sha256=hashlib.sha256(result).hexdigest(),
                  behavior='Center key-up uses existing onSpacePressed only while keyguard showing and credential bouncer absent',
                  compiled=False, installed=False, credential_behavior_tested=False)
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.source, a.output), indent=2))

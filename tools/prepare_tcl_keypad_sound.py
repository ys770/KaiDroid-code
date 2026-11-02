"""Prepare TextView keypad click control and ViewRootImpl one-click suppression.

Offline candidate only. DecorView/Kyocera softkey audio integration, platform
compilation and physical sound comparisons remain separate requirements.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HASHES = {
    'TextView.java': 'c7fb014c23232506ba18abb0fec299ca5b88740fce3df868079fb250adc178cb',
    'ViewRootImpl.java': '4f4ed7eeb959c7f1dcd29240a3c9bd94582c24ec42b61240d14733c2610ea5d1',
}


def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Nonunique source anchor: ' + old)
    return source.replace(old, new, 1)


def prepare(name, data):
    if hashlib.sha256(data).hexdigest() != HASHES[name]:
        raise ValueError('Unexpected source: ' + name)
    source = data.decode()
    if name == 'TextView.java':
        source = replace(source, '    private boolean mKaidroidManualMarquee;',
                         '    private boolean mKaidroidPlaySoundEffectEnable = true;\n'
                         '    private android.media.AudioManager mKaidroidAudioManager;\n'
                         '    private boolean mKaidroidManualMarquee;')
        source = replace(source, '    @Override\n    public boolean onKeyPreIme(int keyCode, KeyEvent event) {', '''    /** @hide */
    public void setPlaySoundEffectEnable(boolean enabled) {
        mKaidroidPlaySoundEffectEnable = enabled;
    }

    @Override
    public boolean onKeyPreIme(int keyCode, KeyEvent event) {
        boolean textNavigation = (mMovement != null || onCheckIsTextEditor())
                && hasSpannableText() && mLayout != null
                && (isTextEditable() || isTextSelectable()) && isFocused();
        boolean keypad = keyCode >= KeyEvent.KEYCODE_0 && keyCode <= KeyEvent.KEYCODE_DPAD_CENTER;
        boolean soundEnabled = mKaidroidPlaySoundEffectEnable
                || (keyCode >= KeyEvent.KEYCODE_DPAD_UP && keyCode <= KeyEvent.KEYCODE_DPAD_CENTER);
        if (textNavigation && event.getAction() == KeyEvent.ACTION_DOWN && keypad
                && soundEnabled && keyCode != KeyEvent.KEYCODE_DPAD_CENTER) {
            if (mKaidroidAudioManager == null) {
                mKaidroidAudioManager = (android.media.AudioManager)
                        getContext().getSystemService(Context.AUDIO_SERVICE);
            }
            mKaidroidAudioManager.playSoundEffect(android.media.AudioManager.FX_KEY_CLICK);
            if (getViewRootImpl() != null) {
                getViewRootImpl().setPlayClickSound(false);
            }
        }''')
    else:
        source = replace(source, '    AudioManager mAudioManager;',
                         '    AudioManager mAudioManager;\n'
                         '    private boolean mKaidroidPlayClickSound = true;')
        source = replace(source, '    private AudioManager getAudioManager() {', '''    /** @hide */
    public void setPlayClickSound(boolean enabled) {
        mKaidroidPlayClickSound = enabled;
    }

    private AudioManager getAudioManager() {''')
        source = replace(source, '''                case SoundEffectConstants.CLICK:
                    audioManager.playSoundEffect(AudioManager.FX_KEY_CLICK);
                    return;''', '''                case SoundEffectConstants.CLICK:
                    if (mKaidroidPlayClickSound) {
                        audioManager.playSoundEffect(AudioManager.FX_KEY_CLICK);
                    }
                    mKaidroidPlayClickSound = true;
                    return;''')
    return source.encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    inputs = {name: (a.source / name).read_bytes() for name in HASHES}
    candidates = {name: prepare(name, data) for name, data in inputs.items()}
    a.output.mkdir(parents=True)
    rows, patches = [], []
    for name, data in candidates.items():
        (a.output / name).write_bytes(data)
        rows.append(dict(file=name, source_sha256=HASHES[name],
                         candidate_sha256=hashlib.sha256(data).hexdigest()))
        path = 'core/java/android/' + ('widget/' if name == 'TextView.java' else 'view/') + name
        patches.extend(difflib.unified_diff(inputs[name].decode().splitlines(True),
                       data.decode().splitlines(True), fromfile='a/' + path, tofile='b/' + path))
    (a.output / 'keypad-sound.patch').write_text(''.join(patches), newline='\n')
    report = dict(files=rows, platform_compiled=False, installed=False, physical_parity=False,
                  softkey_audio_integration_complete=False,
                  hiddenapi_addition='Landroid/widget/TextView;->setPlaySoundEffectEnable(Z)V')
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

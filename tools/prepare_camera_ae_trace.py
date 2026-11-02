"""Add bounded AE metadata diagnostics to a pinned Camera2 source, preserving behavior."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = '47118655731f4a42266ccd3ba2efe093da7b9bbbdfc56d2950a4f66f19af77e2'
RELATIVE = 'packages/apps/Camera2/src/com/android/camera/one/v2/autofocus/AETriggerResult.java'


def adapt(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unreviewed AETriggerResult source')
    text = original.decode()
    replacements = {
        '    private final SettableFuture<Boolean> mFutureResult;':
        '    private final SettableFuture<Boolean> mFutureResult;\n'
        '    private int mKaiDroidTraceCount; // Bounded diagnostic build only.\n',
        '        mFutureResult = SettableFuture.create();':
        '        mFutureResult = SettableFuture.create();\n'
        '        android.util.Log.i("KaiDroidAE", "created id=" + System.identityHashCode(this));',
        '        if (done) {':
        '''        if (mKaiDroidTraceCount < 32) {
            mKaiDroidTraceCount++;
            android.util.Log.i("KaiDroidAE", "id=" + System.identityHashCode(this)
                    + " sample=" + mKaiDroidTraceCount
                    + " frame=" + result.getFrameNumber()
                    + " trigger=" + result.getRequest().get(CaptureRequest.CONTROL_AE_PRECAPTURE_TRIGGER)
                    + " state=" + state + " done=" + done
                    + " kind=" + result.getClass().getSimpleName()
                    + " thread=" + Thread.currentThread().getName());
        }
        if (done) {''',
        '            return mFutureResult.get();':
        '            android.util.Log.i("KaiDroidAE", "wait id=" + System.identityHashCode(this));\n'
        '            return mFutureResult.get();',
    }
    for before, after in replacements.items():
        if text.count(before) != 1:
            raise ValueError('Unexpected diagnostic anchor: ' + before)
        text = text.replace(before, after)
    return text.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    path = args.source_root / RELATIVE
    original = path.read_bytes()
    patched = adapt(original)
    with args.backup.open('xb') as stream:
        stream.write(original)
    path.write_bytes(patched)
    print('Patched SHA256:', hashlib.sha256(patched).hexdigest())


if __name__ == '__main__':
    main()

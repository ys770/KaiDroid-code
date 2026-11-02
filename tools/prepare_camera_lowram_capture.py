"""Select non-ZSL JPEG capture on low-RAM devices in the pinned AOSP Camera2 source."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = 'b90f9506551261785d5d668680d63c47a4cb9186e26bf4a67775b3c46e13a1b5'
RELATIVE = Path('packages/apps/Camera2/src/com/android/camera/one/config/OneCameraFeatureConfigCreator.java')


def adapt(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unrecognized Camera2 source; inspect before adapting')
    text = original.decode('utf-8')
    text = text.replace('import com.android.camera.util.ApiHelper;',
                        'import com.android.camera.util.AndroidServices;\nimport com.android.camera.util.ApiHelper;')
    anchor = '                // No matter if L or L MR1, the N5 does not currently support'
    assert text.count(anchor) == 1
    text = text.replace(anchor, '''                // Full sensor support does not imply enough RAM for a ZSL ring.
                // Keep full-resolution JPEG capture without retained reprocessing images.
                if (AndroidServices.instance().provideActivityManager().isLowRamDevice()) {
                    Log.i(TAG, "KaiDroid low-RAM capture: LIMITED_JPEG");
                    return CaptureSupportLevel.LIMITED_JPEG;
                }

''' + anchor)
    return text.encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root / RELATIVE
    original = source.read_bytes()
    patched = adapt(original)
    # Exclusive backup creation: never overwrite an earlier experiment.
    with args.backup.open('xb') as stream:
        stream.write(original)
    source.write_bytes(patched)
    print('Patched SHA256:', hashlib.sha256(patched).hexdigest())


if __name__ == '__main__':
    main()

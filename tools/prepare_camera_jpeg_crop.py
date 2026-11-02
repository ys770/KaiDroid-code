"""Correct the JPEG crop comparison to use the same dimensions as safeCrop."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = '9d8bda122049dca4eef2c85e779de9da54a4c1d3d6d375397e8e41fa5d598813'
RELATIVE = 'packages/apps/Camera2/src/com/android/camera/processing/imagebackend/TaskCompressImageToJpeg.java'


def adapt(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Expected reviewed save-trace source')
    text = original.decode()
    before = '''                    android.util.Log.i("KaiDroidSave", "EXIF parsed crop=" + safeCrop
                            + " required=" + requiresCropOperation(img.proxy, safeCrop));
                    if(requiresCropOperation(img.proxy, safeCrop)) {'''
    after = '''                    // Match the coordinate space used by guaranteedSafeCrop above.
                    // A HAL-rotated JPEG can differ from ImageProxy dimensions.
                    final Rect fullJpegBounds = (exifPixelXDimension == null
                            || exifPixelYDimension == null)
                            ? new Rect(0, 0, img.proxy.getWidth(), img.proxy.getHeight())
                            : new Rect(0, 0, imageWidth, imageHeight);
                    final boolean needsJpegCrop = !safeCrop.equals(fullJpegBounds);
                    android.util.Log.i("KaiDroidSave", "EXIF parsed crop=" + safeCrop
                            + " fullBounds=" + fullJpegBounds + " required=" + needsJpegCrop);
                    if (needsJpegCrop) {'''
    if text.count(before) != 1:
        raise ValueError('Unexpected JPEG crop comparison')
    return text.replace(before, after).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    path = args.source_root / RELATIVE
    patched = adapt(path.read_bytes())
    with args.backup.open('xb') as stream:
        stream.write(path.read_bytes())
    path.write_bytes(patched)
    print('Patched SHA256:', hashlib.sha256(patched).hexdigest())


if __name__ == '__main__':
    main()

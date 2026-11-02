"""Instrument the pinned Camera2 JPEG save path without changing capture behavior."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = '9c0772a1c9d036a47257df68ab984d4b3cc0c443c784f02ef81f2f3064f7abb0'
RELATIVE = 'packages/apps/Camera2/src/com/android/camera/processing/imagebackend/TaskCompressImageToJpeg.java'


def adapt(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unreviewed TaskCompressImageToJpeg source')
    text = original.decode()
    replacements = {
        '        ImageToProcess img = mImage;':
        '        ImageToProcess img = mImage;\n'
        '        android.util.Log.i("KaiDroidSave", "task start format=" + img.proxy.getFormat()\n'
        '                + " size=" + img.proxy.getWidth() + "x" + img.proxy.getHeight());',
        '                    compressedData = ByteBuffer.allocate(origBuffer.limit());':
        '                    android.util.Log.i("KaiDroidSave", "copy JPEG bytes=" + origBuffer.limit());\n'
        '                    compressedData = ByteBuffer.allocate(origBuffer.limit());',
        '                    if(requiresCropOperation(img.proxy, safeCrop)) {':
        '                    android.util.Log.i("KaiDroidSave", "EXIF parsed crop=" + safeCrop\n'
        '                            + " required=" + requiresCropOperation(img.proxy, safeCrop));\n'
        '                    if(requiresCropOperation(img.proxy, safeCrop)) {',
        '        writeOut = new byte[numBytes];':
        '        android.util.Log.i("KaiDroidSave", "output copy bytes=" + numBytes);\n'
        '        writeOut = new byte[numBytes];',
        '        onJpegEncodeDone(mId, inputImage, resultImage, writeOut,':
        '        android.util.Log.i("KaiDroidSave", "encode callback begin");\n'
        '        onJpegEncodeDone(mId, inputImage, resultImage, writeOut,',
        '        final ExifInterface exif = createExif(Optional.fromNullable(exifData), resultImage,':
        '        android.util.Log.i("KaiDroidSave", "create EXIF metadataDone=" + img.metadata.isDone());\n'
        '        final ExifInterface exif = createExif(Optional.fromNullable(exifData), resultImage,',
        '        ListenableFuture<Optional<Uri>> futureUri = mSession.saveAndFinish(writeOut,':
        '        android.util.Log.i("KaiDroidSave", "saveAndFinish begin");\n'
        '        ListenableFuture<Optional<Uri>> futureUri = mSession.saveAndFinish(writeOut,',
        '            public void onSuccess(Optional<Uri> uriOptional) {':
        '            public void onSuccess(Optional<Uri> uriOptional) {\n'
        '                android.util.Log.i("KaiDroidSave", "save resolved present=" + uriOptional.isPresent());',
        '            public void onFailure(Throwable throwable) {':
        '            public void onFailure(Throwable throwable) {\n'
        '                android.util.Log.e("KaiDroidSave", "save failed", throwable);',
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

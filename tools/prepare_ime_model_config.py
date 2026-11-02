"""Create a private, hash-pinned IME configuration trial for the engineering Nokia.

Only appends its model to the donor model list. No APK, system property, date,
feature or native engine changes. Does not install or mount anything.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

APK_SHA = 'f80ddc5b461d1d23cc05f9c212f43629991766f9630466b89fbdec8b34ea8e7f'
CONFIG_SHA = '88456edcda69e34647ef3db35d640dd57337db59db87231ba736568427bfbb0c'
MODEL = 'KaiDroid N139DL development'


def parse(text):
    return json.loads('\n'.join(line for line in text[1:].splitlines()
                               if not line.lstrip().startswith('//')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    if sha(args.apk.read_bytes()) != APK_SHA:
        raise ValueError('Unrecognized donor APK')
    with zipfile.ZipFile(args.apk) as archive:
        original = archive.read('lib/armeabi/libiqqijni.so')
    if sha(original) != CONFIG_SHA:
        raise ValueError('Unexpected donor config')
    decoded = ''.join(chr(ord(c) ^ 6) for c in original.decode('utf-8'))
    before = parse(decoded)
    entry = next(x for x in before['Settings'] if x['Config'] == 'LOCK_MACHINE_CODE')
    previous = entry['Value']
    if MODEL in previous.split('\uff0c') or decoded.count(previous) != 1:
        raise ValueError('Ambiguous or already modified model list')
    modified = decoded.replace(previous, previous + '\uff0c' + MODEL)
    after = parse(modified)
    entry['Value'] += '\uff0c' + MODEL
    if before != after:
        raise ValueError('Unexpected configuration changes')
    candidate = ''.join(chr(ord(c) ^ 6) for c in modified).encode('utf-8')
    args.output.mkdir(parents=True)
    (args.output / 'libiqqijni.so').write_bytes(candidate)
    (args.output / 'original-config.bin').write_bytes(original)
    (args.output / 'report.json').write_text(json.dumps({
        'original_sha256': CONFIG_SHA, 'candidate_sha256': sha(candidate),
        'added_model': MODEL, 'property': 'ro.product.model',
        'scope': 'Model list only; private candidate, not installed',
    }, indent=2) + '\n', encoding='utf-8')
    print((args.output / 'report.json').read_text())


if __name__ == '__main__':
    main()

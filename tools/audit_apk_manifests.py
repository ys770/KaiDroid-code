"""Inventory APK manifest constraints using Android SDK aapt; never runs APKs."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aapt', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--name-pattern', default='Launcher|SystemUI|Settings|Dialer|Contacts|Messaging|IME|TeleService')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    entries = []
    for apk in sorted(args.root.rglob('*.apk')):
        if not re.search(args.name_pattern, apk.name, re.I):
            continue
        relative = apk.relative_to(args.root).as_posix()
        output = args.output / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        badging = subprocess.run([str(args.aapt), 'dump', 'badging', str(apk)],
                                 check=True, capture_output=True, encoding='utf-8', errors='replace').stdout
        tree = subprocess.run([str(args.aapt), 'dump', 'xmltree', str(apk), 'AndroidManifest.xml'],
                              check=True, capture_output=True, encoding='utf-8', errors='replace').stdout
        output.with_suffix('.badging.txt').write_text(badging, encoding='utf-8')
        output.with_suffix('.manifest.txt').write_text(tree, encoding='utf-8')

        def field(pattern):
            match = re.search(pattern, badging, re.M)
            return match.group(1) if match else None

        with zipfile.ZipFile(apk) as archive:
            native = [name for name in archive.namelist() if name.startswith('lib/') and name.endswith('.so')]
            dex = [name for name in archive.namelist() if re.fullmatch(r'classes\d*\.dex', name)]
        shared_id = re.search(r'android:sharedUserId[^=]*="([^"]+)"', tree)
        entries.append({'path': relative, 'bytes': apk.stat().st_size,
                        'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
                        'package': field(r"^package: name='([^']+)'"),
                        'min_sdk': field(r"^sdkVersion:'([^']+)'"),
                        'target_sdk': field(r"^targetSdkVersion:'([^']+)'"),
                        'shared_user_id': shared_id.group(1) if shared_id else None,
                        'libraries': re.findall(r"^uses-library[^:]*:'([^']+)'", badging, re.M),
                        'native_libraries': native, 'dex_entries': dex})
    (args.output / 'summary.json').write_text(json.dumps(entries, indent=2) + '\n', encoding='utf-8')
    print(json.dumps([{'file': Path(entry['path']).name, 'package': entry['package'],
                       'min_sdk': entry['min_sdk'], 'target_sdk': entry['target_sdk'],
                       'shared_user_id': entry['shared_user_id'], 'libraries': entry['libraries']}
                      for entry in entries], indent=2))


if __name__ == '__main__':
    main()

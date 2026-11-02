"""Check image18's required concrete framework methods without executing them.

Input must be framework.jar extracted from the candidate image. This is an
offline packaging gate; installed boot-class and UI tests remain required.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

from audit_dex_references import read_dex

REQUIRED = {
    ('Landroid/view/accessibility/AccessibilityRecord;', 'isSynthesized', '()Z'),
    ('Landroid/view/accessibility/AccessibilityRecord;', 'setSynthesized', '(Z)V'),
    ('Landroid/widget/KeypadSoftkeyBar;', '<init>', '(Landroid/content/Context;)V'),
    ('Landroid/widget/KeypadSoftkeyBar;', 'showState', '(Landroid/widget/KeypadSoftkeyState;)V'),
    ('Landroid/widget/KeypadSoftkeyState;', 'resolve',
     '(Landroid/widget/KeypadSoftkeyState;Landroid/widget/KeypadSoftkeyState;ZZ)Landroid/widget/KeypadSoftkeyState;'),
    ('Landroid/widget/MenuBar;', '<init>', '(Landroid/content/Context;)V'),
}


def verify(path, allow_stale_sha1=False):
    definitions = set()
    entries = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if re.fullmatch(r'classes\d*\.dex', name):
                data = archive.read(name)
                _, _, methods, stale = read_dex(data, allow_stale_sha1=allow_stale_sha1,
                                                definitions_only=True)
                definitions.update(methods)
                entries.append(dict(name=name, sha256=hashlib.sha256(data).hexdigest(),
                                    concrete_methods=len(methods), stale_header_sha1=stale))
    missing = REQUIRED - definitions
    if missing:
        raise ValueError('Missing concrete methods: ' + repr(sorted(missing)))
    return dict(jar_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                dex=entries, required_concrete_methods=sorted(REQUIRED),
                runtime_validated=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jar', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-stale-sha1', action='store_true',
                        help='Explicit structural-only analysis; retain checksum validation and report stale digests')
    args = parser.parse_args()
    result = verify(args.jar, args.allow_stale_sha1)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result))

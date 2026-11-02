"""Prepare a held, feature-gated PiP dependency candidate from pinned source.

Writes only a fresh local candidate tree and patch. Does not edit AOSP, build,
install, change feature declarations or establish RAM savings.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

SOURCE = 'frameworks/base/packages/SystemUI/src/com/android/systemui/pip/PipUI.java'
PIN = '6ded26651357708e35cb65fe7a1384acc113ecca6872e918be9c1253cbe5e9cc'


def candidate(raw):
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError('PipUI source identity changed')
    text = raw.decode()
    for old, new in [
        ('import javax.inject.Inject;', 'import dagger.Lazy;\n\nimport javax.inject.Inject;'),
        ('            BasePipManager pipManager) {', '            Lazy<BasePipManager> pipManager) {'),
        ('        mPipManager = pipManager;',
         '        // Keep the existing eager path on supported devices. On unsupported devices,\n'
         '        // do not construct the PiP controller/listener graph merely to skip start().\n'
         '        mPipManager = context.getPackageManager().hasSystemFeature(\n'
         '                FEATURE_PICTURE_IN_PICTURE) ? pipManager.get() : null;'),
    ]:
        if text.count(old) != 1:
            raise ValueError('Unexpected source marker')
        text = text.replace(old, new, 1)
    for signature in ['public void showPictureInPictureMenu() {', 'public void expandPip() {',
                      'public void hidePipMenu(Runnable onStartCallback, Runnable onEndCallback) {']:
        if text.count(signature) != 1:
            raise ValueError('Unexpected forwarding method')
        text = text.replace(signature, signature + '\n        if (mPipManager == null) {\n            return;\n        }', 1)
    return text


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--patch', type=Path, required=True)
    a = p.parse_args()
    raw = (a.source / SOURCE).read_bytes()
    changed = candidate(raw)
    a.output.mkdir(parents=True, exist_ok=False)
    target = a.output / SOURCE
    target.parent.mkdir(parents=True)
    target.write_bytes(changed.encode())
    patch = ''.join(difflib.unified_diff(raw.decode().splitlines(True), changed.splitlines(True),
                                       fromfile='a/' + SOURCE, tofile='b/' + SOURCE))
    with a.patch.open('x', newline='\n') as file: file.write(patch)
    (a.output / 'preparation.json').write_text(json.dumps(dict(source_sha256=PIN,
        candidate_sha256=hashlib.sha256(changed.encode()).hexdigest(),
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        built=False, installed=False, savings_proven=False), indent=2) + '\n')

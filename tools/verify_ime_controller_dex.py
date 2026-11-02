"""Verify concrete IME bridge/controller definitions in image-extracted jars.

This checks packaging, not lifecycle behavior. Never substitutes for device tests.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

from audit_dex_references import read_dex
from verify_framework18_dex import verify as verify_previous_framework

REQUIRED = {
    'framework.jar': {
        ('Landroid/view/inputmethod/InputMethodManager;', 'getImeWindowStatus', '()I'),
        ('Landroid/view/inputmethod/InputMethodManager;', 'getImeClientWindowStatus', '()I'),
        ('Lcom/android/internal/view/IInputMethodManager$Stub$Proxy;', 'getImeClientWindowStatus', '()I'),
        ('Lcom/android/internal/view/IInputMethodManager$Stub$Proxy;', 'getImeWindowStatus', '()I'),
        ('Landroid/widget/KeypadImeController;', '<init>', '(Landroid/widget/MenuBar;)V'),
        ('Landroid/widget/KeypadImeController;', 'attach', '()V'),
        ('Landroid/widget/KeypadImeController;', 'detach', '()V'),
        ('Landroid/widget/KeypadImeController;', 'refreshOwner', '()V'),
        ('Landroid/widget/KeypadImeController;', 'showPicker', '()V'),
        ('Landroid/widget/MenuBar;', 'setImeMode', '(Ljava/lang/String;Ljava/lang/Runnable;)V'),
        ('Landroid/widget/MenuBar;', 'clearImeMode', '()V'),
    },
    'services.jar': {
        ('Lcom/android/server/inputmethod/InputMethodManagerService;', 'getImeWindowStatus', '()I'),
        ('Lcom/android/server/inputmethod/InputMethodManagerService;', 'getImeClientWindowStatus', '()I'),
        ('Lcom/android/server/inputmethod/MultiClientInputMethodManagerService$ApiCallbacks;',
         'getImeClientWindowStatus', '()I'),
        ('Lcom/android/server/inputmethod/MultiClientInputMethodManagerService$ApiCallbacks;',
         'getImeWindowStatus', '()I'),
    },
}


def verify(framework, services, allow_stale_sha1=False):
    previous = verify_previous_framework(framework, allow_stale_sha1)
    result = {}
    for name, path in [('framework.jar', framework), ('services.jar', services)]:
        definitions = set()
        entries = []
        with zipfile.ZipFile(path) as archive:
            for entry in archive.namelist():
                if not re.fullmatch(r'classes\d*\.dex', entry):
                    continue
                data = archive.read(entry)
                _, _, methods, stale = read_dex(data, allow_stale_sha1=allow_stale_sha1,
                                                definitions_only=True)
                definitions.update(methods)
                entries.append({'name': entry, 'sha256': hashlib.sha256(data).hexdigest(),
                                'stale_header_sha1': stale})
        missing = REQUIRED[name] - definitions
        if missing:
            raise ValueError(name + ' missing concrete methods: ' + repr(sorted(missing)))
        result[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'required_concrete_methods': sorted(REQUIRED[name]), 'dex': entries}
    return {'jars': result, 'previous_framework_gate': previous, 'runtime_validated': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--framework', type=Path, required=True)
    parser.add_argument('--services', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-stale-sha1', action='store_true')
    args = parser.parse_args()
    result = verify(args.framework, args.services, args.allow_stale_sha1)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'verified': list(result['jars']), 'runtime_validated': False}))

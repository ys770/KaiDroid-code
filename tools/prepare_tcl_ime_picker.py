"""Prepare an isolated titleless TCL keyboard picker over accepted49; never install."""
import argparse
import hashlib
import json
from pathlib import Path

BASE = '633dc17c0e4778bdb86e14f9d591ef39a11cc1fcda235816f9c4871e20482acd'
PICKER = 'a2569a1f47a16117c83d66cab56800965c5cca1bfd9d062e57905a6782aef5f5'


def controller(data):
    if hashlib.sha256(data).hexdigest() != BASE:
        raise ValueError('Requires exact accepted49 IME controller')
    text = data.decode('utf-8').replace('\r\n', '\n')
    text = text.replace('import android.app.AlertDialog;', 'import android.app.Dialog;')
    text = text.replace('private AlertDialog picker;', 'private KeypadImePicker picker;')
    text = text.replace('AlertDialog old = picker;', 'Dialog old = picker;')
    old = '''final AlertDialog dialog = new AlertDialog.Builder(context).setTitle("Input mode")
                .setItems(choices.toArray(new String[0]), (ignored, index) -> {'''
    new = '''final KeypadImePicker dialog = new KeypadImePicker(context, choices, index -> {'''
    if text.count(old) != 1 or text.count('                }).create();') != 1:
        raise ValueError('Unexpected picker source shape')
    text = text.replace(old, new).replace('                }).create();', '                });')
    old = '''            dialog.getListView().setSelection(0);
            dialog.getListView().requestFocus();'''
    if text.count(old) != 1:
        raise ValueError('Unexpected initial picker focus')
    text = text.replace(old, '            dialog.focusFirstChoice();')
    return text.encode('utf-8')


def sources(root, version=2):
    helper = (root/'experiments/ui/KeypadImePicker.java').read_bytes()
    if hashlib.sha256(helper).hexdigest() != PICKER:
        raise ValueError('Unreviewed picker helper')
    owner = controller((root/'framework/core/java/android/widget/KeypadImeController.java').read_bytes())
    if version == 1:
        return {'core/java/android/widget/KeypadImeController.java': owner,
                'core/java/android/widget/KeypadImePicker.java': helper}
    if version != 2:
        raise ValueError('Unreviewed picker packaging version')
    # A package-private top-level helper can share the existing source unit.
    # This avoids a new bind target or copying the shared android/widget tree.
    text = owner.decode('utf-8')
    missing = [line for line in helper.decode('utf-8').splitlines()
               if line.startswith('import ') and line not in text.splitlines()]
    marker = '/** Window-local owner of the observed keyboard mode protocol. @hide */'
    if text.count(marker) != 1:
        raise ValueError('Unexpected controller declaration')
    text = text.replace(marker, '\n'.join(missing)+'\n\n'+marker)
    body = helper.decode('utf-8').split('/** Original TCL titleless keyboard menu geometry;', 1)
    if len(body) != 2:
        raise ValueError('Unexpected helper declaration')
    text += '\n/** Original TCL titleless keyboard menu geometry;'+body[1]
    return {'core/java/android/widget/KeypadImeController.java': text.encode('utf-8')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version', type=int, choices=(1, 2), default=2)
    p.add_argument('--build-inputs', action='store_true', help='Include exact retained49 MenuBar/TctDialog for preserved48 compile cache')
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    files = sources(Path(__file__).resolve().parents[1], args.version)
    if args.build_inputs:
        if args.version != 2:
            raise ValueError('Build inputs require packaging02')
        root = Path(__file__).resolve().parents[1]
        for name, digest in {
            'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
            'core/java/android/app/TctDialog.java':'e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6',
        }.items():
            data = (root/'framework'/name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Retained49 source changed: '+name)
            files[name] = data
    for name, data in files.items():
        dest = args.output/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    report = dict(packaging_version=args.version,compile_cache48_input_completion=args.build_inputs,baseline_controller_sha256=BASE,
        files={name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        source_reference='docs/evidence/tcl-kika-notes-picker01.json',
        active_framework_modified=False, platform_built=False, installed=False,
        ownership_focus_generation_checks_retained=True)
    (args.output/'contract.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

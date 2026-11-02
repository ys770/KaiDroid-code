"""Check or apply the experimental framework integration to a clean base checkout.

Use a disposable frameworks/base checkout. Never builds or flashes. File hashes
bind the patch; the report records the checkout revision and exact staged inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Git ' + ' '.join(args) + ' failed:\n' + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    target = args.source.resolve()
    report = args.report.resolve()
    if report.exists() or report == target or target in report.parents:
        raise ValueError('Report must be a new path outside the target checkout')
    if Path(git(target, 'rev-parse', '--show-toplevel')).resolve() != target:
        raise ValueError('Source must be the root of its own frameworks/base Git checkout')
    if git(target, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Source checkout must be clean')
    pin = json.loads((project / 'docs/contracts/tcl-window-methods.json').read_text())['platform_source']
    before = {}
    accessibility = json.loads((project / 'docs/contracts/tcl-accessibility-methods.json').read_text())
    ime_status = json.loads((project / 'docs/contracts/tcl-ime-window-status.json').read_text())
    if any(contract['revision'] != pin['revision'] for contract in (accessibility, ime_status)):
        raise ValueError('Framework source revisions disagree')
    for entry in [*pin['files'], *accessibility['files'], *ime_status['files']]:
        path = target / entry['path']
        if target not in path.resolve().parents:
            raise ValueError('Pinned source escapes target checkout')
        if digest(path) != entry['sha256']:
            raise ValueError('Pinned source mismatch: ' + entry['path'])
        before[entry['path']] = entry['sha256']
    additions = {}
    for relative in ('core/java/android/app/TctDialog.java',
                     'core/java/android/widget/MenuBar.java',
                     'core/java/android/widget/KeypadSoftkeyBar.java',
                     'core/java/android/widget/KeypadSoftkeyState.java',
                     'core/java/android/widget/KeypadImeModeState.java',
                     'core/java/android/widget/KeypadImeController.java',
                     'core/java/android/widget/TctDialogMessage.java',
                     'core/java/android/widget/TitleEditText.java',
                     'core/res/res/values/kaidroid_title_editor.xml',
                     'core/res/res/values/kaidroid_styles.xml'):
        destination = target / relative
        if destination.exists() or destination.is_symlink():
            raise ValueError('Refusing to replace existing file: ' + relative)
        if target not in destination.resolve().parents:
            raise ValueError('Destination escapes target checkout')
        additions[relative] = (project / 'framework' / relative).read_bytes()
    patch = project / 'framework/patches/0001-window-menubar.patch'
    patches = [patch, project / 'framework/patches/0002-accessibility-synthesized.patch',
               project / 'framework/patches/0003-ime-window-status.patch']
    git(target, 'apply', '--check', *map(str, patches))
    evidence = {'scope': __doc__, 'applied': False,
                'checkout_revision': git(target, 'rev-parse', 'HEAD'),
                'upstream_pin': pin['revision'], 'before_sha256': before,
                'patch_sha256': digest(patch),
                'patches_sha256': {p.name: digest(p) for p in patches},
                'added_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in additions.items()},
                'platform_compiled': False}
    # All validations precede writes. Keep the check report on an interrupted
    # apply; Git diff and the listed paths identify any partial changes.
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(evidence, indent=2) + '\n')
    if args.apply:
        git(target, 'apply', *map(str, patches))
        for relative, data in additions.items():
            path = target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
        evidence['after_sha256'] = {name: digest(target / name) for name in [*before, *additions]}
        evidence['applied'] = True
        report.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'applied': evidence['applied'], 'patched_files': len(before),
                      'added_files': len(additions), 'report': str(report)}))


if __name__ == '__main__':
    main()

"""Stage the coordinated title-editor additions; preserve source and output baselines."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

POLICY_SHA = '63de58a1632c9161cf3a42308add52640afcf34100bbfa3d83ed18891b9e09eb'
ADDITIONS = ('core/java/android/widget/TitleEditText.java',
             'core/res/res/values/kaidroid_title_editor.xml')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'inputs', 'output', 'product'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise FileExistsError(a.output)
    policy = a.base / 'config/hiddenapi-greylist.txt'
    if sha(policy) != POLICY_SHA:
        raise ValueError('Hidden API baseline changed')
    manifest = json.loads((a.inputs / 'manifest.json').read_text())
    expected = {Path(n).name for n in ADDITIONS} | {'title-editor-hiddenapi.txt'}
    if set(manifest) != expected or any(sha(a.inputs / n) != h for n, h in manifest.items()):
        raise ValueError('Candidate identity mismatch')
    for name in ADDITIONS:
        if (a.base / name).exists() or (a.base / name).is_symlink():
            raise FileExistsError(name)
    signatures = (a.inputs / 'title-editor-hiddenapi.txt').read_text().splitlines()
    if len(signatures) != 14 or len(set(signatures)) != 14:
        raise ValueError('Unexpected hidden API set')
    if any(not s.startswith('Landroid/widget/TitleEditText') for s in signatures):
        raise ValueError('Unrelated hidden API entry')
    original = policy.read_bytes()
    if set(signatures) & set(original.decode().splitlines()):
        raise ValueError('Signatures already staged')
    changed = set()
    for args in (('diff', '--name-only', '-z', 'HEAD'),
                 ('ls-files', '--others', '--exclude-standard', '-z')):
        result = subprocess.run(['git', '-C', str(a.base), *args], capture_output=True, check=True)
        changed.update(n.decode() for n in result.stdout.split(b'\0') if n)
    before = {n: sha(a.base / n) if (a.base / n).is_file() else None for n in changed}
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'hiddenapi.original.txt').write_bytes(original)
    outputs = {}
    for name in ('framework.jar', 'framework-res.apk'):
        src = a.product / 'system/framework' / name
        outputs[name] = sha(src)
        shutil.copy2(src, a.output / (name + '.original'))
    report = dict(before=before, candidates=manifest, original_outputs=outputs,
                  hiddenapi_additions=signatures, compiled=False, installed=False)
    (a.output / 'prestage.json').write_text(json.dumps(report, indent=2) + '\n')
    for name in ADDITIONS:
        with (a.base / name).open('xb') as stream:
            stream.write((a.inputs / Path(name).name).read_bytes())
    policy.write_bytes(original.rstrip(b'\n') + b'\n' + ('\n'.join(signatures) + '\n').encode())
    for name, digest in before.items():
        if name == 'config/hiddenapi-greylist.txt':
            continue
        if (sha(a.base / name) if (a.base / name).is_file() else None) != digest:
            raise ValueError('Unrelated source changed: ' + name)
    report.update(unrelated_preserved=True, policy_sha256=sha(policy))
    (a.output / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(staged=True, unrelated_preserved=True, hiddenapi_entries=14)))


if __name__ == '__main__':
    main()

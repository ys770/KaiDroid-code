"""Stage the coordinated three-file visibility fix, preserving original sources."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

FILES = {
    'core/java/android/widget/MenuBar.java': 'de64de0108f3b8d848dad37df7da840f668dfa7ec739df504bf18b649d154761',
    'core/java/android/widget/KeypadImeController.java': '1253c5e19b5488abf3d99aa1e316b74faeeb02d0a8c35f83e356c3e66607175b',
    'core/java/com/android/internal/policy/DecorView.java': '29d756c3e1bfb073b1095157cb1f5202ef2118a4077842850df7c3884801cd77',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stage(base, inputs, output):
    if output.exists():
        raise FileExistsError(output)
    manifest = json.loads((inputs / 'candidates.json').read_text())
    if set(manifest) != set(FILES):
        raise ValueError('Unexpected candidate paths')
    before, candidates = {}, {}
    for path, expected in FILES.items():
        before[path] = (base / path).read_bytes()
        candidates[path] = (inputs / Path(path).name).read_bytes()
        if sha(before[path]) != expected or sha(candidates[path]) != manifest[path]:
            raise ValueError('Source or candidate identity mismatch: ' + path)
    changed = set()
    for args in (('diff', '--name-only', '-z', 'HEAD'),
                 ('ls-files', '--others', '--exclude-standard', '-z')):
        result = subprocess.run(['git', '-C', str(base), *args], check=True, capture_output=True)
        changed.update(n.decode() for n in result.stdout.split(b'\0') if n)
    unrelated = {n: sha((base / n).read_bytes()) if (base / n).is_file() else None
                 for n in changed if n not in FILES}
    output.mkdir(parents=True, exist_ok=False)
    for name, data in before.items():
        (output / (Path(name).name + '.original')).write_bytes(data)
    report = dict(before=FILES, candidates=manifest, unrelated=unrelated,
                  compiled=False, installed=False)
    (output / 'prestage.json').write_text(json.dumps(report, indent=2) + '\n')
    for name, data in candidates.items():
        (base / name).write_bytes(data)
    for name, digest in unrelated.items():
        actual = sha((base / name).read_bytes()) if (base / name).is_file() else None
        if actual != digest:
            raise ValueError('Unrelated source changed: ' + name)
    report['unrelated_preserved'] = True
    (output / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(staged=True, files=len(FILES), unrelated_preserved=True)))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'inputs', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    stage(a.base, a.inputs, a.output)

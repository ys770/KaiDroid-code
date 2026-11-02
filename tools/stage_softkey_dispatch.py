"""Stage the coordinated two-file callback dispatch fix, preserving original sources."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

FILES = {'core/java/android/widget/MenuBar.java': '7c40b06092a8b620b8c35c82068cea75ae1eb21f23fd745bc83a9dd893ed9b94', 'core/java/com/android/internal/policy/DecorView.java': 'fa5a584e662b6f1059572f6e1daa8e313d774dacb84bb52884543426db72b679'}


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

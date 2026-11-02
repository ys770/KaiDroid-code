"""Stage the pinned IMS callback source in a new directory; never edit AOSP in place."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[1]
REL = Path('frameworks/base/telephony/java/android/telephony/ims/ImsCallSessionListener.java')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source, output):
    spec = json.loads((REPO / 'experiments/ims01/callback-adapter.json').read_text())
    original = source.read_bytes()
    if sha(original) != spec['source_sha256']:
        raise ValueError('Original source hash mismatch; no output created')
    output.mkdir(parents=True, exist_ok=False)
    target = output / REL
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    patch = REPO / 'experiments/ims01/ImsCallSessionListener.patch'
    # A new isolated directory keeps both accepted source and prior attempts intact.
    for flags in (['--check'], []):
        subprocess.run(['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                        'apply', *flags, str(patch)], cwd=output, check=True,
                       capture_output=True, timeout=30)
    candidate = target.read_bytes()
    if sha(candidate) != spec['candidate_sha256']:
        raise ValueError('Patched source hash mismatch; retain failed stage for diagnosis')
    if source.read_bytes() != original:
        raise ValueError('Original source changed concurrently')
    report = {
        'classification': 'isolated_source_preparation_only',
        'source_sha256': sha(original),
        'candidate_sha256': sha(candidate),
        'patch_sha256': sha(patch.read_bytes()),
        'original_unchanged': True,
        'compiled': False,
        'installed': False,
        'binder_behavior_validated': False,
    }
    (output / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source.resolve(), args.output.resolve()), indent=2))

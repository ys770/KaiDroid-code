"""Stage only the reviewed marquee candidate, preserving shared source/output.

Run only after build-tree coordination and an idle-build preflight. This script
does not start a build or touch a device. Existing unrelated edits are hashed
before/after and must remain identical.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

BASE = 'f6b3bf402c3ec891ecb49e41e0e4f6a6c1219c62337ab483793f64f636d3dbf8'
CANDIDATE = 'c7fb014c23232506ba18abb0fec299ca5b88740fce3df868079fb250adc178cb'
WIDGET = 'bedf13ee55571a3b8e22e05b53cd93f50dca5f3c0a93d58e164ee6bef4faad49'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('aosp', 'out', 'candidate', 'stage'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    base = a.aosp / 'frameworks/base'
    text = base / 'core/java/android/widget/TextView.java'
    widget = base / 'core/java/android/widget/MarqueeTextView.java'
    policy = base / 'config/hiddenapi-greylist.txt'
    if sha(text) != BASE or sha(a.candidate / 'TextView.java') != CANDIDATE or sha(a.candidate / 'MarqueeTextView.java') != WIDGET:
        raise ValueError('Marquee source identity mismatch')
    if widget.exists() or widget.is_symlink():
        raise ValueError('MarqueeTextView already exists; review before restaging')
    # Capture all modified/untracked framework files without assuming a clean tree.
    def paths(*args):
        output = subprocess.run(['git', '-C', str(base), *args], check=True, capture_output=True).stdout
        return [Path(n.decode()) for n in output.split(b'\0') if n]
    changed = set(paths('diff', '--name-only', '-z', 'HEAD')) | set(paths('ls-files', '--others', '--exclude-standard', '-z'))
    before = {str(n): sha(base / n) if (base / n).is_file() else None for n in changed}
    policy_data = policy.read_bytes()
    additions = [
        'Landroid/widget/MarqueeTextView;-><init>(Landroid/content/Context;)V',
        'Landroid/widget/MarqueeTextView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V',
        'Landroid/widget/MarqueeTextView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V',
        'Landroid/widget/MarqueeTextView;->startMarquee()V',
        'Landroid/widget/MarqueeTextView;->stopMarquee()V',
    ]
    existing = policy_data.decode().splitlines()
    if any(line in existing for line in additions):
        raise ValueError('Marquee hidden-API policy already staged')
    a.stage.mkdir(parents=True)
    (a.stage / 'TextView.original.java').write_bytes(text.read_bytes())
    (a.stage / 'hiddenapi-greylist.original.txt').write_bytes(policy_data)
    original_jar = a.out / 'target/product/n139dl/system/framework/framework.jar'
    shutil.copy2(original_jar, a.stage / 'framework.original.jar')
    report = dict(before_framework_edits_sha256=before,
                  original_framework_sha256=sha(original_jar),
                  source_sha256=BASE, candidate_sha256=CANDIDATE, widget_sha256=WIDGET,
                  original_policy_sha256=hashlib.sha256(policy_data).hexdigest(),
                  hiddenapi_additions=additions, compiled=False, installed=False)
    (a.stage / 'prestage.json').write_text(json.dumps(report, indent=2) + '\n')
    text.write_bytes((a.candidate / 'TextView.java').read_bytes())
    with widget.open('xb') as f:
        f.write((a.candidate / 'MarqueeTextView.java').read_bytes())
    policy.write_bytes(policy_data.rstrip(b'\n') + b'\n' + ('\n'.join(additions) + '\n').encode())
    for name, digest in before.items():
        if name.replace('\\', '/') == 'config/hiddenapi-greylist.txt':
            continue
        path = base / name
        if (sha(path) if path.is_file() else None) != digest:
            raise ValueError('Unrelated source changed during staging: ' + name)
    report.update(unrelated_framework_edits_preserved=True, staged_policy_sha256=sha(policy))
    (a.stage / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'staged': True, 'stage': str(a.stage), 'unrelated_edits_preserved': True}))


if __name__ == '__main__':
    main()

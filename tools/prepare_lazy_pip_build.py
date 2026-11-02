"""Render or prepare an isolated PiP stage. Actual preparation requires an assigned host slot.

Neither mode launches a build, changes shared AOSP/output files or uses the phone.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from prepare_lazy_pip_candidate import SOURCE, PIN, candidate

ROOT = '/opt/kaidroid/kaidroid-build-20261023'
RETAINED = 'memory-wallpaper-build01'
APK = '2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
GRAPH = '931aa0c06b4ccb817efaef6098c52574215608b0952c8eb168c3246b1abb6e4d'
MANIFEST = 'b0414fb515eb234013d5de8f09c814fe1a663aa6961fd4328b88f58697387f49'
SCRIPTS = {'build.sh': '182eae6405f7692afa3be2bcb1021d305fb700f88297ac18ea840422c71cc652',
           'launch.sh': 'b06e6e815e7aea6905b8d2fc1f0519da26647498eec4fb104521ce477624cc06'}
CANDIDATE = 'a15aa15d9af269aa10357c8c9d18690526a0bebe22543aaf8506d9b50a8ed073'
SUBTREES = ['inputs', 'ninja', 'intermediates', 'settingslib-intermediates', 'dependency-intermediates']


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text, old, new):
    if text.count(old) != 1: raise ValueError('Unexpected retained script marker')
    return text.replace(old, new, 1)


def render(manifest_raw, scripts, query, name):
    if not re.fullmatch(r'memory-lazy-pip-build\d{2}', name): raise ValueError('Invalid fresh stage name')
    if hashlib.sha256(manifest_raw).hexdigest() != MANIFEST: raise ValueError('Retained manifest changed')
    m = json.loads(manifest_raw)
    if m['stage'] != ROOT + '/' + RETAINED or m['ninja_manifest_sha256'] != GRAPH or not m['wallpaper_prepared']:
        raise ValueError('Retained stage/graph mismatch')
    if hashlib.sha256(query).hexdigest() != m['inputs']['query.ninja']: raise ValueError('Retained query changed')
    for key, pin in SCRIPTS.items():
        if hashlib.sha256(scripts[key]).hexdigest() != pin: raise ValueError('Retained script changed')
    rendered = {key: raw.decode().replace(RETAINED, name) for key, raw in scripts.items()}
    rendered['query.ninja'] = query.decode().replace(RETAINED, name)
    launch = once(rendered['launch.sh'], 'test -f "$stage/wallpaper-staging.complete"', 'test -f "$stage/pip-staging.complete"')
    marker = 'sudo docker image inspect'
    guard = '''python3 - "$stage" <<'PY'
import hashlib,json,sys
from pathlib import Path
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text())
assert (s/'pip-staging.complete').read_text().strip()==hashlib.sha256((s/'staging.json').read_bytes()).hexdigest()
assert m['pip_prepared'] is True
for name,digest in m['generated_scripts_sha256'].items():
 assert hashlib.sha256((s/name).read_bytes()).hexdigest()==digest,name
PY
'''
    launch = once(launch, marker, guard + marker)
    mount = '  -v "$stage/inputs/PipUI.java:/build/aosp/' + SOURCE + ':ro" \\\n'
    launch = once(launch, '  kaidroid-build:20261023 bash ', mount + '  kaidroid-build:20261023 bash ')
    rendered['launch.sh'] = launch
    check = "assert m['pip_prepared'] is True\nassert hashlib.sha256(Path('/build/aosp/" + SOURCE + "').read_bytes()).hexdigest()==m['pip_source']['candidate_sha256']\n"
    rendered['build.sh'] = once(rendered['build.sh'], 'PY\nprebuilts/build-tools/linux-x86/bin/ninja', check + 'PY\nprebuilts/build-tools/linux-x86/bin/ninja')
    updated = copy.deepcopy(m)
    updated.update(stage=ROOT + '/' + name, retained_stage=ROOT + '/' + RETAINED,
        retained_comparison_apk_sha256=APK, baseline_apk_sha256=APK, installed_comparison_apk_sha256=APK,
        pip_source=dict(path=SOURCE, original_sha256=PIN, candidate_sha256=CANDIDATE),
        pip_prepared=False, launched=False, installed=False,
        generated_scripts_sha256={key: hashlib.sha256(text.encode()).hexdigest() for key, text in rendered.items() if key != 'query.ninja'})
    return updated, rendered


def stage(root, retained, candidate_root, name):
    if os.name != 'posix': raise ValueError('Actual preparation requires Linux')
    root = root.resolve(strict=True); retained = retained.resolve(strict=True); dest = root / name
    if str(root) != ROOT or retained != root / RETAINED or dest.exists(): raise ValueError('Require reviewed roots and fresh destination')
    raw = (retained / 'staging.json').read_bytes()
    m, rendered = render(raw, {k: (retained / k).read_bytes() for k in SCRIPTS}, (retained / 'inputs/query.ninja').read_bytes(), name)
    old = json.loads(raw)
    if (retained / 'build.exit').read_text().strip() != '0' or sha(retained / 'output/SystemUI.apk') != APK:
        raise ValueError('Retained completed APK mismatch')
    if (retained / 'wallpaper-staging.complete').read_text().strip() != MANIFEST or sha(root / 'out-eng-02/soong/build.ninja') != GRAPH:
        raise ValueError('Retained completion/shared graph changed')
    for filename, pin in old['inputs'].items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', filename) or (retained / 'inputs' / filename).is_symlink() or sha(retained / 'inputs' / filename) != pin:
            raise ValueError('Retained input changed: ' + filename)
    if {p.name for p in (retained / 'inputs').iterdir()} != set(old['inputs']): raise ValueError('Unexpected retained input')
    original = (root / 'aosp' / SOURCE).read_bytes()
    if sha(root / 'aosp' / SOURCE) != PIN or sha(candidate_root / SOURCE) != CANDIDATE or (candidate_root / SOURCE).read_bytes() != candidate(original).encode():
        raise ValueError('Source/candidate changed')
    for subtree in SUBTREES:
        p = retained / subtree
        if p.is_symlink() or not p.is_dir() or not p.resolve().is_relative_to(retained): raise ValueError('Cache subtree escapes stage')
    for process in ['ninja', 'soong_build', 'e2fsdroid']:
        if subprocess.run(['pgrep', '-x', process], capture_output=True).returncode != 1:
            raise ValueError('Build active or process status ambiguous')
    sizes = subprocess.run(['du', '-sb', '--count-links', *[str(retained / p) for p in SUBTREES]], capture_output=True, text=True, check=True)
    needed = sum(int(line.split('\t', 1)[0]) for line in sizes.stdout.splitlines())
    free = shutil.disk_usage(root).free
    if free < needed + 2 * 1024**3: raise ValueError('Insufficient space for independent copies and 2GiB margin')
    m['copy_space_preflight'] = dict(apparent_bytes=needed, free_bytes=free, margin_bytes=2 * 1024**3)
    dest.mkdir()
    for subtree in SUBTREES:
        subprocess.run(['cp', '--reflink=auto', '-a', str(retained / subtree), str(dest / subtree)], check=True)
    shutil.copy2(retained / 'output/SystemUI.apk', dest / 'inputs/SystemUI.comparison.apk')
    (dest / 'inputs/PipUI.java.original').write_bytes(original)
    (dest / 'inputs/PipUI.java').write_bytes((candidate_root / SOURCE).read_bytes())
    for key, text in rendered.items():
        (dest / ('inputs/query.ninja' if key == 'query.ninja' else key)).write_bytes(text.encode())
    cached = [dest / 'intermediates/SystemUI-core/android_common/javac/SystemUI-core.jar', dest / 'intermediates/SystemUI/android_common/SystemUI.apk']
    if any(p.is_symlink() or not p.resolve().is_relative_to(dest) for p in cached): raise ValueError('Cached output escapes stage')
    now = time.time_ns(); latest = max(p.stat().st_mtime_ns for p in cached)
    if latest > now + 5_000_000_000: raise ValueError('Future cached output timestamp')
    fresh = max(now, latest + 2_000_000_000)
    for filename in ['AccessPointControllerImpl.java', 'BubbleDataRepository.kt', 'SystemUI.proguard.flags', 'ImageWallpaper.java', 'ImageWallpaperRenderer.java', 'PipUI.java']:
        os.utime(dest / 'inputs' / filename, ns=(fresh, fresh))
    m.update(pip_prepared=True, fresh_input_timestamp_ns=fresh,
             inputs={p.name: sha(p) for p in (dest / 'inputs').iterdir()}, free_bytes_after_preparation=shutil.disk_usage(root).free)
    (dest / 'staging.json').write_text(json.dumps(m, indent=2) + '\n')
    for key in SCRIPTS: subprocess.run(['bash', '-n', str(dest / key)], check=True)
    (dest / 'pip-staging.complete').write_text(sha(dest / 'staging.json') + '\n')
    return m


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name', required=True)
    p.add_argument('--render-only', type=Path)
    p.add_argument('--retained-snapshot', type=Path)
    p.add_argument('--retained-query', type=Path)
    p.add_argument('--root', type=Path)
    p.add_argument('--retained-stage', type=Path)
    p.add_argument('--candidate-root', type=Path)
    a = p.parse_args()
    if a.render_only:
        if not a.retained_snapshot or not a.retained_query: p.error('Render requires snapshot and query')
        m, scripts = render((a.retained_snapshot / 'staging.json').read_bytes(),
            {k: (a.retained_snapshot / k).read_bytes() for k in SCRIPTS}, a.retained_query.read_bytes(), a.name)
        if (a.retained_snapshot / 'build.exit').read_text().strip() != '0' or sha(a.retained_snapshot / 'output/SystemUI.apk') != APK:
            raise ValueError('Local retained build snapshot/APK mismatch')
        a.render_only.mkdir(parents=True, exist_ok=False)
        for key, text in scripts.items(): (a.render_only / key).write_bytes(text.encode())
        (a.render_only / 'proposal.json').write_text(json.dumps(m, indent=2) + '\n')
        print('Local held scripts rendered; no host stage or launch.')
    else:
        if not all([a.root, a.retained_stage, a.candidate_root]): p.error('Preparation requires root/stage/candidate')
        print(json.dumps(stage(a.root, a.retained_stage, a.candidate_root, a.name), indent=2))

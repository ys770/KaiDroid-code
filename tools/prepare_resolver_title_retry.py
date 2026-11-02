"""Prepare one retained-log retry after the exact build02 timestamp no-op failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(root):
    stage = root.resolve(strict=True) / 'tcl-resolver-build02'
    assert (stage / 'build.exit').read_text().strip() == '1'
    assert 'ninja: no work to do.' in (stage / 'build.log').read_text()
    assert sha(stage / 'build.sh') == '1be00329bfd7e62336f1e681be643484a1669716adaca1561dfed8c950389368'
    assert sha(stage / 'staging.json') == '232add6194c05c30c7c388a352bfd559b97ca784a39e2863afbc270053d98064'
    assert not subprocess.check_output(['sudo', 'docker', 'ps', '-q'], text=True).strip()
    for name in ('ninja', 'soong_build', 'soong_ui', 'ckati', 'e2fsdroid'):
        assert subprocess.run(['pgrep', '-x', name], stdout=subprocess.DEVNULL).returncode == 1
    assert sha(stage / 'out/target/product/n139dl/system/framework/framework.jar') == '5126b8f1c15c0ee17a5a6c472fa5bc58bab99cdcb400b286e19f73af949f7054'
    names = ['build-retry02.sh', 'launch-retry02.sh', 'retry02.json',
             'build-retry02.log', 'build-retry02.exit', 'container-id-retry02',
             'outputs-retry02.json', 'output-retry02']
    assert all(not (stage / name).exists() for name in names)
    manifest = json.loads((stage / 'staging.json').read_text())
    for name, digest in manifest['inputs'].items():
        assert sha(stage / 'inputs' / name) == digest
    before = {}
    for name in ('app/ChooserActivity.java', 'app/TclResolverPresentation.java'):
        path = stage / 'inputs' / name
        before[name] = dict(sha256=sha(path), mtime_ns=path.stat().st_mtime_ns)
    script = (stage / 'build.sh').read_text()
    for old, new in [('build.exit', 'build-retry02.exit'), ('build.log', 'build-retry02.log'),
                     ('frontend.log', 'frontend-retry02.log'), ('source-graph.json', 'source-graph-retry02.json'),
                     ('dependency-plan.log', 'dependency-plan-retry02.log'), ('outputs.json', 'outputs-retry02.json')]:
        script = script.replace(old, new)
    assert "out=s/'output';" in script
    script = script.replace("out=s/'output';", "out=s/'output-retry02';")
    (stage / 'build-retry02.sh').write_text(script)
    launcher = (stage / 'launch.sh').read_text()
    for old, new in [('container-id', 'container-id-retry02'), ('build.log', 'build-retry02.log'),
                     ('build.exit', 'build-retry02.exit'), ('/build.sh', '/build-retry02.sh'),
                     ('--name kaidroid-tcl-resolver-build02 ', '--name kaidroid-tcl-resolver-build02-retry02 ')]:
        launcher = launcher.replace(old, new)
    (stage / 'launch-retry02.sh').write_text(launcher)
    # Only private input timestamps change. Original sources, logs and source bytes remain.
    for name, item in before.items():
        path = stage / 'inputs' / name
        os.utime(path, None)
        assert sha(path) == item['sha256']
        assert path.stat().st_mtime_ns > (stage / 'out/target/product/n139dl/system/framework/framework.jar').stat().st_mtime_ns
        item['new_mtime_ns'] = path.stat().st_mtime_ns
    report = dict(reason='Epoch-zero overlay timestamps made Ninja reuse image45 framework',
                  original_attempt_preserved=True, source_bytes_unchanged=True,
                  changed_timestamps=before, launched=False,
                  scripts={n: sha(stage / n) for n in ('build-retry02.sh', 'launch-retry02.sh')})
    (stage / 'retry02.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    prepare(p.parse_args().root)

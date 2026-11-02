"""Compare every framework DEX method, permitting only the reviewed title change."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile
from compare_dexdump_methods import methods

BASE = '5126b8f1c15c0ee17a5a6c472fa5bc58bab99cdcb400b286e19f73af949f7054'
CHOOSER = 'Lcom/android/internal/app/ChooserActivity;'
PRESENTATION = 'Lcom/android/internal/app/TclResolverPresentation;'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(jar, output, dexdump):
    output.mkdir()
    result = {}
    with zipfile.ZipFile(jar) as archive:
        names = [n for n in archive.namelist() if n.startswith('classes') and n.endswith('.dex')]
        assert names and all('/' not in n for n in names)
        for name in names:
            dex = output / name
            dex.write_bytes(archive.read(name))
            dump = output / (name + '.txt.gz')
            with (output / (name + '.stderr')).open('wb') as error, gzip.open(dump, 'wb') as target:
                proc = subprocess.Popen([str(dexdump), '-d', str(dex)], stdout=subprocess.PIPE, stderr=error)
                with proc.stdout:
                    shutil.copyfileobj(proc.stdout, target)
                assert proc.wait() == 0, name
            rows = methods(dump, dex)
            assert not result.keys() & rows.keys()
            result.update(rows)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'dexdump', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--candidate-sha256', required=True)
    a = p.parse_args()
    assert sha(a.baseline) == BASE
    assert sha(a.candidate) == a.candidate_sha256 != BASE
    a.output.mkdir(parents=True, exist_ok=False)
    before = inventory(a.baseline, a.output / 'before', a.dexdump)
    after = inventory(a.candidate, a.output / 'after', a.dexdump)
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
    expected_added = [(PRESENTATION, 'chooserHeading', '(Landroid/content/Intent;Ljava/lang/CharSequence;)Ljava/lang/CharSequence;')]
    expected_changed = [(CHOOSER, 'setupTclResolver', '(Ljava/lang/CharSequence;Ljava/lang/String;)V')]
    passed = added == expected_added and not removed and changed == expected_changed
    routing = ('startSelected', 'onTargetSelected', 'onActivityStarted', 'getReplacementIntent', 'shouldAutoLaunchSingleChoice')
    route_keys = [k for k in before if k[0] == CHOOSER and k[1] in routing]
    assert {k[1] for k in route_keys} == set(routing)
    routing_unchanged = all(k in after and before[k] == after[k] for k in route_keys)
    report = dict(baseline_sha256=BASE, candidate_sha256=a.candidate_sha256,
                  dexdump_sha256=sha(a.dexdump), before_methods=len(before), after_methods=len(after),
                  added=added, removed=removed, changed=changed,
                  protected_routing_unchanged=routing_unchanged,
                  expected_title_delta_only=passed, runtime_verified=False,
                  exclusions=['fields', 'annotations', 'debug metadata'])
    (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    (a.output / 'method-diffs.json').write_text(json.dumps([
        dict(method=k, before=before[k], after=after[k]) for k in changed], indent=2) + '\n')
    print(json.dumps(report))
    assert passed and routing_unchanged, 'Unexpected compiled method delta; preserve evidence and review'


if __name__ == '__main__':
    main()

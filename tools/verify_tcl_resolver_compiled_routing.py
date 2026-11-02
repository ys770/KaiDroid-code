"""Verify preserved chooser routing in existing DEX dumps; never dump or install."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import zipfile

from audit_dex_references import read_dex
from compare_dexdump_methods import methods

OWNER = 'Lcom/android/internal/app/ChooserActivity;'
NAMES = {'startSelected', 'onTargetSelected', 'onActivityStarted',
         'getReplacementIntent', 'shouldAutoLaunchSingleChoice'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(jar, audit, output):
    inventory = []
    result = {}
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            if not name.endswith('.dex'):
                continue
            data = archive.read(name)
            retained = audit/name
            if data != retained.read_bytes():
                raise ValueError('Dump DEX differs from JAR: '+name)
            _, classes, concrete, stale = read_dex(data, definitions_only=True, allow_stale_sha1=True)
            inventory.append(dict(dex=name, sha256=sha(retained), stale_header_sha1=stale,
                                  concrete_methods=len(concrete)))
            if OWNER not in classes:
                continue
            dump = audit/(name+'.txt.gz')
            subset = output/(name+'.chooser.txt.gz')
            with gzip.open(dump, 'rt', encoding='latin1', newline='') as source, \
                    gzip.open(subset, 'wt', encoding='latin1', newline='') as target:
                header = ''
                keep = False
                for line in source:
                    if line.startswith('Class #'):
                        header = line
                        keep = False
                    elif 'Class descriptor' in line:
                        keep = "'"+OWNER+"'" in line
                        if keep:
                            target.write(header)
                    if keep:
                        target.write(line)
            rows = methods(subset, retained)
            if not rows or any(k[0] != OWNER for k in rows):
                raise ValueError('Invalid chooser subset')
            if result.keys() & rows.keys():
                raise ValueError('Duplicate chooser definition')
            result.update(rows)
    return result, inventory


def verify(before_jar, before_audit, after_jar, after_audit, output):
    output.mkdir(parents=True, exist_ok=False)
    (output/'before').mkdir()
    (output/'after').mkdir()
    before, old_inventory = extract(before_jar, before_audit, output/'before')
    after, new_inventory = extract(after_jar, after_audit, output/'after')
    keys = sorted(k for k in before if k[1] in NAMES)
    if len(keys) != 5 or {k[1] for k in keys} != NAMES:
        raise ValueError('Expected five concrete native routing methods')
    for key in keys:
        if key not in after or before[key] != after[key]:
            raise ValueError('Native routing changed: '+repr(key))
    hook = (OWNER, 'selectTclTarget', '(Ljava/lang/String;)V')
    instructions = after[hook]['instructions']
    calls = [i for i in instructions if isinstance(i, str) and i.startswith('invoke-')]
    native = [i for i in calls if OWNER+'.startSelected:(IZZ)V' in i]
    if len(native) != 1 or any('.startActivity' in i for i in calls):
        raise ValueError('Hook must call native startSelected once, without direct launch')
    report = dict(before_jar_sha256=sha(before_jar), after_jar_sha256=sha(after_jar),
                  before_dex=old_inventory, after_dex=new_inventory,
                  unchanged_native_methods=keys, hook_native_call=native,
                  scope='Normalized decoded instruction/frame/catch equality; debug metadata, annotations and fields excluded. Existing same-tool dumps reused; no new dump or device action.',
                  runtime_uri_or_caller_verified=False)
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(unchanged_native_methods=len(keys), native_hook_calls=len(native), runtime_verified=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('before-jar', 'before-audit', 'after-jar', 'after-audit', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    verify(args.before_jar, args.before_audit, args.after_jar, args.after_audit, args.output)

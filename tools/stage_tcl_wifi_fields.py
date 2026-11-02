"""Stage pinned Wi-Fi field candidate in a coordinated idle build tree.

Preserves source/output backups and all pre-existing unrelated framework edits.
Does not compile or operate a device. Requires prepare_tcl_wifi_fields.py nearby.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from prepare_tcl_wifi_fields import SOURCE, prepare
HASHES = {"WifiEnterpriseConfig.java": SOURCE}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('aosp', 'out', 'stage'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    base = a.aosp / 'frameworks/base'
    paths = {'WifiEnterpriseConfig.java': Path('wifi/java/android/net/wifi/WifiEnterpriseConfig.java')}
    originals = {name: (base / paths[name]).read_bytes() for name in HASHES}
    candidates = {name: prepare(data) for name, data in originals.items()}
    policy = base / 'config/hiddenapi-greylist.txt'
    policy_data = policy.read_bytes()
    additions = []
    for name in ('SimSlot', 'IsPresetAp'):
        additions += ['Landroid/net/wifi/WifiEnterpriseConfig;->get' + name + '(Ljava/lang/String;)Ljava/lang/String;',
                      'Landroid/net/wifi/WifiEnterpriseConfig;->set' + name + '(Ljava/lang/String;Ljava/lang/String;)V']
    if any(line in policy_data.decode().splitlines() for line in additions):
        raise ValueError('Wi-Fi field policy already staged')
    changed = set()
    for args in [('diff', '--name-only', '-z', 'HEAD'),
                 ('ls-files', '--others', '--exclude-standard', '-z')]:
        changed.update(n.decode() for n in subprocess.run(
            ['git', '-C', str(base), *args], check=True, capture_output=True).stdout.split(b'\0') if n)
    before = {name: sha(base / name) for name in changed}
    a.stage.mkdir(parents=True)
    for name, data in originals.items():
        (a.stage / (name + '.original')).write_bytes(data)
    (a.stage / 'hiddenapi-greylist.original.txt').write_bytes(policy_data)
    jar = a.out / 'soong/.intermediates/frameworks/base/wifi/framework-wifi/android_common_com.android.wifi/dex/framework-wifi.jar'
    shutil.copy2(jar, a.stage / 'framework-wifi.original.jar')
    report = dict(before_framework_edits_sha256=before, original_framework_sha256=sha(jar),
                  source_sha256=HASHES, candidate_sha256={n: hashlib.sha256(d).hexdigest() for n,d in candidates.items()},
                  hiddenapi_additions=additions, compiled=False, installed=False)
    (a.stage / 'prestage.json').write_text(json.dumps(report, indent=2) + '\n')
    for name, data in candidates.items():
        (base / paths[name]).write_bytes(data)
    policy.write_bytes(policy_data.rstrip(b'\n') + b'\n' + ('\n'.join(additions) + '\n').encode())
    owned = {'config/hiddenapi-greylist.txt'} | {p.as_posix() for p in paths.values()}
    for name, digest in before.items():
        if name not in owned and sha(base / name) != digest:
            raise ValueError('Unrelated source changed during staging: ' + name)
    report.update(unrelated_framework_edits_preserved=True, staged_policy_sha256=sha(policy))
    (a.stage / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

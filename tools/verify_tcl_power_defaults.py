"""Inspect built SettingsProvider resources, DEX and signer against its saved baseline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--directory', required=True, type=Path)
p.add_argument('--build-tools', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
blocks, dex, signers, hashes = {}, {}, {}, {}
for name, filename in [('before', 'SettingsProvider.before.apk'), ('candidate', 'SettingsProvider.apk')]:
    apk = a.directory / filename
    hashes[name] = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert hashes[name] in (a.directory / 'apks.sha256').read_text()
    result = subprocess.run([str(a.build_tools / 'aapt2.exe'), 'dump', 'resources', str(apk)],
                            capture_output=True, check=True, timeout=30)
    (a.directory / (name + '-resources.txt')).write_bytes(result.stdout)
    records, current = {}, None
    for line in result.stdout.decode().splitlines():
        match = re.match(r'\s*resource (0x[0-9a-f]+) (\S+)', line)
        if match:
            current = match[2]
            records[current] = [match[1]]
        elif current and line.startswith('      '):
            records[current].append(line.strip())
    blocks[name] = records
    with zipfile.ZipFile(apk) as archive:
        dex[name] = {entry: hashlib.sha256(archive.read(entry)).hexdigest()
                     for entry in archive.namelist() if re.fullmatch(r'classes\d*\.dex', entry)}
    result = subprocess.run([str(a.build_tools / 'apksigner.bat'), 'verify', '--print-certs', str(apk)],
                            capture_output=True, check=True, timeout=30)
    (a.directory / (name + '-signer.txt')).write_bytes(result.stdout)
    signers[name] = re.findall(r'certificate SHA-256 digest: ([0-9a-f]+)', result.stdout.decode())
assert blocks['before'].keys() == blocks['candidate'].keys()
changed = sorted(key for key in blocks['before'] if blocks['before'][key] != blocks['candidate'][key])
expected = ['bool/def_lockscreen_disabled', 'integer/def_end_button_behavior', 'integer/def_screen_off_timeout']
assert changed == expected, changed
assert blocks['candidate'][expected[0]][1:] == ['() true']
assert blocks['candidate'][expected[1]][1:] == ['() 1']
assert blocks['candidate'][expected[2]][1:] == ['() 30000']
assert dex['before'] and dex['before'] == dex['candidate']
assert signers['before'] and signers['before'] == signers['candidate']
report = dict(apk_sha256=hashes, changed_resources={key: {
    'before': blocks['before'][key], 'candidate': blocks['candidate'][key]} for key in changed},
    unchanged_resource_count=len(blocks['before']) - len(changed), dex_identical=True,
    dex_sha256=dex['candidate'], signer_sha256=signers['candidate'], installed=False,
    scope='Built initial-default resources only. Existing settings/LockSettings users are not migrated.')
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))

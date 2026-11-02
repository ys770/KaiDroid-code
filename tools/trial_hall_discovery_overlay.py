"""Image30-only temporary hinge binary overlay, with original hash restoration."""
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

root = Path(__file__).resolve().parents[1]
adb = '/opt/kaidroid/source/Documents/platform-tools/adb.exe'
base = [adb, '-s', 'DEVICE_SERIAL_REQUIRED']
boot = '00000000-0000-0000-0000-000000000005'
candidate = root / 'work/hall-discovery-directory01/hall-bridge'
expected = '69d2a26bba49dfa748b4e9d8005be078eab5f845079345d22b36f90923ef57d1'
original = 'bd43ad632d8a938c21e5c648986c29d2be5b21006d2ad6ddee251e95877f3fa5'
target = '/system/bin/kaidroid-hall'
out = root / 'artifacts/runtime/image30-hall-discovery-overlay01'
assert hashlib.sha256(candidate.read_bytes()).hexdigest() == expected
out.mkdir(exist_ok=False)

def sh(name, cmd):
    r = subprocess.run(base + ['shell', cmd], capture_output=True, timeout=30)
    (out / (name + '.txt')).write_bytes(r.stdout + r.stderr)
    r.check_returncode()
    return r.stdout.decode(errors='replace').strip()

def guard(name):
    assert sh(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; getenforce').splitlines() == ['30', boot, 'Enforcing']

guard('before')
assert sh('state', 'getprop init.svc.kaidroid-hall') == 'stopped'
assert sh('original-hash', 'sha256sum ' + target).split()[0] == original
remote = '/data/local/tmp/kaidroid-hall-discovery-' + uuid.uuid4().hex
r = subprocess.run(base + ['push', str(candidate), remote], capture_output=True, check=True, timeout=30)
(out / 'push.txt').write_bytes(r.stdout + r.stderr)
sh('prepare', 'chmod 0755 ' + remote + ' && chcon u:object_r:kaidroid_hall_exec:s0 ' + remote)
assert sh('candidate-hash', 'sha256sum ' + remote).split()[0] == expected
mounted = False
result = {'candidate_sha256': expected, 'original_sha256': original, 'persistent_change': False}
try:
    mounted = True
    sh('mount', 'mount --bind ' + remote + ' ' + target)
    assert sh('overlay-hash', 'sha256sum ' + target).split()[0] == expected
    q = subprocess.run([sys.executable, str(root/'tools/trial_hall_init_service.py'),
        '--adb', adb, '--boot-id', boot, '--output', str(out/'service')], capture_output=True, timeout=90)
    (out/'trial.txt').write_bytes(q.stdout+q.stderr)
    result['trial_exit'] = q.returncode
    q.check_returncode()
finally:
    try:
        guard('cleanup-identity')
        sh('stop', 'stop kaidroid-hall')
        if mounted:
            sh('unmount', 'umount ' + target)
        result['original_restored'] = sh('restored-hash', 'sha256sum '+target).split()[0] == original
        assert result['original_restored']
    finally:
        (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))

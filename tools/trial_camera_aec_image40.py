"""Bounded image40 TCL preview trial with temporary AEC overlay and restoration.

No shutter, video action, vendor byte overwrite, or picture-buffer patch.
Raw preview images stay in ignored artifacts for review before publication.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

ADB = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
BOOT = '00000000-0000-0000-0000-000000000008'
TARGET = '/vendor/lib/libmmcamera2_stats_modules.so'
SERVICE = 'vendor.camera-provider-2-4'
ORIGINAL = '6e28e04df7b0af0bbef3f226e92c62064be21b072d2c584cb95c1654d5634847'
CANDIDATE = '41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0'
PERMISSIONS = ['CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE']


def main():
    out = Path('artifacts/runtime/image40-camera-aec-preview01')
    candidate = Path('work/camera-trial-bundle01/libmmcamera2_stats_modules.so')
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == CANDIDATE
    out.mkdir(parents=True, exist_ok=False)
    def run(name, args):
        r = subprocess.run(ADB + args, capture_output=True, timeout=30)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout
    def sh(name, command):
        return run(name, ['shell', command]).decode(errors='replace').replace('\r', '').strip()
    def guard(name):
        assert sh(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; getenforce; id -u').splitlines() == ['40', BOOT, 'Enforcing', '0']
    def service(action, label):
        sh(label, action + ' ' + SERVICE)
        desired = 'stopped' if action == 'stop' else 'running'
        for n in range(12):
            if sh(label + '-state-' + str(n), 'getprop init.svc.' + SERVICE) == desired:
                return
            time.sleep(1)
        raise RuntimeError('Provider transition not observed: ' + desired)
    guard('identity')
    assert sh('original', 'sha256sum ' + TARGET).split()[0] == ORIGINAL
    mounts = sh('mounts-before', 'cat /proc/mounts')
    assert all(line.split()[1] != TARGET for line in mounts.splitlines())
    ns = sh('namespace', 'readlink /proc/1/ns/mnt; readlink /proc/self/ns/mnt').splitlines()
    assert len(ns) == 2 and ns[0] == ns[1]
    pkg = sh('package', 'dumpsys package com.tcl.camera')
    assert 'userId=10104' in pkg
    for permission in PERMISSIONS:
        assert re.search(r'android.permission.' + permission + r': granted=false', pkg)
    path = sh('apk-path', 'pm path com.tcl.camera')
    assert path.startswith('package:') and '\n' not in path
    assert sh('apk-hash', 'sha256sum ' + path[8:]).split()[0] == 'f8ea9baef449c8e658ac61e4af9b2167040045f339708275b1e34e4735af121e'
    remote = '/data/local/tmp/kaidroid-aec40-' + uuid.uuid4().hex
    run('push', ['push', str(candidate), remote])
    sh('label', 'chmod 0644 ' + remote + ' && chcon u:object_r:vendor_file:s0 ' + remote)
    assert sh('staged-hash', 'sha256sum ' + remote).split()[0] == CANDIDATE
    report = dict(candidate=CANDIDATE, original=ORIGINAL, image=40, photo_taken=False)
    try:
        sh('force-stop-before', 'am force-stop com.tcl.camera')
        service('stop', 'stop-before-overlay')
        sh('bind', 'mount --bind ' + remote + ' ' + TARGET)
        assert sh('bound-hash', 'sha256sum ' + TARGET).split()[0] == CANDIDATE
        service('start', 'start-overlay')
        for permission in PERMISSIONS:
            sh('grant-' + permission, 'pm grant com.tcl.camera android.permission.' + permission)
        for n in range(2):
            print('Preview cycle', n + 1, flush=True)
            sh('launch-' + str(n), 'am start -W -n com.tcl.camera/.CameraActivity')
            time.sleep(10)
            pid = sh('provider-pid-' + str(n), 'pidof android.hardware.camera.provider@2.4-service')
            assert pid.isdigit()
            sh('provider-maps-' + str(n), 'cat /proc/' + pid + '/maps')
            assert sh('provider-root-hash-' + str(n), 'sha256sum /proc/' + pid + '/root' + TARGET).split()[0] == CANDIDATE
            (out / ('preview-' + str(n) + '.png')).write_bytes(run('screen-' + str(n), ['exec-out', 'screencap', '-p']))
            sh('camera-' + str(n), 'dumpsys media.camera')
            sh('logcat-' + str(n), 'logcat -d -t 1500')
            sh('force-stop-' + str(n), 'am force-stop com.tcl.camera')
        report['cycles_observed'] = 2
    except Exception as exc:
        report['error'] = repr(exc)
        raise
    finally:
        try:
            guard('cleanup-identity')
            sh('force-stop-final', 'am force-stop com.tcl.camera')
            service('stop', 'stop-cleanup')
            # Inspect actual mount state even if the earlier mount call timed out.
            current = sh('mounts-cleanup', 'cat /proc/mounts')
            if any(line.split()[1] == TARGET for line in current.splitlines()):
                sh('unmount', 'umount ' + TARGET)
            assert sh('restored-hash', 'sha256sum ' + TARGET).split()[0] == ORIGINAL
            report['original_restored'] = True
            service('start', 'start-original')
            for permission in PERMISSIONS:
                sh('revoke-' + permission, 'pm revoke com.tcl.camera android.permission.' + permission)
            sh('final-camera', 'dumpsys media.camera')
            report['cleanup_complete'] = True
        finally:
            (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

"""Bounded image42/43/44 TCL fixed-buffer preview trial with temporary AEC overlay and restoration.

One bounded video start/stop; no vendor byte overwrite or picture-buffer patch.
Raw preview images stay in ignored artifacts for review before publication.
"""
import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import uuid
from camera_stream_state import require_mode, active_mode

ADB = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
TARGET = '/vendor/lib/libmmcamera2_stats_modules.so'
SERVICE = 'vendor.camera-provider-2-4'
ORIGINAL = '6e28e04df7b0af0bbef3f226e92c62064be21b072d2c584cb95c1654d5634847'
CANDIDATE = '41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0'
PERMISSIONS = ['CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate', choices=('buffer', 'fixed30', 'startup-trace'), default='buffer')
    parser.add_argument('--boot-id', type=uuid.UUID, required=True)
    parser.add_argument('--image', choices=('42', '43', '44'), default='42')
    parser.add_argument('--system-trace', action='store_true', help='Capture a bounded 20-second local Perfetto trace')
    args = parser.parse_args()
    out = args.output
    apk_hash = {'buffer': 'cbc8276c752d46f157cdec987596c1a0c3e2c5e3f8f261f7811fd219e83c85e3',
                'startup-trace': '8bfdf03bd0b9730ee5abec630a326f633c52184da4964c9c9713ce39201ec8dd',
                'fixed30': '1ae46bf64f93903c4cefd54d0198e754b914c3d048468e22c1970cfbb96c1b94'}[args.candidate]
    candidate = Path('work/camera-trial-bundle01/libmmcamera2_stats_modules.so')
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == CANDIDATE
    out.mkdir(parents=True, exist_ok=False)
    def run(name, args):
        r = subprocess.run(ADB + args, capture_output=True,
                           timeout=45 if name.endswith('-dump') else 30)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout
    def sh(name, command):
        return run(name, ['shell', command]).decode(errors='replace').replace('\r', '').strip()
    def guard(name):
        assert sh(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; getenforce; id -u').splitlines() == [args.image, str(args.boot_id), 'Enforcing', '0']
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
    assert sh('apk-hash', 'sha256sum ' + path[8:]).split()[0] == apk_hash
    remote = '/data/local/tmp/kaidroid-aec42-' + uuid.uuid4().hex
    run('push', ['push', str(candidate), remote])
    sh('label', 'chmod 0644 ' + remote + ' && chcon u:object_r:vendor_file:s0 ' + remote)
    assert sh('staged-hash', 'sha256sum ' + remote).split()[0] == CANDIDATE
    report = dict(boot_id=str(args.boot_id), candidate=CANDIDATE, original=ORIGINAL, image=int(args.image), photo_taken=False, camera_apk=apk_hash, mode_guard='active camera streams')
    trace_remote = None
    trace_deadline = None
    try:
        sh('force-stop-before', 'am force-stop com.tcl.camera')
        service('stop', 'stop-before-overlay')
        sh('bind', 'mount --bind ' + remote + ' ' + TARGET)
        assert sh('bound-hash', 'sha256sum ' + TARGET).split()[0] == CANDIDATE
        service('start', 'start-overlay')
        for permission in PERMISSIONS:
            sh('grant-' + permission, 'pm grant com.tcl.camera android.permission.' + permission)
        sh('files-before', 'find /data/media/0/DCIM -type f')
        for n in range(1):
            print('Preview cycle', n + 1, flush=True)
            sh('launch-' + str(n), 'am start -W -n com.tcl.camera/.CameraActivity')
            for ready in range(10):
                state = sh('ready-' + str(ready), 'dumpsys media.camera')
                if any('SurfaceView - com.tcl.camera' in part and
                       re.search(r'Frames produced: [1-9][0-9]*', part.split('Camera3 Buffer Manager:')[0])
                       for part in state.split('Stream[')):
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Camera preview did not produce frames before UI inspection')
            focus = sh('mode-window', 'dumpsys window')
            assert any('mCurrentFocus=' in line and 'com.tcl.camera/com.tcl.camera.CameraActivity' in line for line in focus.splitlines())
            initial_mode = active_mode(sh('initial-module-state', 'dumpsys media.camera'))
            report['initial_camera_module'] = initial_mode
            # Retained app data may reopen Video. Never toggle it blindly back to Photo.
            if initial_mode == 'photo':
                guard('mode-identity')
                sh('mode-down', 'input keyevent 20')
            for ready in range(12):
                video_state = sh('video-ready-' + str(ready), 'dumpsys media.camera')
                try:
                    require_mode(video_state, 'video')
                    (out / 'video-state.stdout').write_text(video_state, encoding='utf-8')
                    break
                except ValueError:
                    if ready == 11:
                        raise
                    time.sleep(2)
            pid = sh('provider-pid-' + str(n), 'pidof android.hardware.camera.provider@2.4-service')
            assert pid.isdigit()
            sh('provider-maps-' + str(n), 'cat /proc/' + pid + '/maps')
            assert sh('provider-root-hash-' + str(n), 'sha256sum /proc/' + pid + '/root' + TARGET).split()[0] == CANDIDATE
            (out / ('preview-' + str(n) + '.png')).write_bytes(run('screen-' + str(n), ['exec-out', 'screencap', '-p']))
            sh('camera-' + str(n), 'dumpsys media.camera')
            sh('logcat-' + str(n), 'logcat -d -t 1500')
            guard('record-identity')
            focus = sh('record-focus', 'dumpsys window')
            assert any('mCurrentFocus=' in line and 'com.tcl.camera/com.tcl.camera.CameraActivity' in line for line in focus.splitlines())
            report['record_start_requested'] = True
            (out / 'result.json').write_text(json.dumps(report, indent=2))
            if args.system_trace:
                query = sh('perfetto-before', 'perfetto --query')
                if not re.search(r'^num_sessions: 0$', query, re.MULTILINE):
                    raise RuntimeError('An existing Perfetto session prevents this isolated trace')
                trace_remote = '/data/misc/perfetto-traces/kaidroid-camera-' + uuid.uuid4().hex + '.pftrace'
                trace_deadline = time.monotonic() + 23
                config = '''buffers { size_kb: 2048 fill_policy: RING_BUFFER }
duration_ms: 20000
write_into_file: true
file_write_period_ms: 250
flush_period_ms: 1000
max_file_size_bytes: 33554432
data_sources { config { name: "linux.ftrace" ftrace_config {
ftrace_events: "sched/sched_switch"
ftrace_events: "sched/sched_wakeup"
ftrace_events: "sched/sched_blocked_reason"
ftrace_events: "vmscan/mm_vmscan_direct_reclaim_begin"
ftrace_events: "vmscan/mm_vmscan_direct_reclaim_end"
ftrace_events: "block/block_rq_issue"
ftrace_events: "block/block_rq_complete"
atrace_categories: "audio"
atrace_categories: "camera"
atrace_categories: "binder_driver"
} } }
data_sources { config { name: "linux.process_stats" process_stats_config { scan_all_processes_on_start: true } } }
'''
                (out / 'perfetto-config.pbtxt').write_text(config)
                # Fixed configuration has no shell quotes. Periodic file draining
                # preserves startup without allocating a large RAM ring buffer.
                assert "'" not in config
                sh('perfetto-start', "printf '%s' '" + config +
                   "' | perfetto --background --txt -c - -o " + trace_remote)
                report['system_trace'] = dict(remote=trace_remote, duration_seconds=20,
                                             buffer_mb=2, file_cap_mb=32, drain_period_ms=250)
            sh('record-start', 'input keyevent 23')
            time.sleep(5)
            recording = sh('record-camera', 'dumpsys media.camera')
            sh('record-log', 'logcat -d -t 1500')
            (out / 'recording.png').write_bytes(run('record-screen', ['exec-out', 'screencap', '-p']))
            # Only toggle stop when the encoder stream actually received frames.
            require_mode(recording, 'video', recording=True)
            guard('stop-record-identity')
            focus = sh('stop-record-focus', 'dumpsys window')
            assert any('mCurrentFocus=' in line and 'com.tcl.camera/com.tcl.camera.CameraActivity' in line for line in focus.splitlines())
            sh('record-stop', 'input keyevent 23')
            report['record_stop_requested'] = True
            time.sleep(5)
            sh('files-after', 'find /data/media/0/DCIM -type f')
            sh('record-final-log', 'logcat -d -t 2000')
            if args.candidate == 'startup-trace':
                sh('record-monotonic-log', 'logcat -d -v monotonic -t 2000')
            sh('force-stop-' + str(n), 'am force-stop com.tcl.camera')
        report['cycles_observed'] = 1
        report['video_recorded'] = None  # Independently decode the saved file before claiming success.
    except Exception as exc:
        report['error'] = repr(exc)
        raise
    finally:
        try:
            guard('cleanup-identity')
            try:
                sh('force-stop-final', 'am force-stop com.tcl.camera')
            except subprocess.TimeoutExpired:
                report['cleanup_force_stop_timed_out'] = True
                # ActivityManager may block after the client has already exited.
                # Do not let that alone prevent restoring the vendor overlay.
                remaining = sh('cleanup-camera-process',
                               'pidof com.tcl.camera; rc=$?; test "$rc" -le 1')
                if remaining:
                    raise RuntimeError('Camera client still present; inspect before provider cleanup')
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
            if trace_remote is not None:
                # The daemon owns a finite session even if recording fails. Never stop
                # another session or clear global trace buffers during cleanup.
                time.sleep(max(0, trace_deadline - time.monotonic()))
                run('perfetto-pull', ['pull', trace_remote, str(out / 'startup.pftrace')])
                report['system_trace_sha256'] = hashlib.sha256((out / 'startup.pftrace').read_bytes()).hexdigest()
                sh('perfetto-after', 'perfetto --query')
        finally:
            (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

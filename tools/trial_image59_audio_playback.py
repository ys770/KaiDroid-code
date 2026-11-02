"""One bounded speaker-path regression; requires the exclusive Nokia lease."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import uuid

APK = '6f4c1fcd841c8bcd5abf8ddbedece7a2a06448d29b8fe52c91e9804a2528db94'
FRAMEWORK = '04eeb83ba7b062a6da7610d20829fc088f9cdf89d9474540e74b65da9f4e28bf'
IDENTITY = ('getprop ro.serialno; getprop ro.kaidroid.image; '
            'cat /proc/sys/kernel/random/boot_id; getprop sys.boot_completed; '
            'id -u; pidof system_server; pidof com.android.systemui; getenforce')


def music_configuration(text):
    matches = re.findall(r'^- STREAM_MUSIC:\n(.*?)(?=^- |\Z)', text, re.M | re.S)
    if len(matches) != 1:
        raise ValueError('Expected exactly one music stream configuration')
    return matches[0].strip()


def playback_result(text):
    values = {}
    for line in text.splitlines():
        if line.startswith('INSTRUMENTATION_RESULT: '):
            key, value = line.removeprefix('INSTRUMENTATION_RESULT: ').split('=', 1)
            if key in values:
                raise ValueError('Duplicate instrumentation field: ' + key)
            values[key] = value
    expected = dict(result='PASS', playback_frames='12000', samples_written='24000',
                    underruns='0', routed_device_type='2', music_muted='false')
    if any(values.get(k) != v for k, v in expected.items()):
        raise ValueError('Incomplete playback or unexpected speaker route/mute state')
    if re.findall(r'^INSTRUMENTATION_CODE: (-?\d+)$', text, re.M) != ['-1']:
        raise ValueError('Instrumentation did not finish successfully')
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot', required=True, type=lambda s: str(uuid.UUID(s)))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--adb', default='/opt/kaidroid/source/Documents/platform-tools/adb.exe')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(image=59, boot=args.boot, passed=False, instrumentation_attempted=False,
                  physical_audibility_verified=False, probe_apk_sha256=APK)

    def run(name, command, timeout=30):
        try:
            result = subprocess.run([args.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell', command],
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (args.output / (name + '.stdout')).write_bytes(error.stdout or b'')
            (args.output / (name + '.stderr')).write_bytes(error.stderr or b'')
            report['ambiguous_timeout'] = name
            raise
        (args.output / (name + '.stdout')).write_bytes(result.stdout)
        (args.output / (name + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout.decode().replace('\r\n', '\n')

    def focus(text):
        rows = [line.strip() for line in text.splitlines() if 'mCurrentFocus=' in line]
        if len(rows) != 1 or 'com.android.launcher3/' not in rows[0]:
            raise ValueError('Expected original Launcher focus')
        return rows

    try:
        before = run('identity-before', IDENTITY)
        rows = before.splitlines()
        if (len(rows) != 8 or rows[:5] != ['DEVICE_SERIAL_REQUIRED', '59', args.boot, '1', '0']
                or rows[-1] != 'Enforcing'
                or not all(re.fullmatch('[1-9][0-9]*', value) for value in rows[5:7])):
            raise ValueError('Handset/build/boot/process identity mismatch')
        if run('framework', 'sha256sum /system/framework/framework.jar').split()[0] != FRAMEWORK:
            raise ValueError('Unexpected framework')
        paths = run('package-path', 'pm path org.kaidroid.inputprobe').splitlines()
        if len(paths) != 1 or not paths[0].startswith('package:/data/app/'):
            raise ValueError('Unexpected probe installation')
        if run('apk', 'sha256sum ' + shlex.quote(paths[0][8:])).split()[0] != APK:
            raise ValueError('Probe APK differs from reviewed audio implementation')
        if run('probe-idle', 'pidof org.kaidroid.inputprobe; true').strip():
            raise ValueError('Probe already active')
        audio = run('audio-before', 'dumpsys audio')
        if 'In ring or call: false' not in audio:
            raise ValueError('Call state not idle')
        music = music_configuration(audio)
        original_focus = focus(run('window-before', 'dumpsys window'))
        run('flinger-before', 'dumpsys media.audio_flinger')
        report['instrumentation_attempted'] = True
        result = run('playback', 'am instrument -w org.kaidroid.inputprobe/.AudioPlaybackInstrumentation')
        report['results'] = playback_result(result)
        run('flinger-after', 'dumpsys media.audio_flinger')
        if music_configuration(run('audio-after', 'dumpsys audio')) != music:
            raise ValueError('Music stream configuration changed')
        if run('identity-after', IDENTITY) != before:
            raise ValueError('Boot or core processes changed')
        if focus(run('window-after', 'dumpsys window')) != original_focus:
            raise ValueError('Original Launcher window changed')
        report.update(passed=True, music_stream_configuration_unchanged=True,
                      same_boot_and_core=True, foreground_restored=True)
    except Exception as error:
        report['failure'] = str(error)
    finally:
        report['captures'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in args.output.iterdir() if p.is_file()}
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

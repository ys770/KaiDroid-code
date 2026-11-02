"""Serial/boot-bound new FileManager trial; default read-only, no file operations."""
import argparse
import json
import re
import subprocess
import uuid
from pathlib import Path
from deliver_stock_apps36 import digest, installed_paths, metadata
from trial_clock_parallel38 import FRAMEWORK_SHA, packages, uid
from trial_messaging38 import provider_owners
from verify_tcl_app_build import PLATFORM_CERT

PACKAGE = 'com.jrdcom.filemanager'
AUTHORITY = PACKAGE + '.bb.fileProvider'
SHA = 'bedd4cffc5d4d57321150bdf19d699089d4c1020bce625567d1e511fcb57176a'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('adb', 'java', 'build-tools', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    assert str(uuid.UUID(args.boot)) == args.boot
    args.output.mkdir(parents=True, exist_ok=False)
    candidate = Path(__file__).resolve().parents[1] / 'work/tcl-stock-app-build02/KaiDroidTclFileManager.apk'
    adb = [str(args.adb), '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(installed=False, launched=False, runtime_verified=False, boot=args.boot)

    def run(label, command):
        try:
            result = subprocess.run(list(map(str, command)), capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as error:
            report['unknown_command_outcome'] = label
            (args.output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (args.output / (label + '.stderr')).write_bytes(error.stderr or b'')
            raise
        (args.output / (label + '.stdout')).write_bytes(result.stdout)
        (args.output / (label + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    def shell(label, command):
        return run(label, adb + ['shell', command]).decode().strip()

    def guard(label):
        for key, command, expected in [('boot', 'cat /proc/sys/kernel/random/boot_id', args.boot),
                ('image', 'getprop ro.kaidroid.image', '38'), ('root', 'id -u', '0'),
                ('user', 'am get-current-user', '0'), ('selinux', 'getenforce', 'Enforcing')]:
            assert shell(label + '-' + key, command) == expected, key
        assert shell(label + '-framework', 'sha256sum /system/framework/framework.jar').split()[0] == FRAMEWORK_SHA

    try:
        assert digest(candidate) == SHA
        assert metadata(run('badging', [args.build_tools/'aapt.exe', 'dump', 'badging', candidate]).decode(), PACKAGE) == 516083001
        sig = run('signer', [args.java, '-jar', args.build_tools/'lib/apksigner.jar', 'verify', '--print-certs', candidate]).decode()
        assert re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', sig) == [PLATFORM_CERT]
        manifest = run('manifest', [args.build_tools/'aapt.exe', 'dump', 'xmltree', candidate, 'AndroidManifest.xml']).decode()
        assert 'android:sharedUserId' not in manifest
        assert re.findall(r'android:authorities[^\n]*="([^"]+)"', manifest) == [AUTHORITY]
        guard('before')
        inventory = packages(shell('packages-before', 'pm list packages -u --user 0'))
        assert PACKAGE not in inventory
        assert AUTHORITY not in provider_owners(shell('providers-before', 'dumpsys package providers'))
        report['preflight_passed'] = True
        if not args.install:
            return
        result = run('install', adb + ['install', '--user', '0', candidate]).decode().strip()
        assert result == 'Success' or result.endswith('\nSuccess')
        report['installed'] = True
        guard('after')
        after = packages(shell('packages-after', 'pm list packages -u --user 0'))
        assert after - inventory == {PACKAGE} and not inventory - after
        paths = installed_paths(shell('path', 'pm path ' + PACKAGE))
        assert len(paths) == 1
        assert shell('installed-hash', 'sha256sum ' + paths[0]).split()[0] == SHA
        assert uid(shell('package-after', 'dumpsys package ' + PACKAGE)) >= 10000
        assert provider_owners(shell('providers-after', 'dumpsys package providers')).get(AUTHORITY) == PACKAGE
        report['installed_identity_verified'] = True
        launch = shell('launch', 'am start -W -n ' + PACKAGE + '/.activity.FileBrowserActivity')
        report['launched'] = True
        run('screen', adb + ['exec-out', 'screencap', '-p'])
        shell('window', 'dumpsys window')
        shell('crash', 'logcat -b crash -d -t 80')
        assert re.search(r'^Status: ok\s*$', launch, re.M)
        report['screen_requires_review'] = True
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()

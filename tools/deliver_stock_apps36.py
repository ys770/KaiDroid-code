"""Hardware-owned four-app delivery. Default is read-only preflight.

Preserves existing APKs and private app data before installation. Never clears,
uninstalls, downgrades, grants permissions or retries timed-out commands.
"""
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from verify_tcl_app_build import PLATFORM_CERT

BOOT = '00000000-0000-0000-0000-000000000014'
EXISTING_CERT = 'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'
MATCHED_APPS = {'FPCalendar', 'JrdGallery'}
APPS = (
    ('FPCalendar', 'com.android.calendar', '.AllInOneActivity', '971e5f9d32ab5b4f8e616a6c5d44073d66a000631cd47c353abf5ca4bc540b0d'),
    ('Calculator', 'com.android.calculator2', '.Calculator', '88b33864b35de46509dc3efdd47b8ca315db8c8f1667ab64ec55f07b6b695e53'),
    ('Note', 'com.android.note', '.NotesListActivity', '7cfbef1984a10e82f6cd145c04b1d436b34678d64a77ae85029aad770df5f12d'),
    ('JrdGallery', 'com.android.gallery3d', '.app.GalleryActivity', '8ecbf5937c7a3576ca978f49517a367f7b161c68243e15ebeda64858b638f030'),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(badging, package):
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)'", badging, re.M)
    if not match or match[1] != package:
        raise ValueError('APK package identity mismatch')
    return int(match[2])


def installed_paths(text):
    rows = text.splitlines()
    if not rows:
        return []
    if any(not re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk', row) for row in rows):
        raise ValueError('Unexpected package path output')
    return [row[8:] for row in rows]


def require_upgrade(candidate_version, original_version, candidate_cert, original_cert, expected_cert=PLATFORM_CERT):
    if candidate_cert != expected_cert or original_cert != candidate_cert:
        raise ValueError('Signing identity mismatch; no uninstall fallback')
    if candidate_version < original_version:
        raise ValueError('Would require downgrade; retain existing app and data')


def candidate_path(project, name):
    folder = 'tcl-stock-matched-signing01' if name in MATCHED_APPS else 'tcl-stock-app-build02'
    return project / 'work' / folder / ('KaiDroidTcl' + name + '.apk')


def require_launch_success(output):
    if re.search(r'^Error(?:\b|:)', output, re.M) or not re.search(r'^Status:\s*ok\s*$', output, re.M):
        raise ValueError('Activity launch did not report Status: ok')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('adb', 'java', 'build-tools', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--install', action='store_true')
    a = p.parse_args()
    project = Path(__file__).resolve().parents[1]
    if a.output.exists():
        raise FileExistsError(a.output)
    a.output.mkdir(parents=True)
    base = [str(a.adb), '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(image='36', boot=BOOT, install_requested=a.install,
                  apps=[], installed=[], runtime_verified=False, physical_parity=False)

    def run(label, command, timeout=120):
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (a.output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (a.output / (label + '.stderr')).write_bytes(error.stderr or b'')
            report['timed_out_command'] = label
            raise
        (a.output / (label + '.stdout')).write_bytes(result.stdout)
        (a.output / (label + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    def shell(label, command):
        return run(label, base + ['shell', command]).decode().strip()

    def guard(label):
        for key, command, expected in (
            ('image', 'getprop ro.kaidroid.image', '36'),
            ('boot', 'cat /proc/sys/kernel/random/boot_id', BOOT),
            ('root', 'id -u', '0'), ('selinux', 'getenforce', 'Enforcing')):
            if shell(label + '-' + key, command) != expected:
                raise ValueError('Device binding failed: ' + key)
        density = re.findall(r'(?:Physical|Override) density: (\d+)', shell(label + '-density', 'wm density'))
        if not density or density[-1] != '160':
            raise ValueError('Expected effective160dpi')

    def inspect_apk(label, path, package):
        badging = run(label + '-badging', [str(a.build_tools / 'aapt.exe'), 'dump', 'badging', str(path)]).decode()
        signed = run(label + '-signature', [str(a.java), '-jar', str(a.build_tools / 'lib/apksigner.jar'),
                                          'verify', '--print-certs', str(path)]).decode()
        certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', signed)
        if len(certs) != 1:
            raise ValueError('Unexpected signer set')
        return metadata(badging, package), certs[0]

    remote = '/data/local/tmp/stock-delivery-' + uuid.uuid4().hex
    try:
        guard('preflight')
        packages = shell('package-inventory', 'pm list packages -u --user 0')
        known_packages = {line[8:] for line in packages.splitlines() if line.startswith('package:')}
        if not known_packages:
            raise ValueError('Empty package inventory')
        # Complete all identity/signature/version checks before app installation.
        for name, package, component, expected in APPS:
            candidate = candidate_path(project, name)
            if digest(candidate) != expected:
                raise ValueError('Candidate hash mismatch: ' + name)
            version, cert = inspect_apk(name + '-candidate', candidate, package)
            expected_cert = EXISTING_CERT if name in MATCHED_APPS else PLATFORM_CERT
            if cert != expected_cert:
                raise ValueError('Unexpected candidate signer')
            paths = installed_paths(shell(name + '-paths', 'pm path ' + package)) if package in known_packages else []
            if package in known_packages and not paths:
                raise ValueError('Known package has no accessible APK; inspect user state')
            row = dict(name=name, package=package, candidate_sha256=expected,
                       candidate_version=version, candidate_certificate=cert, original_paths=paths, backups=[])
            report['apps'].append(row)
            if paths:
                shell(name + '-package-before', 'dumpsys package ' + package)
                shell(name + '-ops-before', 'cmd appops get ' + package)
            if len(paths) > 1:
                raise ValueError('Split package requires separate migration review')
            for index, path in enumerate(paths):
                original = a.output / (name + '-original-' + str(index) + '.apk')
                expected_original = shell(name + '-original-hash', 'sha256sum ' + shlex.quote(path)).split()[0]
                run(name + '-original-pull', base + ['pull', path, str(original)])
                if digest(original) != expected_original:
                    raise ValueError('Original APK backup mismatch')
                old_version, old_cert = inspect_apk(name + '-original', original, package)
                require_upgrade(version, old_version, cert, old_cert, expected_cert)
                row.update(original_sha256=expected_original, original_version=old_version)
        report['preflight_passed'] = True
        if not a.install:
            return
        guard('before-backups')
        shell('mkdir', 'mkdir -m 700 ' + remote)
        report['remote'] = remote
        # Stop these apps only; archive CE/DE private data, without modifying it.
        for row in report['apps']:
            name, package = row['name'], row['package']
            shell(name + '-stop-before-backup', 'am force-stop ' + package)
            for kind, parent in (('ce', '/data/user/0'), ('de', '/data/user_de/0')):
                exists = shell(name + '-' + kind + '-exists', 'if test -d ' + parent + '/' + package + '; then echo present; else echo absent; fi')
                if exists == 'absent':
                    continue
                if exists != 'present':
                    raise ValueError('Unexpected data-directory state')
                archive = remote + '/' + name + '-' + kind + '.tar'
                shell(name + '-' + kind + '-archive', 'tar -C ' + parent + ' -cf ' + archive + ' ' + package)
                expected = shell(name + '-' + kind + '-hash', 'sha256sum ' + archive).split()[0]
                local = a.output / (name + '-' + kind + '.tar')
                run(name + '-' + kind + '-pull', base + ['pull', archive, str(local)])
                if digest(local) != expected:
                    raise ValueError('Data archive backup mismatch')
                row['backups'].append(dict(kind=kind, path=str(local), sha256=expected))
        for name, package, component, expected in APPS:
            guard(name + '-before-install')
            candidate = candidate_path(project, name)
            result = run(name + '-install', base + ['install', '-r', str(candidate)]).decode().strip()
            if result != 'Success' and not result.endswith('\nSuccess'):
                raise ValueError('Install did not report success: ' + name)
            report['installed'].append(name)
            paths = installed_paths(shell(name + '-installed-path', 'pm path ' + package))
            if len(paths) != 1 or shell(name + '-installed-hash', 'sha256sum ' + shlex.quote(paths[0])).split()[0] != expected:
                raise ValueError('Installed candidate identity mismatch')
        shell('wake', 'input keyevent 224')
        shell('home-before', 'input keyevent 3')
        for row, (_, package, component, _) in zip(report['apps'], APPS):
            name = row['name']
            guard(name + '-before-launch')
            require_launch_success(shell(name + '-launch', 'am start -W -n ' + package + '/' + component))
            time.sleep(3)
            focus = shell(name + '-focus', 'dumpsys window')
            current = '\n'.join(line for line in focus.splitlines() if 'mCurrentFocus=' in line)
            png = run(name + '-screen', base + ['exec-out', 'screencap', '-p'])
            if not png.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('Invalid screenshot')
            (a.output / (name + '.png')).write_bytes(png)
            shell(name + '-dump', 'uiautomator dump ' + remote + '/' + name + '.xml')
            xml = shell(name + '-xml', 'cat ' + remote + '/' + name + '.xml')
            nodes = list(ET.fromstring(xml).iter('node'))
            row['main_focused'] = package + '/' in current and any(n.get('package') == package for n in nodes)
            row['focus'] = current
            if not row['main_focused']:
                row['navigation'] = 'Blocked by prompt/other focus; no permission choice attempted'
                shell(name + '-stop-after-prompt', 'am force-stop ' + package)
                continue
            shell(name + '-back', 'input keyevent 4')
            time.sleep(1)
            row['back_focus'] = '\n'.join(line for line in shell(name + '-after-back', 'dumpsys window').splitlines() if 'mCurrentFocus=' in line)
            shell(name + '-home', 'input keyevent 3')
            time.sleep(1)
            row['home_focus'] = '\n'.join(line for line in shell(name + '-after-home', 'dumpsys window').splitlines() if 'mCurrentFocus=' in line)
            row['home_returned'] = 'com.android.launcher3/' in row['home_focus']
        guard('final')
        report['candidates_retained'] = True
        report['main_and_home_passed'] = all(r.get('main_focused') and r.get('home_returned') for r in report['apps'])
    except Exception as error:
        report['error'] = str(error)
        report['recovery'] = 'Retain installed candidates/data and inspect evidence; no automatic rollback or retry'
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

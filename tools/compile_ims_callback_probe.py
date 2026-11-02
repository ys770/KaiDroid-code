"""Compile original and adapted listener against retained native12 API headers.

This is a single-class compile check, not a framework/image build or Binder test.
Run on the Linux build host with two prepared source files and a fresh output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--original', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    pins = {'original': '6c5cc98016bf0e0161a8f0bbe15ec59c960193613642cc783dd266c1b9a76e89',
            'candidate': '303257372bd8cb24f44a70c8201f8fcc0ed20dc3638d0e97f102e078e4ffc54a'}
    for role in pins:
        if digest(getattr(a, role)) != pins[role]:
            raise ValueError('Source hash mismatch: ' + role)
    base = a.root / 'tcl-dialog-build12/out/soong/.intermediates'
    jars = [base / entry for entry in (
        'frameworks/base/framework/android_common/turbine-combined/framework.jar',
        'frameworks/base/framework-minus-apex/android_common/turbine-combined/framework-minus-apex.jar',
        'frameworks/base/framework-annotations-lib/android_common/turbine-combined/framework-annotations-lib.jar',
        'libcore/core-all/android_common/turbine-combined/core-all.jar')]
    jdk = a.root / 'aosp/prebuilts/jdk/jdk11/linux-x86'
    inputs = jars + [jdk / 'bin/javac', jdk / 'bin/javap', jdk / 'lib/modules']
    before = {str(x): digest(x) for x in inputs}
    a.output.mkdir(parents=True, exist_ok=False)
    report = {'classification': 'single_class_compile_only', 'inputs': before,
              'source_pins': pins, 'roles': {}, 'installed': False,
              'binder_runtime_validated': False, 'full_framework_built': False}
    for role in pins:
        stage = a.output / role
        stage.mkdir()
        source = stage / 'ImsCallSessionListener.java'
        source.write_bytes(getattr(a, role).read_bytes())
        classes = stage / 'classes'
        classes.mkdir()
        cmd = [str(jdk / 'bin/javac'), '-J-Xmx512m', '-J-XX:ActiveProcessorCount=2',
               '-source', '8', '-target', '8', '-proc:none', '-implicit:none',
               '-sourcepath', str(stage / 'empty-sourcepath'), '-bootclasspath', str(jars[-1]),
               '-classpath', ':'.join(map(str, jars[:-1])), '-d', str(classes), str(source)]
        r = subprocess.run(cmd, capture_output=True, timeout=90)
        (stage / 'stdout.txt').write_bytes(r.stdout)
        (stage / 'stderr.txt').write_bytes(r.stderr)
        item = {'command': cmd, 'exit_code': r.returncode}
        report['roles'][role] = item
        if r.returncode == 0:
            dis = subprocess.run([str(jdk / 'bin/javap'), '-p', '-c', '-s',
                                  '-classpath', str(classes), 'android.telephony.ims.ImsCallSessionListener'],
                                 capture_output=True, check=True, timeout=30)
            (stage / 'javap.txt').write_bytes(dis.stdout)
            item['class_sha256'] = digest(classes / 'android/telephony/ims/ImsCallSessionListener.class')
    report['inputs_unchanged'] = all(digest(x) == before[str(x)] for x in inputs)
    report['sources_unchanged'] = all(digest(getattr(a, r)) == pins[r] for r in pins)
    report['passed'] = report['inputs_unchanged'] and report['sources_unchanged'] and all(
        r['exit_code'] == 0 for r in report['roles'].values())
    (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

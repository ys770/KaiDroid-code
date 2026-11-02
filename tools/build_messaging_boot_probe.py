"""Build an emulator-only probe for the exact Messaging boot lifecycle helper."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'jdk', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]; source = root/'tests/messagingboot'
    helper = root/'framework/apps/Messaging/src/com/android/mms/transaction/KaiBootRecovery.java'
    jdk = a.jdk.resolve(); bt = a.sdk.resolve()/'build-tools/35.0.0'
    android = a.sdk.resolve()/'platforms/android-30/android.jar'
    suffix = '.exe' if os.name == 'nt' else ''
    env = os.environ.copy(); env['JAVA_HOME'] = str(jdk)
    env['PATH'] = str(jdk/'bin') + os.pathsep + env.get('PATH', '')
    def run(args):
        args = list(map(str, args))
        r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)
        with (out/'build.log').open('a', encoding='utf-8') as f:
            f.write(json.dumps(args)+'\n'+r.stdout+r.stderr)
        r.check_returncode()
    for name in ('classes', 'dex'):
        (out/name).mkdir()
    unsigned = out/'unsigned.apk'
    run([bt/('aapt'+suffix), 'package', '-f', '-M', source/'AndroidManifest.xml',
         '-I', android, '-F', unsigned])
    files = [*source.rglob('*.java'), helper]
    run([jdk/('bin/javac'+suffix), '--release', '8', '-classpath', android,
         '-d', out/'classes', *files])
    run([jdk/('bin/java'+suffix), '-cp', bt/'lib/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '30', '--lib', android, '--output', out/'dex',
         *sorted((out/'classes').rglob('*.class'))])
    with zipfile.ZipFile(unsigned, 'a', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(out/'dex/classes.dex', 'classes.dex')
    aligned = out/'aligned.apk'
    run([bt/('zipalign'+suffix), '-f', '4', unsigned, aligned])
    key = out/'diagnostic-only.p12'
    run([jdk/('bin/keytool'+suffix), '-genkeypair', '-keystore', key,
         '-storepass', 'android', '-keypass', 'android', '-alias', 'diagnostic',
         '-dname', 'CN=KaiDroid Local Diagnostic', '-keyalg', 'RSA', '-keysize', '2048',
         '-validity', '3650', '-noprompt'])
    signer = [jdk/('bin/java'+suffix), '-jar', bt/'lib/apksigner.jar']
    apk = out/'messaging-boot-probe.apk'
    run([*signer, 'sign', '--ks', key, '--ks-pass', 'pass:android', '--out', apk, aligned])
    run([*signer, 'verify', '--verbose', '--print-certs', apk])
    report = dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
        source_sha256={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest()
                       for f in [source/'AndroidManifest.xml', *files]}, installed=False,
        scope='Exact helper, fixture services; no telephony/provider/network access')
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

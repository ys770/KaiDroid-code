"""Compile original default-callback bridges and append them to a pinned APK.

Offline only. Existing app DEX bytes remain unchanged. The candidate is unsigned;
Android runtime/role/signing validation still requires coordinated device work.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

from audit_tcl_target_api import archive, parse
from prepare_tcl_ui_apps import APPS

RENAMES = {
    'Landroid/animation/Animator$AnimatorListener$DCC;': 'Landroid/animation/Animator$AnimatorListener$-CC;',
    'Landroid/content/ServiceConnection$DCC;': 'Landroid/content/ServiceConnection$-CC;',
}


def rename_companions(data):
    classes, _, _, _ = parse(data)
    if set(classes) != set(RENAMES):
        raise ValueError('Unexpected generated bridge classes')
    out = bytearray(data)
    count, start = struct.unpack_from('<II', data, 56)
    before, after, changed = [], [], set()
    for i in range(count):
        pos = struct.unpack_from('<I', data, start + 4 * i)[0]
        for _ in range(5):
            byte = data[pos]
            pos += 1
            if not byte & 128:
                break
        else:
            raise ValueError('Bad generated string length')
        end = data.index(b'\0', pos)
        text = data[pos:end].decode('ascii')
        before.append(text)
        replacement = RENAMES.get(text, text)
        after.append(replacement)
        if text in RENAMES:
            if len(text) != len(replacement):
                raise ValueError('Rename would move DEX string data')
            out[pos:end] = replacement.encode('ascii')
            changed.add(text)
    if changed != set(RENAMES) or before != sorted(before) or after != sorted(after):
        raise ValueError('Missing bridge descriptor or DEX string ordering changed')
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into('<I', out, 8, zlib.adler32(out[12:]) & 0xffffffff)
    final, _, _, stale = parse(bytes(out))
    if set(final) != set(RENAMES.values()) or stale:
        raise ValueError('Generated DEX declaration/integrity check failed')
    return bytes(out)


def run(command):
    result = subprocess.run(list(map(str, command)), check=True, capture_output=True,
                            encoding='utf-8', errors='replace')
    return result.stdout + result.stderr


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'java-home', 'sdk', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    digest = hashlib.sha256(a.apk.read_bytes()).hexdigest()
    allowed = {row[1] for row in APPS.values()} | {
        '5c598de6f2814331cbcafaf64619c92e1f3ab43fd636670309b1c5a5acbe4271'}
    if digest not in allowed:
        raise ValueError('Unrecognized donor/candidate APK')
    app_classes, refs, _, _ = archive(a.apk)
    if app_classes.keys() & set(RENAMES.values()):
        raise ValueError('APK already defines a companion class')
    if not any(owner in RENAMES.values() for owner, _, _ in refs):
        raise ValueError('APK has no observed companion references')
    project = Path(__file__).resolve().parents[1]
    sources = sorted((project / 'compat/java').rglob('*.java'))
    if len(sources) != 2:
        raise ValueError('Unexpected callback source set')
    java = a.java_home / 'bin/java.exe'
    javac = a.java_home / 'bin/javac.exe'
    android = a.sdk / 'platforms/android-30/android.jar'
    d8 = a.sdk / 'build-tools/35.0.0/lib/d8.jar'
    for required in (java, javac, android, d8):
        if not required.is_file():
            raise ValueError('Missing tool: ' + str(required))
    a.output.mkdir(parents=True)
    classes, dex = a.output / 'classes', a.output / 'dex'
    classes.mkdir()
    dex.mkdir()
    log = run([javac, '--release', '8', '-classpath', android, '-d', classes, *sources])
    jar = a.output / 'bridges.jar'
    with zipfile.ZipFile(jar, 'w') as z:
        for file in sorted(classes.rglob('*.class')):
            z.write(file, file.relative_to(classes).as_posix())
    log += run([java, '-cp', d8, 'com.android.tools.r8.D8', '--min-api', '30',
                '--lib', android, '--output', dex, jar])
    original_dex = (dex / 'classes.dex').read_bytes()
    bridge = rename_companions(original_dex)
    (a.output / 'callback-bridges.dex').write_bytes(bridge)
    # Execute callback dispatch tests on the JVM before packaging the DEX spelling.
    test = project / 'tests/DefaultCallbackBridgeTest.java'
    log += run([javac, '--release', '8', '-classpath', str(android) + ';' + str(classes),
                '-d', classes, test])
    log += run([java, '-cp', str(android) + ';' + str(classes), 'DefaultCallbackBridgeTest'])
    candidate = a.output / a.apk.name
    preserved = {}
    with zipfile.ZipFile(a.apk) as src, zipfile.ZipFile(candidate, 'w') as dst:
        if len(src.namelist()) != len(set(src.namelist())):
            raise ValueError('Duplicate APK ZIP entry')
        existing = [n for n in src.namelist() if re.fullmatch(r'classes\d*\.dex', n)]
        numbers = sorted(1 if n == 'classes.dex' else int(n[7:-4]) for n in existing)
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError('Non-contiguous original DEX entries')
        new_entry = f'classes{len(numbers) + 1}.dex'
        for info in src.infolist():
            name = info.filename
            if re.fullmatch(r'META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))', name, re.I):
                continue
            payload = src.read(name)
            dst.writestr(info, payload)
            preserved[name] = hashlib.sha256(payload).hexdigest()
        dst.writestr(new_entry, bridge, compress_type=zipfile.ZIP_STORED)
    with zipfile.ZipFile(candidate) as z:
        if z.testzip() is not None or any(hashlib.sha256(z.read(n)).hexdigest() != h for n, h in preserved.items()):
            raise ValueError('Original payload changed or candidate CRC failed')
    report = dict(input_sha256=digest, output_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
                  bridge_dex_sha256=hashlib.sha256(bridge).hexdigest(), added_entry=new_entry,
                  preserved_original_dex_entries=len(existing), all_original_payloads_preserved=True,
                  source_sha256={s.relative_to(project).as_posix(): hashlib.sha256(s.read_bytes()).hexdigest() for s in sources},
                  sdk_sha256=hashlib.sha256(android.read_bytes()).hexdigest(),
                  d8_sha256=hashlib.sha256(d8.read_bytes()).hexdigest(),
                  callback_jvm_tests_passed=True, signed=False, installed=False)
    (a.output / 'build.log').write_text(log)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

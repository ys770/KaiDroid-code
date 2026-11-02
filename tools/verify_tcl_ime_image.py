"""Verify the private TCL IME payload in an extracted raw ext4 system image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

APK_SHA = 'f80ddc5b461d1d23cc05f9c212f43629991766f9630466b89fbdec8b34ea8e7f'
CONFIG_SHA = '4b6708df6e5b7ce14f813cf6a3c832f2d26cd0a8eb81caf94232a300f82b1466'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', required=True)
    parser.add_argument('--apksigner', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    provenance = json.loads((args.module / 'provenance.json').read_text())
    sha = lambda file: hashlib.sha256(file.read_bytes()).hexdigest()
    assert provenance['donor_apk_sha256'] == APK_SHA
    assert provenance['model_config_sha256'] == CONFIG_SHA
    assert len(provenance['files']) == 12
    results = []

    def query(command):
        run = subprocess.run(['debugfs', '-R', command, str(args.image)],
                             capture_output=True, check=True)
        return run.stdout, run.stderr

    def extract(path, filename, expected, label):
        dest = args.output / filename
        stdout, stderr = query('dump ' + path + ' ' + str(dest))
        assert dest.is_file(), (path, stderr)
        actual = sha(dest)
        if expected is not None:
            assert actual == expected, (path, actual, expected)
        attrs, errors = query('ea_get ' + path + ' security.selinux')
        (args.output / (filename + '.label.txt')).write_bytes(attrs + errors)
        assert label.encode() in attrs, (path, attrs)
        results.append(dict(path=path, sha256=actual, selinux_label=label))
        return dest

    apk = extract('/system/app/KaiDroidTclIme/KaiDroidTclIme.apk', 'KikaIME.apk',
                  APK_SHA, 'u:object_r:system_file:s0')
    for name, item in sorted(provenance['files'].items()):
        assert Path(name).name == name and item['destination'] == 'system/lib/' + name
        expected = CONFIG_SHA if name == 'libiqqijni.so' else sha(args.module / 'lib' / name)
        assert item['sha256'] == expected
        extract('/system/lib/' + name, name, expected, 'u:object_r:system_lib_file:s0')
    for name in ('libIQQILib.so', 'libIQQI-jni-Resource.so'):
        stdout, stderr = query('stat /system/app/KaiDroidTclIme/lib/arm/' + name)
        assert b'Type: symlink' in stdout and ('/system/lib/' + name).encode() in stdout
        (args.output / (name + '.symlink.txt')).write_bytes(stdout + stderr)
    # Preserve the fallback keyboard, not merely the donor.
    extract('/system/product/app/LatinIME/LatinIME.apk', 'LatinIME.apk', None,
            'u:object_r:system_file:s0')
    verify = subprocess.run([args.java, '-jar', args.apksigner, 'verify', '--verbose',
                             '--print-certs', '--min-sdk-version', '30',
                             '--max-sdk-version', '30', str(apk)], capture_output=True, check=True)
    (args.output / 'signature.txt').write_bytes(verify.stdout + verify.stderr)
    assert b'd24c9c3f4379b8070310617c96a87c88618dfb5297b2ebb8da39d45e2d13dac9' in verify.stdout
    report = dict(files=results, donor_signature_valid=True, native_symlinks_valid=True,
                  fallback_present=True, runtime_validated=False)
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

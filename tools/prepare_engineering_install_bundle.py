"""Prepare private policy/library payload; compile exact packaged policy bytes.

Does not modify an AOSP checkout or install anything on a phone.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'libcutils', 'platform', 'mapping', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--extra-policy', type=Path, action='append', default=[],
                        help='Actual system_ext/product policy and mapping inputs selected by init')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    hashes = {
        'vendor_sepolicy.cil': '1eb3258c9827cd589365338ef0d3d73ca4fb08375fe981a8b2a665d6f963a59f',
        'plat_pub_versioned.cil': 'b4998d758fb2fd6cfa9484e81b4eb8a17f7f85d259dcd5dd11d596a77ed6e3cc',
        '29.0.compat.cil': '400d07488c97bee746b75497432fae13985c368e192d74370a9ffee117d1f799',
    }
    data, source_hashes = {}, {}
    for name, expected in hashes.items():
        source = args.candidate / name
        raw = source.read_bytes()
        normalized = raw.replace(b'\r\n', b'\n')
        if sha(normalized) != expected:
            raise ValueError('Unreviewed policy input: ' + name)
        data[name], source_hashes[name] = normalized, sha(raw)
    library = args.libcutils.read_bytes()
    if sha(library) != '36b69524612e30aef9b158d91ee27f89174a7dd08db8a37a9d4c813eefbce1b4':
        raise ValueError('Unreviewed adapted libcutils')
    args.output.mkdir(parents=True, exist_ok=False)
    payload = args.output / 'payload'
    policy = payload / 'policy'
    policy.mkdir(parents=True)
    for name, contents in data.items():
        (policy / name).write_bytes(contents)
    (payload / 'libcutils.so').write_bytes(library)
    subprocess.run([sys.executable, str(root / 'tools/compile_policy_bundle.py'),
                    '--compiler', str(args.compiler), '--output', str(args.output / 'compiled'),
                    str(args.platform), str(args.mapping), str(policy / '29.0.compat.cil'),
                    str(policy / 'plat_pub_versioned.cil'), str(policy / 'vendor_sepolicy.cil')]
                   + [str(p) for p in args.extra_policy], check=True)
    source_root = 'device/nokia/n139dl/engineering-private'
    mk = ['# Generated private engineering payload; requires paired init/VNDK staging.',
          'ifneq ($(TARGET_BUILD_VARIANT),eng)',
          '$(error KaiDroid engineering policy requires eng variant)', 'endif']
    for name in hashes:
        mk.append(f'PRODUCT_COPY_FILES += {source_root}/policy/{name}:system/etc/selinux/kaidroid/{name}')
    (payload / 'engineering.mk').write_text('\n'.join(mk) + '\n')
    (args.output / 'install-bundle.json').write_text(json.dumps({
        'source_policy_sha256': source_hashes, 'packaged_policy_sha256': hashes,
        'library_sha256': sha(library),
        'library_source_destination': 'prebuilts/vndk/v29/arm/arch-arm-armv7-a-neon/shared/vndk-sp/libcutils.so',
        'expected_original_library_sha256': '18aae711bbd2028b21024c27d987c393eafc0b57b39f8892eac1ef95a27d475f',
        'scope': 'Private prepared payload; no build checkout change, product inclusion or installation.',
        'required_pairings': ['engineering init selector', 'sysdata label', 'platform data init actions',
                              'radio property context', 'ashmem node labels'],
    }, indent=2) + '\n')
    print('Prepared and compiled exact install payload:', args.output)


if __name__ == '__main__':
    main()

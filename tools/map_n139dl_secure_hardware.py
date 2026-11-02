"""Hash-bound offline mapping of secure hardware configuration; no key operations."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--profiles', type=Path, required=True)
    parser.add_argument('--boot-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    entry = next(e for e in manifest['reads'] if e['file'] == 'device-tree.tar')
    tree_hash = sha(args.capture / 'device-tree.tar')
    if not manifest.get('same_identity_and_boot') or entry['returncode'] or entry['stderr_bytes'] or tree_hash != entry['sha256']:
        raise ValueError('Unverified capture')
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        props = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
    handles = {int.from_bytes(v, 'big'): k.rsplit('/', 1)[0]
               for k, v in props.items() if k.endswith('/phandle') and len(v) == 4}
    reference = './soc/sdhci@7824900/sdhc-msm-crypto'
    ice = handles[int.from_bytes(props[reference], 'big')]
    targets = {'./soc/qseecom@85b00000', ice,
               './reserved-memory/qseecom_region@0', './reserved-memory/qseecom_ta_region'}
    nodes = {}
    for path, data in props.items():
        parent, name = path.rsplit('/', 1)
        if parent not in targets:
            continue
        if name in ('compatible', 'status', 'name', 'reg-names', 'clock-names', 'qcom,msm-bus,name'):
            value = data.rstrip(b'\0').decode().split('\0')
        elif not data:
            value = {'boolean_property_present': True}
        else:
            value = {'raw_hex': data.hex()}
        nodes.setdefault(parent, {})[name] = value
    if set(nodes) != targets:
        raise ValueError('Expected secure hardware nodes absent')
    options = ('CONFIG_QSEECOM', 'CONFIG_QCOM_SCM_32', 'CONFIG_MMC_SDHCI_MSM_ICE',
               'CONFIG_CRYPTO_DEV_QCOM_ICE', 'CONFIG_FS_ENCRYPTION', 'CONFIG_F2FS_FS_ENCRYPTION',
               'CONFIG_EXT4_FS_ENCRYPTION', 'CONFIG_EXT4_FS_ICE_ENCRYPTION', 'CONFIG_KEYS')
    kernels = {}
    for profile in ('engineering', 'retail2216'):
        root = args.profiles / profile
        summary = json.loads((root / 'kernel-summary.json').read_text())
        if sha(root / 'kernel.config') != summary['config_sha256'] or sha(args.boot_root / profile / 'kernel') != summary['input_sha256']:
            raise ValueError('Changed kernel/config: ' + profile)
        lines = (root / 'kernel.config').read_text().splitlines()
        values = {}
        for option in options:
            matches = [s for s in lines if s.startswith(option + '=') or s == '# ' + option + ' is not set']
            if len(matches) != 1:
                raise ValueError('Missing/ambiguous option: ' + option)
            values[option] = matches[0].split('=', 1)[1] if '=' in matches[0] else 'n'
        kernels[profile] = {'kernel_sha256': summary['input_sha256'],
                            'config_sha256': summary['config_sha256'], 'options': values}
    result = {'scope': 'Captured engineering DT and extracted stock kernel configs; no driver-binding, ioctl, secure-firmware or key compatibility proof.',
              'tree_sha256': tree_hash, 'sdhci_crypto_reference': {'property': reference, 'node': ice},
              'nodes': nodes, 'kernels': kernels}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'nodes': len(nodes), 'kernels': len(kernels), 'ice_node': ice}))


if __name__ == '__main__':
    main()

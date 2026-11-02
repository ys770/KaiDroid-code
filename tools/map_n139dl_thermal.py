"""Decode captured thermal-zone relationships without reading or writing live controls."""
import argparse
import hashlib
import json
import struct
import tarfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    entry = next(e for e in manifest['reads'] if e['file'] == 'device-tree.tar')
    digest = hashlib.sha256((args.capture / entry['file']).read_bytes()).hexdigest()
    if not manifest.get('same_identity_and_boot') or entry['returncode'] or entry['stderr_bytes'] or digest != entry['sha256']:
        raise ValueError('Unverified captured tree')
    with tarfile.open(args.capture / entry['file']) as tree:
        props = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
    handles = {int.from_bytes(v, 'big'): k.rsplit('/', 1)[0]
               for k, v in props.items() if k.endswith('/phandle') and len(v) == 4}
    result = {}
    for path, data in props.items():
        prefix = './soc/thermal-zones/'
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):]
        if '/' not in rest:
            continue
        zone, prop = rest.split('/', 1)
        name = prop.rsplit('/', 1)[-1]
        if name in ('name', 'phandle'):
            continue
        if name in ('type', 'status', 'thermal-governor'):
            value = data.rstrip(b'\0').decode()
        elif not data:
            value = True
        else:
            if len(data) % 4:
                raise ValueError('Unexpected non-cell property: ' + path)
            cells = [v[0] for v in struct.iter_unpack('>I', data)]
            value = {'raw_u32_cells': cells}
            if name in ('trip', 'thermal-sensors', 'cooling-device'):
                refs = []
                cursor = 0
                while cursor < len(cells):
                    node = handles[cells[cursor]]
                    count = 0 if name == 'trip' else int.from_bytes(props[node + ('/#thermal-sensor-cells' if name == 'thermal-sensors' else '/#cooling-cells')], 'big')
                    if cursor + 1 + count > len(cells):
                        raise ValueError('Truncated reference: ' + path)
                    refs.append({'node': node, 'args': cells[cursor + 1:cursor + 1 + count]})
                    cursor += 1 + count
                value['references'] = refs
        result.setdefault(zone, {})[prop] = value
    if not result:
        raise ValueError('No thermal zones')
    report = {'scope': 'Configured engineering thermal zones, not runtime trip points, temperatures or verified mitigation. Numeric values preserve raw DT cells.',
              'tree_sha256': digest, 'zones': result}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'zones': len(result), 'cooling_maps': sum('/cooling-device' in p for z in result.values() for p in z)}))


if __name__ == '__main__':
    main()

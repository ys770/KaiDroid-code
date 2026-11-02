"""Fetch only routed ARM/Binder64 VNDK29 libraries from a pinned AOSP revision."""
import argparse
import base64
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--routes', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.revision):
        raise ValueError('Pin a full upstream commit SHA')
    report = json.loads(args.routes.read_text())
    selected = set()
    for binary in report['binaries']:
        for item in binary['needed'].values():
            for route in item['routes']:
                if route['namespace'] == 'vndk':
                    selected.add(route['candidate'])
    results = []
    cached = {}
    manifest_path = args.output / 'manifest.json'
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text())
        if previous['revision'] != args.revision:
            raise ValueError('Use a separate directory for a different upstream revision')
        cached = {item['captured_candidate']: item for item in previous['files']}
    for candidate in sorted(selected):
        match = re.fullmatch(r'system:/system/lib/(vndk-sp-29|vndk-29)/([A-Za-z0-9_@.+-]+)', candidate)
        if not match:
            raise ValueError('Unsupported snapshot path: ' + candidate)
        directory, name = match.groups()
        category = 'vndk-sp' if directory == 'vndk-sp-29' else 'vndk-core'
        relative = 'arm/arch-arm-armv7-a-neon/shared/' + category + '/' + name
        target = args.output / category / name
        if candidate in cached and target.exists():
            entry = cached[candidate]
            if entry['upstream_path'] != relative or hashlib.sha256(target.read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('Cached reference mismatch')
            results.append(entry)
            continue
        url = 'https://android.googlesource.com/platform/prebuilts/vndk/v29/+/' + args.revision + '/' + urllib.parse.quote(relative, safe='/') + '?format=TEXT'
        data = base64.b64decode(urllib.request.urlopen(url, timeout=60).read(), validate=True)
        if data[:6] != b'\x7fELF\x01\x01' or int.from_bytes(data[18:20], 'little') != 40:
            raise ValueError('Expected ARM32 little-endian ELF: ' + relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Refusing to overwrite different reference')
        target.write_bytes(data)
        results.append({'captured_candidate': candidate, 'upstream_path': relative,
                        'local_path': category + '/' + name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
    (args.output / 'manifest.json').write_text(json.dumps({'revision': args.revision,
        'source': 'https://android.googlesource.com/platform/prebuilts/vndk/v29',
        'abi': 'armv7-a-neon, default Binder64 snapshot (not arm/binder32)', 'files': results,
        'scope': 'Reference artifacts only; not copied into product or device.'}, indent=2) + '\n')
    print('Fetched and checked', len(results), 'pinned ARM32 VNDK29 reference libraries')


if __name__ == '__main__':
    main()

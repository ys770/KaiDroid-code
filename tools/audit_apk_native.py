"""Inspect packaged native libraries using Linux readelf; never execute them.

Reports ELF attributes, dynamic dependencies and undefined dynamic symbols.
Filename closure within an ABI is not linker or symbol compatibility proof.
"""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath


def dynamic_symbols(report):
    # ARM IFUNC may be rendered as the multi-word type '<OS specific>: 10'.
    pattern = r'^\s*\d+:\s+\S+\s+\d+\s+(.+?)\s+(LOCAL|GLOBAL|WEAK|UNIQUE)\s+(DEFAULT|PROTECTED|HIDDEN|INTERNAL)\s+(\S+)\s+(\S+)'
    for line in report.splitlines():
        match = re.match(pattern, line)
        if match:
            kind, binding, visibility, section, name = match.groups()
            yield {'name': name, 'binding': binding, 'type': kind,
                   'visibility': visibility, 'section': section}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    actual = hashlib.sha256(args.apk.read_bytes()).hexdigest()
    if actual != args.sha256:
        raise ValueError('APK does not match expected SHA-256')
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with zipfile.ZipFile(args.apk) as archive:
        for name in sorted(archive.namelist()):
            parts = PurePosixPath(name).parts
            if len(parts) != 3 or parts[0] != 'lib' or not name.endswith('.so'):
                continue
            if any(part in ('.', '..') or '\\' in part for part in parts):
                raise ValueError('Unsafe native library path')
            data = archive.read(name)
            destination = args.output.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.read_bytes() != data:
                raise ValueError('Refusing to replace different extracted library')
            destination.write_bytes(data)
            if data[:4] != b'\x7fELF':
                results.append({'entry': name, 'sha256': hashlib.sha256(data).hexdigest(),
                                'bytes': len(data), 'abi': parts[1], 'is_elf': False,
                                'prefix_hex': data[:16].hex(), 'needed': [], 'textrel': None})
                continue
            report = subprocess.run(['readelf', '-h', '-d', '-A', '--dyn-syms', '--wide', str(destination)],
                                    check=True, capture_output=True, text=True).stdout
            destination.with_suffix('.readelf.txt').write_text(report)
            undefined = []
            exported = []
            for symbol in dynamic_symbols(report):
                if symbol['section'] == 'UND':
                    undefined.append(symbol)
                elif symbol['binding'] in ('GLOBAL', 'WEAK', 'UNIQUE') and symbol['visibility'] in ('DEFAULT', 'PROTECTED'):
                    exported.append(symbol['name'])
            results.append({'entry': name, 'sha256': hashlib.sha256(data).hexdigest(),
                            'bytes': len(data), 'abi': parts[1], 'is_elf': True,
                            'elf_header': report.split('Dynamic section')[0].strip(),
                            'needed': re.findall(r'\(NEEDED\).*?\[(.*?)\]', report),
                            'soname': re.findall(r'\(SONAME\).*?\[(.*?)\]', report),
                            'undefined_symbols': undefined, 'exported_symbols': sorted(set(exported)),
                            'textrel': bool(re.search(r'\(TEXTREL\)|\(FLAGS\).*TEXTREL', report))})
    for item in results:
        bundled = {PurePosixPath(other['entry']).name for other in results
                   if other['abi'] == item['abi'] and other['is_elf']}
        item['needed_outside_apk'] = sorted(set(item['needed']) - bundled)
    output = {'apk_sha256': actual, 'libraries': results,
              'scope': 'Static ELF metadata and symbols only. No dlopen, namespace, relocations or runtime validation.'}
    (args.output / 'summary.json').write_text(json.dumps(output, indent=2) + '\n')
    for item in results:
        print(item['entry'], 'ELF:', item['is_elf'], 'external:', ', '.join(item['needed_outside_apk']), 'textrel:', item['textrel'])


if __name__ == '__main__':
    main()

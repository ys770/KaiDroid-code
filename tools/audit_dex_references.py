"""Map APK DEX type references to captured framework definitions, without execution.

References are not proof that a code path runs. Reflection, native code, resource
IDs and method-level ABI changes require separate analysis. Output stays local.
"""
import argparse
import hashlib
import json
import re
import struct
import zipfile
import zlib
from collections import defaultdict
from pathlib import Path

OEM_PREFIXES = ('Lcom/mediatek/', 'Lcom/tct/', 'Lcom/tcl/', 'Lcom/jrd/',
                'Landroid/tct/', 'Landroid/tcl/', 'Lcom/qualcomm/', 'Lcom/qti/')


def read_dex(data, allow_stale_sha1=False, definitions_only=False, declarations=None):
    # Optional empty output dictionary captures all encoded definitions, including
    # abstract/native methods without bytecode, while preserving the return API.
    if declarations is not None and (not definitions_only or not isinstance(declarations,dict) or declarations):
        raise ValueError('Declarations require definitions_only and an empty dictionary')
    if len(data) < 112 or not re.fullmatch(rb'dex\n0[0-9]{2}\0', data[:8]):
        raise ValueError('Unsupported DEX header')
    if struct.unpack_from('<I', data, 32)[0] != len(data):
        raise ValueError('DEX file size mismatch')
    if struct.unpack_from('<I', data, 40)[0] != 0x12345678:
        raise ValueError('Unsupported DEX byte order')
    if struct.unpack_from('<I', data, 8)[0] != zlib.adler32(data[12:]) & 0xffffffff:
        raise ValueError('DEX checksum mismatch')
    stale_sha1 = data[12:32] != hashlib.sha1(data[32:]).digest()
    if stale_sha1 and not allow_stale_sha1:
        raise ValueError('DEX SHA-1 header digest mismatch')

    def table(header_offset, width):
        count, offset = struct.unpack_from('<II', data, header_offset)
        if offset + count * width > len(data):
            raise ValueError('DEX table exceeds file')
        return count, offset

    string_count, string_offset = table(56, 4)
    cache = {}

    def string(index):
        if index >= string_count:
            raise ValueError('String index outside DEX table')
        if index not in cache:
            offset, = struct.unpack_from('<I', data, string_offset + index * 4)
            for _ in range(5):
                byte = data[offset]
                offset += 1
                if not byte & 0x80:
                    break
            else:
                raise ValueError('Invalid string length ULEB128')
            end = data.index(b'\0', offset)
            cache[index] = data[offset:end].decode('utf-8', errors='replace')
        return cache[index]

    count, offset = table(64, 4)
    types = [string(struct.unpack_from('<I', data, offset + index * 4)[0]) for index in range(count)]
    count, offset = table(96, 32)
    defined = {types[struct.unpack_from('<I', data, offset + index * 32)[0]] for index in range(count)}
    proto_count, proto_offset = table(72, 12)
    prototypes = []
    for index in range(proto_count):
        _, return_type, parameter_offset = struct.unpack_from('<III', data, proto_offset + index * 12)
        parameters = []
        if parameter_offset:
            parameter_count, = struct.unpack_from('<I', data, parameter_offset)
            for parameter in range(parameter_count):
                type_index, = struct.unpack_from('<H', data, parameter_offset + 4 + parameter * 2)
                parameters.append(types[type_index])
        prototypes.append('(' + ''.join(parameters) + ')' + types[return_type])
    count, offset = table(88, 8)
    method_ids = []
    for index in range(count):
        owner, prototype, name = struct.unpack_from('<HHI', data, offset + index * 8)
        method_ids.append((types[owner], string(name), prototypes[prototype]))
    methods = set(method_ids)
    if definitions_only:
        methods = set()
        class_count, class_offset = table(96, 32)

        def uleb(cursor):
            value = 0
            for shift in range(0, 35, 7):
                byte = data[cursor]
                cursor += 1
                value |= (byte & 127) << shift
                if not byte & 128:
                    if value > 0xffffffff:
                        raise ValueError('ULEB128 overflow')
                    return value, cursor
            raise ValueError('Invalid ULEB128')

        for index in range(class_count):
            base = class_offset + index * 32
            owner = types[struct.unpack_from('<I', data, base)[0]]
            cursor = struct.unpack_from('<I', data, base + 24)[0]
            if not cursor:
                continue
            counts = []
            for _ in range(4):
                value, cursor = uleb(cursor)
                counts.append(value)
            for _ in range(counts[0] + counts[1]):
                _, cursor = uleb(cursor)  # field index delta
                _, cursor = uleb(cursor)  # access flags
            for method_kind,method_count in zip(('direct','virtual'),counts[2:]):
                method_index = 0
                for _ in range(method_count):
                    delta, cursor = uleb(cursor)
                    method_index += delta
                    flags, cursor = uleb(cursor)
                    code_offset, cursor = uleb(cursor)
                    method = method_ids[method_index]
                    if method[0] != owner:
                        raise ValueError('Defined method owner mismatch')
                    if declarations is not None:
                        if method in declarations: raise ValueError('Duplicate encoded method definition')
                        declarations[method]=dict(kind=method_kind,access=flags,has_code=bool(code_offset))
                    # Require an actual bytecode body, not a reference or an
                    # abstract/native declaration, for this verification mode.
                    if not flags & (0x100 | 0x400) and code_offset:
                        if code_offset % 4 or code_offset + 16 > len(data):
                            raise ValueError('Invalid method code offset')
                        instructions = struct.unpack_from('<I', data, code_offset + 12)[0]
                        if code_offset + 16 + instructions * 2 > len(data):
                            raise ValueError('Method instructions exceed DEX')
                        methods.add(method)
    return set(types), defined, methods, stale_sha1


def archive_dex(path, allow_stale_sha1=False):
    referenced, defined, methods, count = set(), set(), set(), 0
    errors = []
    warnings = []
    with zipfile.ZipFile(path) as package:
        for name in package.namelist():
            if re.fullmatch(r'classes\d*\.dex', name):
                try:
                    refs, definitions, calls, stale_sha1 = read_dex(package.read(name), allow_stale_sha1)
                except (ValueError, IndexError, struct.error) as error:
                    errors.append({'entry': name, 'error': str(error)})
                    continue
                if stale_sha1:
                    warnings.append({'entry': name, 'warning': 'Stale SHA-1 header digest; structural analysis only, original unchanged'})
                referenced.update(refs)
                defined.update(definitions)
                methods.update(calls)
                count += 1
    return referenced, defined, methods, count, errors, warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--apk-audit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-stale-sha1', action='store_true',
                        help='Analyze checksummed DEX tables with stale SHA-1 header digests; record warnings, never modify input')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    framework, jars = defaultdict(list), []
    for jar in sorted((args.root / 'system/framework').glob('*.jar')):
        _, definitions, _, count, errors, warnings = archive_dex(jar, args.allow_stale_sha1)
        relative = jar.relative_to(args.root).as_posix()
        jars.append({'path': relative, 'sha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
                     'dex_count': count, 'classes': len(definitions), 'rejected_dex': errors, 'warnings': warnings})
        for definition in definitions:
            framework[definition].append(relative)
    results = []
    ui_contract = defaultdict(set)
    for apk in json.loads(args.apk_audit.read_text(encoding='utf-8')):
        path = args.root / apk['path']
        if hashlib.sha256(path.read_bytes()).hexdigest() != apk['sha256']:
            raise ValueError('APK differs from audited input')
        refs, definitions, methods, count, errors, warnings = archive_dex(path, args.allow_stale_sha1)
        external = {ref.lstrip('[') for ref in refs} - definitions
        oem = sorted(ref for ref in external if ref.startswith(OEM_PREFIXES)
                     or ref.startswith('Landroid/widget/MenuBar')
                     or re.search(r'/(?:Tct|TCL|Jrd|GFlip)[^/]*;', ref))
        # Method-table references include overload descriptors but are not a call graph.
        method_refs = [{'owner': owner, 'name': name, 'descriptor': descriptor}
                       for owner, name, descriptor in sorted(methods)]
        for owner, name, descriptor in methods:
            if owner.startswith(('Landroid/app/Tct', 'Landroid/widget/Tct', 'Landroid/widget/MenuBar')):
                ui_contract[(owner, name, descriptor)].add(apk['package'])
        (args.output / (Path(apk['path']).stem + '-method-refs.json')).write_text(
            json.dumps(method_refs, indent=2) + '\n', encoding='utf-8')
        results.append({'path': apk['path'], 'package': apk['package'], 'dex_count': count,
                        'defined_types': len(definitions), 'external_types': len(external), 'rejected_dex': errors, 'warnings': warnings,
                        'external_type_names': sorted(external),
                        'external_oem_types': {name: framework.get(name, []) for name in oem}})
    (args.output / 'summary.json').write_text(json.dumps({'framework_jars': jars, 'apks': results,
        'scope': 'Static type and method-signature references; no call graph, runtime or ABI compatibility proof.'}, indent=2) + '\n', encoding='utf-8')
    (args.output / 'ui-method-contract.json').write_text(json.dumps({
        'scope': 'Referenced method descriptors only; may include inherited methods. Not a complete implementation specification.',
        'methods': [{'owner': owner, 'name': name, 'descriptor': descriptor,
                     'consumers': sorted(consumers), 'class_providers': framework.get(owner, [])}
                    for (owner, name, descriptor), consumers in sorted(ui_contract.items())]
    }, indent=2) + '\n', encoding='utf-8')
    for result in results:
        print(f"{result['package']}: {result['dex_count']} accepted DEX, {len(result['rejected_dex'])} rejected DEX, {len(result['external_oem_types'])} external OEM types")
    print('Framework rejected DEX:', sum(len(jar['rejected_dex']) for jar in jars))


if __name__ == '__main__':
    main()

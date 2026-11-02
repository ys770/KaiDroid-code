"""Compare donor member references to actual target DEX declarations/inheritance.

Includes native/abstract declarations. A method-table reference is NOT treated
as a definition. This does not establish hidden-API permissions, visibility,
class-loader availability, dispatch-kind compatibility or executed code paths.
"""
import argparse
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

from audit_dex_references import read_dex


def parse(data):
    # Reuse existing identity/integrity checks; generated hidden-API DEX often
    # has stale SHA-1 but valid Adler. Keep and report that distinction.
    _, _, _, stale = read_dex(data, allow_stale_sha1=True)

    def u32(offset):
        return struct.unpack_from('<I', data, offset)[0]

    def uleb(offset):
        value = 0
        for shift in range(0, 35, 7):
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                if value > 0xffffffff:
                    raise ValueError('ULEB overflow')
                return value, offset
        raise ValueError('Invalid ULEB')

    strings = []
    for i in range(u32(56)):
        _, pos = uleb(u32(u32(60) + 4 * i))
        strings.append(data[pos:data.index(b'\0', pos)].decode('utf-8', errors='replace'))
    types = [strings[u32(u32(68) + 4 * i)] for i in range(u32(64))]

    def type_list(offset):
        return [] if not offset else [types[struct.unpack_from('<H', data, offset + 4 + 2 * i)[0]]
                                      for i in range(u32(offset))]

    protos = []
    for i in range(u32(72)):
        pos = u32(76) + 12 * i
        protos.append('(' + ''.join(type_list(u32(pos + 8))) + ')' + types[u32(pos + 4)])
    methods, fields = [], []
    for i in range(u32(88)):
        owner, proto, name = struct.unpack_from('<HHI', data, u32(92) + 8 * i)
        methods.append((types[owner], strings[name], protos[proto]))
    for i in range(u32(80)):
        owner, typ, name = struct.unpack_from('<HHI', data, u32(84) + 8 * i)
        fields.append((types[owner], strings[name], types[typ]))
    classes = {}
    for i in range(u32(96)):
        pos = u32(100) + 32 * i
        owner = types[u32(pos)]
        sup = u32(pos + 8)
        entry = dict(superclass=None if sup == 0xffffffff else types[sup],
                     interfaces=type_list(u32(pos + 12)), methods=set(), fields=set())
        cursor = u32(pos + 24)
        if cursor:
            counts = []
            for _ in range(4):
                n, cursor = uleb(cursor)
                counts.append(n)
            for section, n in enumerate(counts):
                index = 0
                for _ in range(n):
                    delta, cursor = uleb(cursor)
                    index += delta
                    _, cursor = uleb(cursor)  # access flags
                    members = fields if section < 2 else methods
                    if section >= 2:
                        _, cursor = uleb(cursor)  # code offset, not required for abstract/native
                    actual_owner, name, descriptor = members[index]
                    if actual_owner != owner:
                        raise ValueError('Declared member owner mismatch')
                    entry['fields' if section < 2 else 'methods'].add((name, descriptor))
        if owner in classes:
            raise ValueError('Duplicate class in DEX')
        classes[owner] = entry
    return classes, methods, fields, stale


def archive(path):
    classes, methods, fields, warnings = {}, set(), set(), []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex', name):
                continue
            c, m, f, stale = parse(z.read(name))
            if classes.keys() & c.keys():
                raise ValueError(f'Duplicate classes in {path}')
            classes.update(c)
            methods.update(m)
            fields.update(f)
            if stale:
                warnings.append(name + ': stale SHA-1, valid Adler; structural analysis only')
    return classes, methods, fields, warnings


def resolve(classes, owner, name, descriptor, kind):
    pending = [owner]
    visited = set()
    missing = set()
    while pending:
        cls = pending.pop()
        if cls in visited:
            continue
        visited.add(cls)
        entry = classes.get(cls)
        if entry is None:
            missing.add(cls)
            continue
        if (name, descriptor) in entry[kind]:
            return cls, missing
        # Constructors/class initializers cannot resolve through inheritance.
        if kind == 'methods' and name in ('<init>', '<clinit>'):
            continue
        pending.extend(entry['interfaces'])
        if entry['superclass']:
            pending.append(entry['superclass'])
    return None, missing


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--classpath', type=Path, required=True,
                   help='Ordered JSON list of file/sha256 rows from the actual image boot classpath')
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if hashlib.sha256(a.apk.read_bytes()).hexdigest() != a.sha256:
        raise ValueError('APK hash mismatch')
    classes, inputs, duplicate = {}, [], []
    for source in json.loads(a.classpath.read_text()):
        path = a.target / source['file']
        if path.parent.resolve() != a.target.resolve():
            raise ValueError('Classpath entry must be a direct child of target')
        if hashlib.sha256(path.read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Target classpath hash mismatch')
        c, _, _, warnings = archive(path)
        for cls in c.keys() & classes.keys():
            if c[cls] != classes[cls]:
                raise ValueError('Conflicting target definitions: ' + cls)
            duplicate.append(cls)
        classes.update(c)
        inputs.append(dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           classes=len(c), warnings=warnings))
    if not classes:
        raise ValueError('No target classes')
    app, methods, fields, warnings = archive(a.apk)
    # Android boot classes take precedence over app-bundled definitions.
    combined = dict(app)
    combined.update(classes)
    rows = []
    resolved = 0
    for kind, refs in [('methods', methods), ('fields', fields)]:
        for owner, name, descriptor in sorted(refs):
            if owner.startswith('['):
                continue  # Array clone resolution is a VM rule, not a declared class.
            provider, missing = resolve(combined, owner, name, descriptor, kind)
            if provider:
                resolved += 1
                continue
            rows.append(dict(kind=kind, owner=owner, name=name, descriptor=descriptor,
                             owner_in_target=owner in classes, owner_in_app=owner in app,
                             missing_hierarchy=sorted(missing)))
    report = dict(scope=__doc__, apk_sha256=a.sha256, target_inputs=inputs,
                  classpath_sha256=hashlib.sha256(a.classpath.read_bytes()).hexdigest(),
                  target_classes=len(classes), app_classes=len(app), warnings=warnings,
                  duplicate_identical_target_classes=sorted(set(duplicate)),
                  resolved_member_references=resolved, unresolved=rows,
                  boot_shadowed_app_classes=sorted(app.keys() & classes.keys()))
    with a.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'resolved': resolved, 'unresolved': len(rows),
                      'missing_members_on_target_classes': sum(r['owner_in_target'] for r in rows)}))


if __name__ == '__main__':
    main()

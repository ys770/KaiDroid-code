"""Offline field-declaration lookup against exact image59; not access/linkage proof."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import zipfile
from dissect.extfs import ExtFS
from audit_tcl_target_api import archive, parse, resolve

RAW = 'ca8153c0d5f3165fa6b79b4f1b31663babef6a58d71590092edd5910ea723aad'
APK = '496fbafce3cb817106ac4d1e7f7931e79064f8ca163ef3da7a0da9f46f1aab6b'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('raw', 'apk', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    for path, pin in ((a.raw, RAW), (a.apk, APK)):
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != pin:
                raise ValueError('Input hash mismatch: ' + str(path))
    app, _, fields, app_warnings = archive(a.apk)
    classes, providers, inputs, conflicts = {}, {}, [], set()
    with a.raw.open('rb') as stream:
        fs = ExtFS(stream)
        paths = ['/system/framework']
        paths += ['/system/apex/' + item.filename + '/javalib'
                  for item in fs.get('/system/apex').iterdir()]
        for directory in paths:
            try:
                nodes = list(fs.get(directory).iterdir())
            except FileNotFoundError:
                continue
            for node in nodes:
                if not node.filename.endswith('.jar'):
                    continue
                source = directory + '/' + node.filename
                data = node.open().read()
                warnings, count = [], 0
                with zipfile.ZipFile(BytesIO(data)) as z:
                    for name in z.namelist():
                        if not re.fullmatch(r'classes\d*\.dex', name):
                            continue
                        found, _, _, stale = parse(z.read(name))
                        count += len(found)
                        if stale:
                            warnings.append(name + ': stale SHA-1; valid Adler')
                        for cls, definition in found.items():
                            if cls in classes and classes[cls] != definition:
                                conflicts.add(cls)
                            classes[cls] = definition
                            providers.setdefault(cls, []).append(source)
                inputs.append(dict(path=source, sha256=hashlib.sha256(data).hexdigest(),
                                   classes=count, warnings=warnings))
    # This is a declaration inventory, not an assertion that every jar is loaded.
    combined = dict(app)
    combined.update(classes)
    for cls in conflicts:
        combined.pop(cls, None)
    rows, inherited, app_unresolved = [], [], []
    for owner, name, descriptor in sorted(fields):
        if owner in app:
            provider, missing = resolve(combined, owner, name, descriptor, 'fields')
            row = dict(owner=owner, name=name, descriptor=descriptor,
                       declaring_class=provider, providers=providers.get(provider, []),
                       missing_hierarchy=sorted(missing))
            if provider is None:
                app_unresolved.append(row)
            elif provider in classes and provider not in app:
                inherited.append(row)
            continue
        if not owner.startswith(('Landroid/', 'Lcom/android/', 'Ljava/',
                                                'Ljavax/', 'Lcom/qualcomm/', 'Lcom/qti/')):
            continue
        provider, missing = resolve(combined, owner, name, descriptor, 'fields')
        rows.append(dict(owner=owner, name=name, descriptor=descriptor,
                         declaring_class=provider, providers=providers.get(provider, []),
                         missing_hierarchy=sorted(missing)))
    report = dict(image=59, raw_sha256=RAW, candidate_sha256=APK, inputs=inputs,
                  app_warnings=app_warnings, field_references=rows,
                  app_owned_field_reference_count=sum(f[0] in app for f in fields),
                  inherited_platform_fields=inherited,
                  unresolved_app_owned_fields=app_unresolved,
                  conflicting_classes_excluded=sorted(conflicts),
                  resolved=sum(r['declaring_class'] is not None for r in rows),
                  unresolved=[r for r in rows if r['declaring_class'] is None],
                  installed=False,
                  limitations=['Declaration lookup only; not a runtime classpath',
                               'No visibility, static/instance, hidden API or field access proof',
                               'No reflection, native linkage, service binding or call validation'])
    with a.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(fields=len(rows), resolved=report['resolved'],
                          unresolved=report['unresolved'],
                          inherited_platform_fields=inherited,
                          unresolved_app_owned_fields=app_unresolved)))


if __name__ == '__main__':
    main()

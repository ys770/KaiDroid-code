"""Inventory selected APK requests against a captured target framework manifest.

This is not a permission grant simulation. Other packages may define permissions
absent from framework-res, and donor allowlists are evidence, not target grants.
"""
import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def framework_permissions(text):
    permissions = {}
    for block in re.split(r'(?=^    E: )', text, flags=re.M):
        if not block.startswith('    E: permission ('):
            continue
        name = re.search(r'android:name\([^)]*\)="([^"]+)"', block)
        level = re.search(r'android:protectionLevel\([^)]*\)=\(type 0x1[01]\)0x([0-9a-f]+)', block)
        if not name or not level:
            raise ValueError('Permission name or protection level not decoded')
        if name[1] in permissions:
            raise ValueError('Duplicate framework permission')
        permissions[name[1]] = int(level[1], 16)
    if not permissions:
        raise ValueError('No framework permission declarations')
    return permissions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('provenance', 'framework_manifest', 'donor_root', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    provenance = json.loads(args.provenance.read_text(encoding='utf-8'))
    framework = framework_permissions(args.framework_manifest.read_text(encoding='utf-8'))
    sources = []
    donor = {}
    for path in sorted(args.donor_root.rglob('*.xml')):
        if path.parent.name != 'permissions' or path.parent.parent.name != 'etc':
            continue
        root = ET.parse(path).getroot()
        relevant = []
        for node in root.findall('privapp-permissions'):
            package = node.get('package')
            if package not in {a['package'] for a in provenance['apps']}:
                continue
            for child in node:
                if child.tag not in ('permission', 'deny-permission'):
                    continue
                item = dict(name=child.attrib['name'], decision=child.tag,
                            source=path.relative_to(args.donor_root).as_posix())
                donor.setdefault(package, []).append(item)
                relevant.append(item)
        if relevant:
            sources.append(dict(path=path.relative_to(args.donor_root).as_posix(),
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    apps = []
    for app in provenance['apps']:
        requests = app['requested_permissions']
        apps.append(dict(name=app['name'], package=app['package'], apk_sha256=app['sha256'],
            framework_defined=[dict(name=n, protection_level_hex=hex(framework[n]),
                                    base=framework[n] & 15, privileged=bool(framework[n] & 16))
                               for n in requests if n in framework],
            absent_from_framework=[n for n in requests if n not in framework],
            donor_allowlist_entries=donor.get(app['package'], [])))
    report = dict(schema=1, framework_permission_count=len(framework), apps=apps,
        framework_manifest_sha256=hashlib.sha256(args.framework_manifest.read_bytes()).hexdigest(),
        provenance_sha256=hashlib.sha256(args.provenance.read_bytes()).hexdigest(),
        donor_sources=sources, grant_simulation=False, installed=False)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({a['name']: dict(framework_defined=len(a['framework_defined']),
          absent_from_framework=a['absent_from_framework']) for a in apps}, indent=2))


if __name__ == '__main__':
    main()

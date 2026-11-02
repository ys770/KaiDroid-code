"""Extract and inventory Android init configuration from raw ext images offline.

Uses debugfs without mounting or executing firmware. The parser inventories
service declarations/imports; it does not evaluate Android init triggers.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from audit_vendor_dependencies import inventory
from probe_android_filesystems import query


def logical_lines(text):
    pending, start = '', 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        continued = raw.rstrip().endswith('\\')
        pending += raw.rstrip()[:-1] + ' ' if continued else raw
        if not continued:
            yield start, pending
            pending = ''
    if pending:
        raise ValueError('Unterminated init line continuation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sources = []
    # Root-level init files are distinct from /system/etc/init on SAR devices.
    for line in query(args.system, 'ls -p /').decode().splitlines():
        fields = line.split('/')
        if len(fields) >= 8 and fields[5].endswith('.rc') and int(fields[2], 8) & 0o170000 == 0o100000:
            sources.append(('system', '/' + fields[5]))
    for kind, root in [('system', '/system/etc/init'), ('vendor', '/etc/init')]:
        for item in inventory(getattr(args, kind), [root]):
            if item['path'].endswith('.rc') and int(item['mode'], 8) & 0o170000 == 0o100000:
                sources.append((kind, item['path']))
    files, services, imports, system_paths = [], [], [], {}
    for kind, path in sorted(set(sources)):
        data = query(getattr(args, kind), 'cat ' + path)
        target = args.output / kind / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        source = kind + ':' + path
        files.append({'source': source, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        current = None
        for number, raw in logical_lines(data.decode(errors='replace')):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split()
            if not raw[0].isspace():
                current = None
                if fields[0] == 'service' and len(fields) >= 3:
                    current = {'source': source, 'line': number, 'name': fields[1],
                               'executable': fields[2], 'arguments': fields[3:], 'options': []}
                    services.append(current)
                elif fields[0] == 'import' and len(fields) >= 2:
                    imports.append({'source': source, 'line': number, 'path': fields[1]})
            elif current is not None:
                current['options'].append(line)
            for reference in re.findall(r'/system/[^\s"\';]+', line):
                system_paths.setdefault(reference, []).append({'source': source, 'line': number})
    executables = {}
    for executable in sorted({service['executable'] for service in services}):
        # This alias is captured explicitly, not presumed for other images.
        resolved = executable
        if resolved.startswith('/system/vendor/'):
            stat = query(args.system, 'stat /system/vendor').decode()
            if 'Fast link dest: "/vendor"' not in stat:
                raise ValueError('Expected captured /system/vendor -> /vendor alias')
            resolved = resolved.replace('/system/vendor/', '/vendor/', 1)
        if resolved.startswith('/vendor/'):
            kind, image_path = 'vendor', resolved[len('/vendor'):]
        elif resolved.startswith('/system/'):
            kind, image_path = 'system', resolved
        else:
            executables[executable] = {'status': 'not inspected', 'resolved': resolved}
            continue
        if not re.fullmatch(r'/[A-Za-z0-9_./+\-]+', image_path):
            executables[executable] = {'status': 'not inspected', 'resolved': resolved,
                                       'reason': 'Property expansion or unsupported path syntax'}
            continue
        try:
            stat = query(getattr(args, kind), 'stat ' + image_path).decode()
            executables[executable] = {'status': 'present', 'source': kind + ':' + image_path,
                                       'type': re.search(r'Type:\s+(\S+)', stat).group(1)}
        except RuntimeError as error:
            executables[executable] = {'status': 'lookup failed', 'source': kind + ':' + image_path,
                                       'error': str(error)}
    names = {}
    for service in services:
        names.setdefault(service['name'], []).append(service['source'])
    result = {'files': files, 'services': services, 'imports': imports, 'executables': executables,
              'duplicate_service_names': {name: sources for name, sources in names.items() if len(sources) > 1},
              'system_path_references': system_paths,
              'scope': 'Static declarations and filesystem lookups only. Property expansion, import/trigger order, executable symlink targets and runtime availability are not evaluated.'}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'files': len(files), 'services': len(services), 'imports': len(imports),
                      'system_paths': len(system_paths),
                      'vendor_services_using_system_path': sum(1 for s in services
                          if s['source'].startswith('vendor:') and s['executable'].startswith('/system/'))}, indent=2))


if __name__ == '__main__':
    main()

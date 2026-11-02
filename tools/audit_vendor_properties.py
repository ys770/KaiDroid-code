"""Compare static vendor setprop names with captured/upstream context candidates.

Reads firmware with debugfs; never executes scripts. Source-context matching is
a diagnostic approximation, not Android's compiled property-info trie.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from audit_vendor_dependencies import inventory
from probe_android_filesystems import query


def contexts(text, source):
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith('#') or not fields[1].startswith('u:object_r:'):
            continue
        result.append({'pattern': fields[0], 'context': fields[1],
                       'exact': len(fields) >= 3 and fields[2] == 'exact',
                       'source': source, 'line': number})
    return result


def match(name, entries):
    candidates = [e for e in entries if e['pattern'] == '*' or
                  (name == e['pattern'] if e['exact'] else name.startswith(e['pattern']))]
    if not candidates:
        return {'context': 'u:object_r:default_prop:s0', 'reason': 'no matching context entry'}
    best = max((e['exact'], len(e['pattern']) if e['pattern'] != '*' else 0) for e in candidates)
    winners = [e for e in candidates if (e['exact'], len(e['pattern']) if e['pattern'] != '*' else 0) == best]
    labels = sorted({e['context'] for e in winners})
    return {'context': labels[0] if len(labels) == 1 else None, 'candidates': winners,
            'ambiguous': len(labels) != 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    vendor_source = parser.add_mutually_exclusive_group(required=True)
    vendor_source.add_argument('--vendor', type=Path)
    vendor_source.add_argument('--vendor-tree', type=Path,
                               help='Extracted vendor tree with bin scripts and etc/selinux contexts')
    parser.add_argument('--init-root', type=Path, required=True)
    parser.add_argument('--stock-platform-contexts', type=Path, required=True)
    parser.add_argument('--new-platform-contexts', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    vendor_data = ((args.vendor_tree / 'etc/selinux/vendor_property_contexts').read_bytes()
                   if args.vendor_tree else query(args.vendor, 'cat /etc/selinux/vendor_property_contexts'))
    vendor_contexts = contexts(vendor_data.decode(), 'vendor')
    stock = contexts(args.stock_platform_contexts.read_text(), 'stock-platform') + vendor_contexts
    new = [entry for path in args.new_platform_contexts for entry in contexts(path.read_text(), str(path))] + vendor_contexts
    sources = [(str(p.relative_to(args.init_root)), p.read_bytes()) for p in sorted(args.init_root.rglob('*.rc'))]
    items = ([{'path': '/' + p.relative_to(args.vendor_tree).as_posix(), 'mode': '100644'}
              for p in sorted((args.vendor_tree / 'bin').rglob('*.sh')) if p.is_file()]
             if args.vendor_tree else inventory(args.vendor, ['/bin']))
    for item in items:
        if item['path'].endswith('.sh') and int(item['mode'], 8) & 0o170000 == 0o100000:
            data = ((args.vendor_tree / item['path'].lstrip('/')).read_bytes()
                    if args.vendor_tree else query(args.vendor, 'cat ' + item['path']))
            dest = args.output / 'scripts' / item['path'].lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            sources.append(('vendor:' + item['path'], data))
    names, unresolved = {}, []
    for source, data in sources:
        for number, line in enumerate(data.decode(errors='replace').splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            # Static name only. Values, variables, control dispatch and execution paths are not evaluated.
            found = re.search(r'(?:^|[;\s])setprop\s+([^\s;]+)', line)
            if not found:
                continue
            name = found.group(1).strip('"\'')
            location = {'source': source, 'line': number}
            if re.fullmatch(r'[A-Za-z0-9_.-]+', name) and not name.startswith('ctl.'):
                names.setdefault(name, []).append(location)
            else:
                unresolved.append(location | {'name_expression': name})
    rows = [{'name': name, 'writes': locations, 'stock': match(name, stock), 'new': match(name, new)}
            for name, locations in sorted(names.items())]
    result = {'properties': rows, 'unresolved': unresolved,
              'source_hashes': {name: hashlib.sha256(data).hexdigest() for name, data in sources},
              'context_hashes': {'vendor': hashlib.sha256(vendor_data).hexdigest(),
                                'stock': hashlib.sha256(args.stock_platform_contexts.read_bytes()).hexdigest(),
                                'new_sources': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                                for p in args.new_platform_contexts}},
              'scope': 'Static vendor rc/shell setprop names and raw context-source candidates. Not executed branches, native writes, compiled trie resolution, or SELinux permission validation.'}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'sources': len(sources), 'static_properties': len(rows),
                      'unresolved_writes': len(unresolved),
                      'new_default': [r['name'] for r in rows if r['new']['context'] == 'u:object_r:default_prop:s0'],
                      'changed_labels': sum(r['stock']['context'] != r['new']['context'] for r in rows)}, indent=2))


if __name__ == '__main__':
    main()

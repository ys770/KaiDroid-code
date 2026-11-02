"""Offline ARM32 IMS dependency-name graph; never claims linker namespace access."""
import argparse
import hashlib
from io import BytesIO
import json
import stat
from pathlib import Path
import zipfile
from elftools.elf.elffile import ELFFile
from dissect.extfs import ExtFS


def describe(data, symbols=False):
    elf = ELFFile(BytesIO(data))
    if elf.elfclass != 32 or elf['e_machine'] != 'EM_ARM':
        raise ValueError('Expected ARM32 ELF')
    result = {'sha256': hashlib.sha256(data).hexdigest(),
            'needed': [t.needed for t in elf.get_section_by_name('.dynamic').iter_tags()
                       if t.entry.d_tag == 'DT_NEEDED']}
    if symbols:
        dynamic = list(elf.get_section_by_name('.dynsym').iter_symbols())
        result['strong_imports'] = sorted({s.name for s in dynamic if s.name
            and s['st_shndx'] == 'SHN_UNDEF' and s['st_info']['bind'] == 'STB_GLOBAL'})
        result['exports'] = sorted({s.name for s in dynamic if s.name
            and s['st_shndx'] != 'SHN_UNDEF'
            and s['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK')
            and s['st_other']['visibility'] in ('STV_DEFAULT', 'STV_PROTECTED')})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--symbols', action='store_true')
    args = parser.parse_args()
    prefixes = ['/system/lib/', '/system/apex/com.android.runtime/lib/bionic/',
                '/system/apex/com.android.runtime/lib/',
                '/system/apex/com.android.art.release/lib/']
    with args.system.open('rb') as stream, zipfile.ZipFile(args.apk) as apk:
        fs = ExtFS(stream)
        for apex in fs.get('/system/apex').iterdir():
            if apex.filename not in ('.', '..') and apex.filetype == stat.S_IFDIR:
                path = '/system/apex/' + apex.filename + '/lib/'
                if path not in prefixes:
                    prefixes.append(path)
        bundled = {Path(n).name: n for n in apk.namelist()
                   if n.startswith('lib/armeabi-v7a/') and n.endswith('.so')}
        pending = list(bundled)
        graph = {}
        while pending:
            name = pending.pop()
            if name in graph:
                continue
            if name in bundled:
                data = apk.read(bundled[name])
                row = describe(data, args.symbols)
                row['source'] = bundled[name]
            else:
                candidates = []
                aliases = []
                for prefix in prefixes:
                    try:
                        node = fs.get(prefix + name)
                        if node.filetype == stat.S_IFLNK:
                            aliases.append({'path': prefix + name, 'target': node.link})
                            continue
                        with node.open() as library:
                            data = library.read()
                        candidates.append({'path': prefix + name, **describe(data, args.symbols)})
                    except FileNotFoundError:
                        continue
                row = {'candidates': candidates, 'symlinks': aliases,
                       'needed': sorted({d for c in candidates for d in c['needed']})}
            graph[name] = row
            pending.extend(row['needed'])
    result = {'graph': graph,
              'unresolved_names': sorted(n for n, r in graph.items()
                                         if r.get('candidates') == []),
              'limitations': ['Candidate paths are not proven accessible to the app linker namespace',
                              'No symbol/version or runtime initialization compatibility claim',
                              'Bundled libraries take precedence only for this hypothetical graph'],
              'installed': False}
    if args.symbols:
        variants = [v for row in graph.values()
                    for v in row.get('candidates', [row])]
        all_exports = {n for v in variants for n in v['exports']}
        result['bundled_imports_absent_from_entire_candidate_graph'] = {
            name: sorted(set(row['strong_imports']) - all_exports)
            for name, row in graph.items() if 'source' in row
            and set(row['strong_imports']) - all_exports}
        result['limitations'].append('Symbol names ignore versions and runtime/global linker providers; no ABI acceptance')
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
    print(json.dumps({'nodes': len(graph), 'unresolved_names': result['unresolved_names']}))


if __name__ == '__main__':
    main()

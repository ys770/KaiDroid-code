"""Measure separately mapped library paths with the same basename in saved smaps.

Name duplication is not proof of identical bytes, interchangeable ABI, or savings.
PSS and logical SwapPss are kept separate; no per-process RSS sum is produced.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
from summarize_memory_maps import HEADER, summarize


def inspect(path):
    raw = path.read_bytes()
    text = raw.decode()
    summarize(text)  # Existing complete-smaps validation.
    libraries = {}
    current = None
    for line in text.splitlines():
        header = HEADER.fullmatch(line)
        if header:
            current = header[4] if header[4] and header[4].endswith('.so') else None
            if current:
                libraries.setdefault(current, dict(mappings=0, Pss_KiB=0, SwapPss_KiB=0))['mappings'] += 1
        elif current:
            parts = line.split()
            if len(parts) == 3 and parts[0] in ('Pss:', 'SwapPss:') and parts[2] == 'kB':
                libraries[current][parts[0][:-1]+'_KiB'] += int(parts[1])
    by_name = defaultdict(list)
    for name, metrics in libraries.items():
        by_name[PurePosixPath(name).name].append(dict(path=name, **metrics))
    duplicates = [dict(basename=name, paths=paths) for name, paths in sorted(by_name.items()) if len(paths) > 1]
    all_paths = [row for group in duplicates for row in group['paths']]
    vndk_paths = [row for row in all_paths if row['path'].startswith('/apex/com.android.vndk.v29/')]
    def totals(rows):
        return {key: sum(row[key] for row in rows) for key in ('mappings', 'Pss_KiB', 'SwapPss_KiB')}
    return dict(source=str(path), source_sha256=hashlib.sha256(raw).hexdigest(),
                unique_library_paths=len(libraries), duplicate_basename_count=len(duplicates),
                duplicates=duplicates, all_duplicate_paths=totals(all_paths),
                vndk29_duplicate_paths=totals(vndk_paths))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--smaps', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    report = dict(processes=[inspect(path) for path in a.smaps],
                  scope='Sequential per-process mapped-library attribution only. Shared pages, namespace isolation, ABI differences, anonymous allocator and kernel costs prevent interpreting these figures as savings.')
    with a.output.open('x') as f:
        f.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps([dict(source=r['source'], duplicate_basenames=r['duplicate_basename_count'],
                           vndk29=r['vndk29_duplicate_paths']) for r in report['processes']]))


if __name__ == '__main__':
    main()

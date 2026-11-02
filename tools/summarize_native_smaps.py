"""Summarize captured Linux smaps by allocator label, without equating usage to overhead."""
import argparse
import json
import re
from pathlib import Path


def summarize(text):
    groups = {}
    current = None
    for line in text.splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+\s', line):
            label = ('scudo' if 'scudo:' in line else
                     'jemalloc' if 'jemalloc' in line else
                     'libc_malloc' if '[anon:libc_malloc]' in line else 'other')
            current = groups.setdefault(label, {'mappings': 0})
            current['mappings'] += 1
        elif current is not None:
            match = re.fullmatch(r'(Rss|Pss|Private_Dirty|Swap|SwapPss):\s*(\d+) kB', line)
            if match:
                key, value = match.groups()
                current[key + '_KiB'] = current.get(key + '_KiB', 0) + int(value)
    if not groups or not any('Pss_KiB' in group for group in groups.values()):
        raise ValueError('No smaps PSS records; reject empty, maps-only, or error output')
    return {'groups': groups, 'scope': 'One process snapshot. Allocator mappings include live allocations; these totals do not measure allocator overhead or potential savings. Missing allocator labels do not prove allocator absence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('smaps', type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.smaps.read_text()), indent=2))


if __name__ == '__main__':
    main()

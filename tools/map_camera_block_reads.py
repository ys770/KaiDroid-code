"""Map traced eMMC read request sectors onto a captured same-handset partition map.

Read requests are not unique bytes or proof of completed NAND transfers.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
for name in ('trace', 'partition-map', 'processor', 'output'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
raw = a.partition_map.read_bytes()
text = raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig')
names = {device: name for name, device in re.findall(r'\s(\S+) -> /dev/block/(mmcblk0p\d+)', text)}
parts = []
for device, start, size in re.findall(r'PARTITION (mmcblk0p\d+)\s+(\d+)\s+(\d+)', text):
    parts.append(dict(device=device, name=names.get(device, device), start=int(start), end=int(start)+int(size)))
if not parts:
    raise ValueError('No partition extents found')
parts.sort(key=lambda row: row['start'])
if any(x['end'] > y['start'] for x, y in zip(parts, parts[1:])):
    raise ValueError('Overlapping partitions')
sql = """select extract_arg(arg_set_id,'sector') as sector,
extract_arg(arg_set_id,'nr_sector') as sectors
from ftrace_event where name='block_rq_issue'
and extract_arg(arg_set_id,'dev')=45824
and extract_arg(arg_set_id,'rwbs') glob 'R*'"""
r = subprocess.run([sys.executable, str(a.processor), 'query', str(a.trace), sql],
                   capture_output=True, text=True, check=True, timeout=120)
requests = list(csv.DictReader(io.StringIO(r.stdout)))
totals = {}
unmapped = 0
for row in requests:
    start, length = int(row['sector']), int(row['sectors'])
    end = start + length
    mapped = 0
    for part in parts:
        lo, hi = max(start, part['start']), min(end, part['end'])
        if hi <= lo:
            continue
        value = totals.setdefault(part['name'], dict(request_overlaps=0, requested_bytes=0, ranges=[]))
        value['request_overlaps'] += 1
        value['requested_bytes'] += (hi-lo)*512
        value['ranges'].append((lo, hi))
        mapped += hi-lo
    unmapped += (length-mapped)*512
for value in totals.values():
    merged = []
    for lo, hi in sorted(value.pop('ranges')):
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(hi, merged[-1][1])
        else:
            merged.append([lo, hi])
    unique = sum(hi-lo for lo, hi in merged)*512
    value['unique_requested_sector_bytes'] = unique
    value['request_to_unique_ratio'] = value['requested_bytes']/unique if unique else None
report = dict(trace_sha256=hashlib.sha256(a.trace.read_bytes()).hexdigest(),
              map_sha256=hashlib.sha256(raw).hexdigest(), read_requests=len(requests),
              partitions=totals, unmapped_read_bytes=unmapped,
              limitations=['Hard-pinned trace dev45824 denotes this handset mmcblk0 (179:0); not a generic dev_t decoder.',
                           'Union measures unique requested sectors, not unique file data or completed physical transfers.',
                           'Partition attribution does not identify files; captures must belong to the same handset layout.',
                           'Tracing itself adds load.'])
with a.output.open('x') as out:
    json.dump(report, out, indent=2)
    out.write('\n')
print(json.dumps(report))

"""Compare two retained gfxinfo/vmstat captures; never operates a device."""
import argparse
import csv
import json
import re
import statistics
from pathlib import Path


def frames(text):
    result = {}
    process = None
    columns = None
    for line in text.splitlines():
        match = re.match(r'\*\* Graphics info for pid \d+ \[(.+)\] \*\*', line)
        if match:
            process = match[1]
        if line.startswith('Flags,IntendedVsync,'):
            columns = next(csv.reader([line]))
        elif columns and re.match(r'^\d+,', line):
            values = next(csv.reader([line]))
            row = {k: int(v) for k, v in zip(columns, values) if k and v}
            if row['Flags'] == 0 and row['FrameCompleted'] > row['IntendedVsync']:
                result[(process, row['IntendedVsync'])] = row
    return result


def analyze(before, after):
    old, new = frames(before), frames(after)
    report = {'new_frames': {}, 'vm_delta': {}}
    for process in sorted({k[0] for k in new}):
        rows = [v for k, v in new.items() if k not in old and k[0] == process]
        def stats(start, end):
            values = sorted((v[end] - v[start]) / 1e6 for v in rows)
            return {'median_ms': statistics.median(values),
                    'p90_ms': values[min(len(values)-1, int(len(values)*.9))],
                    'max_ms': max(values)} if values else None
        report['new_frames'][process] = {
            'count': len(rows),
            'intended_to_complete': stats('IntendedVsync', 'FrameCompleted'),
            'intended_to_input_start': stats('IntendedVsync', 'HandleInputStart'),
            'issue_to_swap': stats('IssueDrawCommandsStart', 'SwapBuffers'),
            'swap_to_complete': stats('SwapBuffers', 'FrameCompleted')}
    for key in ('pgfault', 'pgmajfault', 'pswpin', 'pswpout',
                'pgscan_kswapd', 'pgsteal_kswapd'):
        a = re.search(r'^' + key + r' (\d+)$', before, re.M)
        b = re.search(r'^' + key + r' (\d+)$', after, re.M)
        if a and b:
            report['vm_delta'][key] = int(b[1]) - int(a[1])
    report['limits'] = ('Bounded gfxinfo ring buffers, potentially incomplete; '
                        'framework timestamps are not physical panel presentation. '
                        'VM counters are system-wide and include capture overhead.')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before', type=Path)
    p.add_argument('after', type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    report = analyze(a.before.read_text(), a.after.read_text())
    with a.output.open('x') as f:
        f.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))

"""Summarize synchronous atrace spans, retaining overflow and pairing limits."""
import argparse
import collections
import json
import re
import statistics
from pathlib import Path


def summarize(text):
    stacks = collections.defaultdict(list)
    durations = collections.defaultdict(list)
    unmatched = 0
    bounds = []
    pattern = re.compile(r'^\s*(.+)-(\d+)\s+\([^)]*\).*?\s(\d+\.\d+): tracing_mark_write: ([BE])(?:\|(.*))?$')
    for line in text.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        thread, tid, stamp, kind, payload = m.groups()
        stamp = float(stamp)
        bounds.append(stamp)
        if kind == 'B':
            pid, name = payload.split('|', 1)
            stacks[tid].append((stamp, pid, thread, name))
        elif stacks[tid]:
            start, pid, thread, name = stacks[tid].pop()
            durations[(pid, tid, thread, name)].append((stamp - start) * 1000)
        else:
            unmatched += 1
    rows = []
    for (pid, tid, thread, name), values in durations.items():
        rows.append(dict(pid=pid, tid=tid, thread=thread, name=name,
                         count=len(values), median_ms=statistics.median(values),
                         max_ms=max(values), total_ms=sum(values)))
    header = re.search(r'entries-in-buffer/entries-written: (\d+)/(\d+)', text)
    return dict(buffer_entries=int(header[1]) if header else None,
                written_entries=int(header[2]) if header else None,
                overflow=bool(header and header[1] != header[2]),
                first_marker=min(bounds) if bounds else None,
                last_marker=max(bounds) if bounds else None,
                unmatched_ends=unmatched,
                unfinished_spans=sum(map(len, stacks.values())),
                spans=sorted(rows, key=lambda r: r['total_ms'], reverse=True),
                limits='Nested inclusive wall times; not CPU time or causal attribution. Boundary spans excluded.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('trace', type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    report = summarize(a.trace.read_text(errors='replace'))
    with a.output.open('x') as f:
        f.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'spans'}))
    print(json.dumps(report['spans'][:15], indent=2))

"""Offline per-process startup counter deltas, bound to boot/PID/start time."""
import argparse
import json
from pathlib import Path


def parse_processes(lines):
    result = []
    current = None
    for line in lines:
        if line.startswith('PROCESS '):
            _, name, pid = line.split()
            current = {'name': name, 'pid': int(pid)}
            result.append(current)
        elif current is not None and line.startswith(str(current['pid']) + ' ('):
            # comm may contain spaces or parentheses; fields after its final ')' are fixed.
            fields = line.rsplit(')', 1)[1].split()
            current.update(start_ticks=int(fields[19]), minor_faults=int(fields[7]),
                           major_faults=int(fields[9]), user_ticks=int(fields[11]),
                           system_ticks=int(fields[12]))
        elif current is not None and ':' in line:
            key, value = line.split(':', 1)
            if key in ('read_bytes', 'write_bytes', 'VmRSS', 'VmSwap'):
                current[key] = int(value.split()[0])
    return result


def summarize(path):
    records = [json.loads(x) for x in path.read_text().splitlines() if x]
    identities, previous, intervals, snapshots = set(), {}, [], []
    counters = ('minor_faults', 'major_faults', 'user_ticks', 'system_ticks',
                'read_bytes', 'write_bytes')
    skipped = 0
    for record in records:
        output = record.get('output', [])
        if len(output) < 4 or 'process_io' not in record:
            continue
        identities.add(tuple(output[:2]))
        uptime = float(output[3].split()[0])
        for process in parse_processes(record['process_io']):
            if 'start_ticks' not in process or not all(k in process for k in counters):
                skipped += 1
                continue
            process['uptime'] = uptime
            snapshots.append(process)
            key = (process['name'], process['pid'], process['start_ticks'])
            before = previous.get(key)
            if before:
                seconds = uptime - before['uptime']
                delta = {k: process[k] - before[k] for k in counters}
                if seconds <= 0 or any(v < 0 for v in delta.values()):
                    raise ValueError('Invalid same-process counter interval')
                intervals.append({'name': key[0], 'pid': key[1], 'start_ticks': key[2],
                                  'start_uptime': before['uptime'], 'end_uptime': uptime,
                                  'delta': delta, 'per_second': {
                                      k: round(v / seconds, 3) for k, v in delta.items()}})
            previous[key] = process
    if len(identities) != 1 or not intervals:
        raise ValueError('Require one boot identity and repeated process samples')
    image, boot = next(iter(identities))
    return {'image': image, 'boot_id': boot, 'snapshots': snapshots,
            'intervals': intervals, 'incomplete_process_samples': skipped,
            'scope': 'Sequential proc reads, not atomic snapshots. Rates use host shell uptime per sample. PID plus start time prevents joining process lifetimes. Kernel read_bytes is attributed I/O, not a filesystem trace; major faults can include swap. CPU counters remain ticks, without assuming clock frequency. Data cannot alone establish the cause of an ANR.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('samples', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.samples)
    with args.output.open('x', encoding='utf-8') as dest:
        json.dump(result, dest, indent=2)
        dest.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('snapshots', 'intervals')}))

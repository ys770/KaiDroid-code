"""Summarize same-boot pressure samples offline; counters are not causal proof."""
import argparse
import json
from pathlib import Path


def summarize(path):
    records = [json.loads(line) for line in path.read_text().splitlines() if line]
    samples = []
    identities = set()
    counters = ('pswpin', 'pswpout', 'pgmajfault', 'pgscan_direct', 'pgsteal_direct')
    for record in records:
        output = record.get('output', [])
        if not record.get('pressure') or len(output) < 4:
            continue
        identities.add(tuple(output[:2]))
        values = {}
        for line in record['pressure']:
            fields = line.split()
            if fields and (fields[0].rstrip(':') in counters or
                           fields[0] in ('MemAvailable:', 'SwapFree:')):
                values[fields[0].rstrip(':')] = int(fields[1])
        samples.append({'uptime': float(output[3].split()[0]),
                        'observer_elapsed': record['elapsed'], **values})
    if len(identities) != 1 or len(samples) < 2:
        raise ValueError('Require at least two pressure samples from exactly one boot')
    intervals = []
    for before, after in zip(samples, samples[1:]):
        seconds = after['uptime'] - before['uptime']
        if seconds <= 0:
            raise ValueError('Sample uptime must increase')
        delta = {key: after[key] - before[key] for key in counters
                 if key in before and key in after}
        if any(value < 0 for value in delta.values()):
            raise ValueError('Cumulative counter decreased')
        intervals.append({'start_uptime': before['uptime'], 'end_uptime': after['uptime'],
                          'seconds': round(seconds, 3), 'delta': delta,
                          'per_second': {key: round(value / seconds, 3)
                                         for key, value in delta.items()}})
    image, boot = next(iter(identities))
    return {'image': image, 'boot_id': boot, 'samples': samples, 'intervals': intervals,
            'minimum_mem_available_kib': min(s['MemAvailable'] for s in samples),
            'minimum_swap_free_kib': min(s['SwapFree'] for s in samples),
            'scope': 'Only the ADB-observed interval; early boot is missing. Swap counters count pages, not bytes. Major faults include file-backed faults. Correlation does not establish ANR or Bluetooth failure causality.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('samples', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = summarize(args.samples)
    with args.output.open('x', encoding='utf-8') as dest:
        json.dump(result, dest, indent=2)
        dest.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('samples', 'intervals')}))

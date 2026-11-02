"""Summarize a completed lightweight observation without accessing a device."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def summarize(directory):
    samples_path = directory / 'samples.jsonl'
    samples = [json.loads(line) for line in samples_path.read_text().splitlines() if line]
    identified = [s for s in samples if len(s.get('output', [])) >= 2]
    identities = {(s['output'][0].strip(), s['output'][1].strip()) for s in identified}
    if len(identities) != 1:
        raise ValueError('Require exactly one observed image/boot identity')
    image, boot = next(iter(identities))
    completed = [s for s in identified if len(s['output']) >= 3 and s['output'][2].strip() == '1']
    logs = sorted(directory.glob('logcat*.txt'))
    lines = set()
    for path in logs:
        lines.update(path.read_text(errors='replace').splitlines())
    events = {}
    for package in ('com.android.systemui', 'com.android.bluetooth'):
        events[package] = {
            tag: sorted(line for line in lines if re.search(r'\b' + tag + r'\s*:', line)
                        and re.search(r'[,\[]' + re.escape(package) + r'[,\]]', line))
            for tag in ('am_anr', 'am_crash', 'am_proc_died')
        }
    return {
        'image': image, 'boot_id': boot, 'sample_count': len(samples),
        'first_identity_elapsed': identified[0]['elapsed'],
        'first_boot_completed_elapsed': completed[0]['elapsed'] if completed else None,
        'last_sample_elapsed': samples[-1]['elapsed'],
        'logcat_segments': len(logs), 'events': events,
        'atomic_commit_error_lines': sum('MSMFB_ATOMIC_COMMIT' in line for line in lines),
        'captures': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [samples_path] + logs},
        'scope': 'Observer-relative times, not exact power-on latency. Full-line deduplication across log segments. Missing events do not prove reliable startup or hardware support. Caller must verify observer is terminal before using as final evidence.'
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.directory)
    with args.output.open('x', encoding='utf-8') as dest:
        json.dump(result, dest, indent=2)
        dest.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('captures', 'events')}, indent=2))

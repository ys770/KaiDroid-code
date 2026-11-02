"""Extract bounded display evidence from a saved image47 trial kernel log."""
import hashlib
import json
from pathlib import Path
import re


def audit(path):
    raw = path.read_bytes()
    lines = raw.decode('utf-8-sig').splitlines()
    expected_boot = '00000000-0000-0000-0000-000000000010'
    if lines[0].strip() != expected_boot:
        raise ValueError('Unexpected trial boot')
    entries = []
    for line in lines[1:]:
        match = re.match(r'\[\s*(\d+\.\d+)\]\s*(.*)', line)
        if match:
            entries.append((float(match[1]), match[2]))
    if not entries or min(t for t, _ in entries) > 2239 or max(t for t, _ in entries) < 2270:
        raise ValueError('Log does not cover submission and restoration')
    windows = {}
    for name, lo, hi in [('submit', 2239, 2239.1), ('restore', 2269, 2269.13)]:
        selected = [{'uptime': t, 'message': s} for t, s in entries
                    if lo <= t <= hi and re.search(r'fb|panel|spi', s, re.I)]
        if not any('sending event=11 for fb1' in x['message'] for x in selected):
            raise ValueError(f'Missing fb1 check event in {name}')
        windows[name] = selected
    return {
        'capture': path.as_posix(), 'sha256': hashlib.sha256(raw).hexdigest(),
        'boot_id': expected_boot, 'image': 47,
        'log_range_uptime': [min(t for t, _ in entries), max(t for t, _ in entries)],
        'windows': windows,
        'conclusion': 'Submission and restoration reached the fb1 mode-check panel event handler.',
        'limitations': [
            'The invalid operation diagnostic is retained; its exact branch cause is unresolved.',
            'Panel check events do not establish SPI pixel transmission or physical output.',
            'Missing pan/transfer log messages do not prove those functions were not called.',
            'No new phone operation or physical observation was performed by this audit.'
        ]
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = audit(args.capture)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(result['conclusion'])

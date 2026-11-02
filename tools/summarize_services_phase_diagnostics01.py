"""Validate phase-only diagnostic records; never infer capture completeness or RAM savings."""
import argparse
import json
from pathlib import Path

MARKER = 'KV_SERVICES_PHASE_V1'
SOURCE = 'services55-oat125818a8'
NUMERIC = ('id', 'id_valid', 'start_ns', 'end_ns', 'decision', 'decision_ns', 'opened',
           'open_ns', 'add_attempted', 'added', 'add_ns', 'fallback', 'fallback_ns',
           'dex_count', 'dex_empty', 'phase_complete')
FLAGS = ('id_valid', 'decision', 'opened', 'add_attempted', 'added', 'fallback',
         'dex_empty', 'phase_complete')


def analyze(text):
    rows = []
    ids = set()
    for line in text.splitlines():
        if MARKER not in line:
            continue
        if line.count(MARKER) != 1:
            raise ValueError('Ambiguous marker')
        pairs = [piece.split('=', 1) for piece in line.split(MARKER, 1)[1].split()]
        if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
            raise ValueError('Incomplete/duplicate record fields')
        row = dict(pairs)
        if set(row) != {'source', *NUMERIC} or row['source'] != SOURCE:
            raise ValueError('Record schema or source token differs')
        for key in NUMERIC:
            if not row[key].isascii() or not row[key].isdigit():
                raise ValueError('Unsigned decimal field required')
            row[key] = int(row[key])
            if row[key] > (1 << 64) - 1:
                raise ValueError('Field exceeds uint64')
        if any(row[key] not in (0, 1) for key in FLAGS):
            raise ValueError('Invalid Boolean flag')
        if not row['id_valid'] or row['id'] >= (1 << 32) - 1 or row['id'] in ids:
            raise ValueError('ID exhausted/contended, duplicate, or mixed process logs')
        ids.add(row['id'])
        if not row['phase_complete'] or row['end_ns'] < row['start_ns']:
            raise ValueError('Incomplete phase or invalid clock order')
        if (row['opened'] and not row['decision']) or (row['add_attempted'] and not row['opened']) or (row['added'] and not row['add_attempted']) or row['fallback'] == row['added']:
            raise ValueError('Impossible branch combination')
        for flag, timing in [('decision', 'open_ns'), ('add_attempted', 'add_ns'), ('fallback', 'fallback_ns')]:
            if not row[flag] and row[timing]:
                raise ValueError('Time attributed to an unexecuted phase')
        row['elapsed_ns'] = row['end_ns'] - row['start_ns']
        if sum(row[key] for key in ('decision_ns', 'open_ns', 'add_ns', 'fallback_ns')) > row['elapsed_ns']:
            raise ValueError('Phase times exceed observation interval')
        if row['dex_empty'] != (row['dex_count'] == 0):
            raise ValueError('DEX result flags disagree')
        rows.append(row)
    if not rows:
        raise ValueError('No diagnostic records; disabled or incomplete logs are not a zero-cost result')
    return dict(classification='phase_records_only', records=rows,
                capture_completeness_proven=False, source_binary_binding_proven=False,
                allocation_attribution=False, savings_proven=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(json.dumps(analyze(args.log.read_text()), indent=2) + '\n', encoding='utf-8')

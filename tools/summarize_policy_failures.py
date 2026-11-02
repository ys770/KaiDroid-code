"""Summarize secilc neverallow diagnostics without changing any policy."""
import argparse
import collections
import json
import re
from pathlib import Path


def summarize(text):
    failures, current, pending = [], None, None
    for line in text.splitlines():
        if line.startswith('neverallow check failed at '):
            current = {'location': line.removeprefix('neverallow check failed at '), 'allows': []}
            failures.append(current)
            pending = None
        elif current is not None and line.strip().startswith('(neverallow '):
            current['rule'] = line.strip()
        elif current is not None and line.strip().startswith('allow at '):
            pending = {'location': line.strip().removeprefix('allow at ')}
            current['allows'].append(pending)
        elif pending is not None and line.strip().startswith('(allow '):
            pending['rule'] = line.strip()
    if any('rule' not in failure or any('rule' not in allow for allow in failure['allows']) for failure in failures):
        raise ValueError('Incomplete or unsupported diagnostic format')
    classes = collections.Counter()
    pairs = collections.Counter()
    for failure in failures:
        for allow in failure['allows']:
            match = re.match(r'\(allow (\S+) (\S+) \((\S+) ', allow['rule'])
            if match:
                source, target, kind = match.groups()
                classes[kind] += 1
                pairs[(source, target, kind)] += 1
    return {'failures': failures, 'counts': {'neverallow_failures': len(failures),
             'allow_diagnostic_occurrences': sum(len(f['allows']) for f in failures),
             'allow_occurrences_by_class': dict(classes)},
            'recurring_pairs': [{'source': a, 'target': b, 'class': c, 'occurrences': n}
                               for (a, b, c), n in pairs.most_common()],
            'scope': 'Diagnostic grouping, not attribute expansion or proof of semantic equivalence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.log.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['counts'], indent=2))


if __name__ == '__main__':
    main()

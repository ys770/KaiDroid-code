"""Summarize the original terminal series without admitting failed partial arms."""
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import matched_memory56_contract as c
from summarize_matched_memory56 import compare


def describe(roots):
    result = compare(roots)  # Frozen checks include raw file closure and hashes.
    rows = []
    for root, checked in zip(roots, result['arms']):
        arm = json.loads((root / 'arm.json').read_text())
        rows.append({
            'slot': arm['slot'], 'image': arm['image'], 'boot': arm['boot'],
            'capture': str(root), 'arm_sha256': c.sha(root / 'arm.json'),
            'classification': checked['classification'],
            'failures': checked['failures'],
            'raw_file_count_verified': len(arm['raw_files_sha256']),
            'complete': arm['complete'],
            'accepted_measurement_ages': list(checked['measurements']),
            'partial_collector_directories_present': [
                name for name in ('census-180', 'maps-225', 'census-300', 'maps-345')
                if (root / name).is_dir()
            ] if not arm['complete'] else [],
            'partial_evidence_is_eligible': False,
        })
    # The frozen comparator skips its population comparison when any arm has
    # no measurements. Preserve its output and explicitly expose the first
    # pair's known mismatch rather than changing or hiding that behavior.
    first_pair_populations = {}
    for age in ('180', '300'):
        old, new = [a['measurements'][age]['population'] for a in result['arms'][:2]]
        first_pair_populations[age] = {
            'baseline_count': sum(old.values()), 'candidate_count': sum(new.values()),
            'equal': old == new,
            'candidate_only': sorted(set(new) - set(old)),
            'baseline_only': sorted(set(old) - set(new)),
        }
    return {
        'classification': result['classification'],
        'eligible_for_matched_comparison': result['eligible_for_matched_comparison'],
        'frozen_comparison_failures': result['comparison_failures'],
        'frozen_comparator_sha256': c.sha(Path(__file__).with_name('summarize_matched_memory56.py')),
        'arms': rows, 'first_pair_populations': first_pair_populations,
        'matched_replicate_summaries': result['matched_replicate_summaries'],
        'savings_proven': False, 'optimization_accepted': False,
        'causal_transport_root_cause_established': False,
        'limits': [
            'Failed arm 3 retains partial files; missing final identity/bindings/log completion cannot be reconstructed.',
            'Failed arm 4 ended before log start; it contributes no memory observation.',
            'First-pair population mismatch is a separate limitation even without the later transport failures.',
            'No replacement runs, provider filtering, protocol relaxation, or inferred optimization acceptance.',
            'Raw hash verification confirms retained bytes, not completion of a failed observation window.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    report = describe(args.arm)
    report['analyzer_sha256'] = c.sha(Path(__file__))
    c.dump(args.output, report)
    print(json.dumps({'classification': report['classification'], 'savings_proven': False}))

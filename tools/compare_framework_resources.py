"""Compare compiled framework resource identities without changing either input.

The reference may be an SDK android.jar or a built framework-res.apk. Results
only describe those exact tables, not a future build's assigned resource IDs.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def table(aapt, path):
    run = subprocess.run([str(aapt), 'dump', 'resources', str(path)], capture_output=True,
                         text=True, encoding="utf-8", check=True, timeout=60)
    by_id = {}
    by_name = {}
    for line in run.stdout.splitlines():
        match = re.search(r'spec resource (0x[0-9a-fA-F]+) ([^ :]+:[^ :]+):', line)
        if match:
            number, name = int(match[1], 16), match[2]
            if number in by_id and by_id[number] != name:
                raise ValueError('Conflicting resource table entries')
            if name in by_name and by_name[name] != number:
                raise ValueError('Duplicate resource name with different IDs')
            by_id[number] = name
            by_name[name] = number
    if not by_id:
        raise ValueError('No resource specifications parsed')
    return by_id, by_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aapt', required=True, type=Path)
    parser.add_argument('--donor', required=True, type=Path)
    parser.add_argument('--reference', required=True, type=Path)
    parser.add_argument('--contract', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text())
    donor_hash = hashlib.sha256(args.donor.read_bytes()).hexdigest()
    if donor_hash != contract['input_sha256']['framework-res.apk']:
        raise ValueError('Donor does not match resource contract')
    donor_ids, donor_names = table(args.aapt, args.donor)
    reference_ids, reference_names = table(args.aapt, args.reference)
    collisions = [(number, name, reference_ids[number]) for number, name in donor_ids.items()
                  if number in reference_ids and reference_ids[number] != name]
    moved = [name for name, number in donor_names.items()
             if name in reference_names and reference_names[name] != number]
    selected = []
    for name, value in contract['ids'].items():
        number = int(value, 16)
        full = 'android:id/' + name
        if donor_ids.get(number) != full:
            raise ValueError('Contract disagrees with donor table: ' + name)
        target = reference_names.get(full)
        selected.append({'name': full, 'donor_id': value,
                         'reference_name_at_donor_id': reference_ids.get(number),
                         'reference_id_for_same_name': None if target is None else f'0x{target:08x}',
                         'collision': number in reference_ids and reference_ids[number] != full})
    report = {'scope': __doc__, 'donor_sha256': donor_hash,
              'reference_sha256': hashlib.sha256(args.reference.read_bytes()).hexdigest(),
              'aapt_sha256': hashlib.sha256(args.aapt.read_bytes()).hexdigest(),
              'donor_entries': len(donor_ids), 'reference_entries': len(reference_ids),
              'same_numeric_id_different_name': len(collisions),
              'shared_names_with_different_ids': len(moved),
              'selected': selected,
              'interpretation': 'Do not copy numeric IDs. Requires target resource assignment and caller/resource remapping, or a proven alternative. No rewrite performed.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('donor_entries', 'reference_entries',
                      'same_numeric_id_different_name', 'shared_names_with_different_ids')}))
    print('Selected collisions:', sum(row['collision'] for row in selected), '/', len(selected))


if __name__ == '__main__':
    main()

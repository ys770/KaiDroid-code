"""Exact native12 prediction including the SDK virtual override's inherited flags."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from prepare_tcl_app_widgets_flags import BASE, ADDED, R, sha
from prepare_tcl_dialog_hiddenapi_candidate import rows, SIGNATURES
from audit_tcl_dialog_hiddenapi10 import GENERATOR, ENCODER_SOURCE

OVERRIDE = R+'->onCreateDrawableState(I)[I'
INHERITED = ['public-api', 'system-api', 'test-api', 'whitelist']
CSV = 'd1c91728e194307c40157dc10c9c0e72ff31804a83ab2c407adbb6195764dc15'


def expected_flags(name):
    return INHERITED if name == OVERRIDE else ['blacklist']


def predict(data):
    if sha(data) != BASE:
        raise ValueError('Require exact native11 CSV')
    old = rows(data)
    for owner in ('Landroid/view/View;', 'Landroid/widget/TextView;'):
        if old.get(owner+'->onCreateDrawableState(I)[I') != INHERITED:
            raise ValueError('Original SDK virtual method classifications differ')
    if ADDED & old.keys():
        raise ValueError('New widget APIs already exist')
    additions = [(name+','+','.join(expected_flags(name))).encode() for name in ADDED]
    result = b''.join(line+b'\n' for line in sorted(data.splitlines()+additions))
    if sha(result) != CSV:
        raise ValueError('Corrected full CSV prediction differs')
    return result


def validate(before, after):
    old, new = rows(before), rows(after)
    if (old.keys()-new.keys() or new.keys()-old.keys() != ADDED
            or any(new[n] != old[n] for n in old)
            or any(new[n] != expected_flags(n) for n in ADDED)):
        raise ValueError('CSV drift beyond seven blacklist members and one exact inherited override')
    if after != predict(before):
        raise ValueError('CSV order/bytes/newlines differ')
    return dict(retained_rows=len(old), added_rows=8, total_rows=len(new),
                all_old_classifications_unchanged=True, new_blacklist_rows=7,
                inherited_override=OVERRIDE, inherited_override_flags=INHERITED)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('flags', 'generator', 'encoder-source', 'actual', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    before = a.flags.read_bytes()
    expected = predict(before)
    if sha(a.generator.read_bytes()) != GENERATOR or sha(a.encoder_source.read_bytes()) != ENCODER_SOURCE:
        raise ValueError('Wrong retained hidden-API generator/list source')
    a.output.mkdir(parents=True, exist_ok=False)
    # hiddenapi list propagates the visible SDK virtual method to every boot
    # override before the CSV generator defaults unassigned entries to blacklist.
    pre = [line.split(b',', 1)[0] if line.split(b',', 1)[0].decode() in SIGNATURES else line
           for line in before.splitlines()]
    pre += [(name+(',public-api,system-api,test-api' if name == OVERRIDE else '')).encode()
            for name in ADDED]
    source = a.output/'pre-default.csv'
    source.write_bytes(b''.join(line+b'\n' for line in sorted(pre)))
    generated = a.output/'generated-host.csv'
    run = subprocess.run([sys.executable, str(a.generator), '--csv', str(source),
                          '--output', str(generated)], capture_output=True, timeout=120)
    (a.output/'generator.log').write_bytes(run.stdout+run.stderr)
    run.check_returncode()
    actual = a.actual.read_bytes()
    generated_linux = generated.read_bytes().replace(b'\r\n', b'\n')
    if generated_linux != expected:
        raise ValueError('Retained generator disagrees with corrected prediction')
    delta = validate(before, actual)
    (a.output/'expected-linux-flags.csv').write_bytes(expected)
    result = dict(scope='Source-backed inherited override prediction and exact native generated CSV',
                  generator_sha256=GENERATOR, encoder_source_sha256=ENCODER_SOURCE,
                  baseline_sha256=BASE, expected_and_actual_sha256=CSV, delta=delta,
                  generator_simulation_matches=True, native_csv_matches=True,
                  existing_flags_modified=False, java_sources_modified=False,
                  frozen_native12_packet_modified=False, native_binary_audited=False)
    (a.output/'result.json').write_bytes((json.dumps(result, indent=2)+'\n').encode())
    print(json.dumps(result))


if __name__ == '__main__':
    main()

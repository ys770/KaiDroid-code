"""Prepare a separate, offline footer-inset candidate; never change a live stage."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

BASE = '3d0993841ca5b69e8630afb6894ad4f068cbf2b710f4dbf0ab7d11e820e18a34'
RELATIVE = 'core/java/com/android/internal/policy/DecorView.java'
OLD = 'insets = insets.inset(consumedLeft, consumedTop, consumedRight, consumedBottom);'
NEW = 'insets = insets.inset(consumedLeft, consumedTop, consumedRight, contentBottom);'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patch(data):
    if sha(data) != BASE:
        raise ValueError('Wrong retained DecorView source; confirm the active source separately')
    text = data.decode('utf-8').replace('\r\n', '\n')
    required = ('final int contentBottom = consumedBottom + (mKaiDroidMenuBar != null',
                'lp.bottomMargin = contentBottom;', OLD)
    if any(text.count(anchor) != 1 for anchor in required):
        raise ValueError('Unexpected footer margin/inset implementation')
    return text.replace(OLD, NEW).encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.source.read_bytes()
    candidate = patch(original)
    args.output.mkdir(parents=True, exist_ok=False)
    target = args.output / RELATIVE
    target.parent.mkdir(parents=True)
    target.write_bytes(candidate)
    delta = ''.join(difflib.unified_diff(
        original.decode().replace('\r\n', '\n').splitlines(True),
        candidate.decode().splitlines(True), fromfile='a/' + RELATIVE,
        tofile='b/' + RELATIVE))
    (args.output / 'candidate.patch').write_bytes(delta.encode())
    receipt = dict(baseline_source_sha256=BASE, candidate_source_sha256=sha(candidate),
                   changed_expression=[OLD, NEW], source_root_modified=False,
                   current_host_source_confirmed=False, native12_packet_modified=False,
                   sdk_runtime_verified=False, native_built=False, installed=False,
                   clock_runtime_cause_proven=False, full_parity=False)
    (args.output / 'contract.json').write_bytes((json.dumps(receipt, indent=2)+'\n').encode())
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()

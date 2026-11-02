"""Bind the separate content-inset candidate to original source evidence, offline."""
import argparse
import json
from pathlib import Path
from prepare_tcl_content_insets import BASE, RELATIVE, patch, sha

DONOR = '150745361a7b936cd9c70430a363d4a413773b6a338dcf83e9c261026c6a83b2'
PACKET = '74c233b490eaa89ea64526c4928efce5c7e028bc06f37309a9603dc642066ca8'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'donor-smali', 'candidate', 'host-receipt', 'native12-packet', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    baseline = a.source.read_bytes()
    donor_bytes = a.donor_smali.read_bytes()
    if sha(donor_bytes) != DONOR:
        raise ValueError('Wrong original DecorView evidence')
    donor = donor_bytes.decode().replace('\r\n', '\n')
    method = donor[donor.index(' updateColorViews('):]
    method = method.split('.end method', 1)[0]
    anchors = (
        'add-int/2addr v1, v3\n\n    iput v1, v12, Lcom/android/internal/policy/DecorView;->mLastBottomInset:I',
        'iget v1, v12, Lcom/android/internal/policy/DecorView;->mLastBottomInset:I\n\n    goto :goto_1e',
        'iput v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I',
        'invoke-virtual {v13, v2, v9, v0, v1}, Landroid/view/WindowInsets;->inset(IIII)Landroid/view/WindowInsets;',
    )
    if any(method.count(anchor) != 1 for anchor in anchors):
        raise ValueError('Donor footer/margin/inset evidence differs')
    host = json.loads(a.host_receipt.read_text())
    if host.get('sha256') != BASE or host.get('read_only_acquisition') is not True:
        raise ValueError('Current host source not confirmed by acquisition receipt')
    candidate = (a.candidate/RELATIVE).read_bytes()
    if candidate != patch(baseline):
        raise ValueError('Candidate contains changes beyond the isolated expression')
    if sha(a.native12_packet.read_bytes()) != PACKET:
        raise ValueError('Frozen native12 archive changed')
    result = dict(scope='Source invariant only; no runtime or pixel acceptance',
                  donor_source_sha256=DONOR, baseline_source_sha256=BASE,
                  candidate_source_sha256=sha(candidate), host_source=host['source'],
                  donor_margin_and_child_insets_use_same_bottom_register=True,
                  port_margin_and_child_insets_now_use_contentBottom=True,
                  source_expression_changes=1, native12_archive_unchanged=True,
                  source_invariant_verified=True, sdk_runtime_verified=False,
                  native_built=False, installed=False, clock_runtime_cause_proven=False,
                  full_parity=False)
    with a.output.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

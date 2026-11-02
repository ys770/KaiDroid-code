"""Strict native08-to-adapter09 code/metadata audit; predictions precede compilation."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

from audit_resolver_title_dex import sha
from audit_tcl_ime_guard05 import exact_inventory, diffs
from audit_tcl_ime_picker_metadata import metadata
from prepare_tcl_dialog_adapter_build_packet import FRAMEWORK08, INPUTS

OWNER='Landroid/app/TctDialog;'
ADDED={
    (OWNER,'setListAdapter','(Landroid/widget/ListAdapter;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/TctDialog;'),
    (OWNER,'getListSelectedPoistion','()I'),
}
CHANGED={(OWNER,'render','()V'),(OWNER,'dispatchKeyEvent','(Landroid/view/KeyEvent;)Z')}
FIELD=('suppliedAdapter','Landroid/widget/ListAdapter;')


def compare_methods(before,after):
    added=set(after)-set(before);removed=set(before)-set(after)
    changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
    valid_baseline=CHANGED<=set(before) and not ADDED & set(before)
    passed=valid_baseline and added==ADDED and not removed and changed==CHANGED
    return dict(before_methods=len(before),after_methods=len(after),added=sorted(added),removed=sorted(removed),
        changed=sorted(changed),expected_added=sorted(ADDED),expected_changed=sorted(CHANGED),
        required_baseline_shape=valid_baseline,
        unrelated_existing_bodies_unchanged=not (changed-CHANGED) and not removed,
        expected_method_delta_only=passed,
        scope='All normalized DEX instructions/register frames/access/catch bodies, exact numeric literal bits. Exactly2 added APIs and2 changed TctDialog methods; no removed methods.')


def compare_metadata(before,after):
    expected=deepcopy(before)
    if OWNER not in expected or FIELD in expected[OWNER]['fields'] or \
            any(k[1:] in expected[OWNER]['methods'] for k in ADDED):
        return dict(expected_metadata_delta_only=False,reason='Required original08 dialog metadata missing or already changed')
    # Source prediction: private instance ListAdapter field; both new methods
    # public virtual. No class, constructor, anonymous-class or lambda changes.
    expected[OWNER]['fields'][FIELD]=(0x2,1)
    for _,name,signature in ADDED:expected[OWNER]['methods'][(name,signature)]=(0x1,3)
    changed=sorted(k for k in before.keys()&after.keys() if before[k]!=after[k])
    unexpected=sorted(k for k in expected.keys()&after.keys() if expected[k]!=after[k])
    added=sorted(set(after)-set(before));removed=sorted(set(before)-set(after))
    passed=not unexpected and not added and not removed and changed==[OWNER]
    return dict(before_classes=len(before),after_classes=len(after),added_classes=added,removed_classes=removed,
        changed_classes=changed,unexpected_changed_classes=unexpected,
        expected_private_instance_field=list(FIELD),
        every_non_dialog_class_declaration_unchanged=all(before[k]==after.get(k) for k in before if k!=OWNER),
        expected_metadata_delta_only=passed,
        scope='Every declared class/superclass/interface/access, field type/access/kind, method signature/access/kind including abstract/native. Exactly1 private instance field and2 public virtual methods in TctDialog.',
        exclusions=['Annotations','Debug/source metadata','DEX static encoded field initial values','Runtime behavior'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','inputs','dexdump','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    a=p.parse_args()
    if sha(a.baseline)!=FRAMEWORK08:raise ValueError('Requires exact native08 framework78328f3a baseline')
    if not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256) or a.candidate_sha256==FRAMEWORK08 or sha(a.candidate)!=a.candidate_sha256:
        raise ValueError('Candidate hash missing, unchanged or mismatched')
    for relative,digest in INPUTS.items():
        source=a.inputs/Path(relative).name
        if source.resolve(strict=True)!=source.absolute() or sha(source)!=digest:
            raise ValueError('Adapter2/retained08 input changed: '+relative)
    a.output.mkdir(parents=True,exist_ok=False)
    before=exact_inventory(a.baseline,a.output/'before08',a.dexdump)
    after=exact_inventory(a.candidate,a.output/'candidate09',a.dexdump)
    code=compare_methods(before,after)
    declarations=compare_metadata(metadata(a.baseline),metadata(a.candidate))
    method_diffs=a.output/'method-diffs-08-09.json'
    method_diffs.write_text(json.dumps(diffs(before,after),indent=2)+'\n',encoding='utf-8')
    passed=code['expected_method_delta_only'] and declarations['expected_metadata_delta_only']
    report=dict(baseline_sha256=FRAMEWORK08,candidate_sha256=a.candidate_sha256,
        source_inputs=INPUTS,dexdump_sha256=sha(a.dexdump),method_diff_sha256=sha(method_diffs),
        numeric_literals_compared_as_exact_encoded_dex_bits=True,
        methods=code,metadata=declarations,passed=passed,
        predictions_fixed_before_native09_output=True,new_class_or_wrapper_allowed=False,
        body_review_required=True,native_runtime_verified=False,full_parity=False)
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=passed,methods=code['expected_method_delta_only'],metadata=declarations['expected_metadata_delta_only'])))
    if not passed:raise ValueError('Unexpected native09 delta; preserve artifacts and investigate, never widen automatically')


if __name__=='__main__':main()

"""Strict native51-to-picker-correction code and declared-metadata audit."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

from audit_resolver_title_dex import inventory, sha
from audit_tcl_ime_picker_metadata import metadata

BASE='efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb'
SOURCE='cdfdf14bcf77805e9df06c1a752b7d0d673eb1a2c18efd2369e9d8ee05147a89'
STATE_SOURCE='cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806'
OWNER='Landroid/widget/KeypadImeController;'
STATE='Landroid/widget/KeypadImeModeState;'
PICKER='Landroid/widget/KeypadImePicker;'
WRAPPER='Landroid/widget/-$$Lambda$KeypadImePicker$'
KEYSIG='(Landroid/content/DialogInterface;ILandroid/view/KeyEvent;)Z'
CTOR='(Landroid/widget/KeypadImePicker;)V'
KEYCALLBACK=(PICKER,'lambda$new$2$KeypadImePicker',KEYSIG)
POLICY_ADDED={(STATE,'pickerModes','()Ljava/util/List;'),
              (STATE,'selectionActions','(Ljava/lang/String;)Ljava/util/List;')}
CHANGED={(OWNER,'showPicker','()V'),
         (OWNER,'lambda$showPicker$4$KeypadImeController','(Landroid/view/View;JLjava/util/List;I)V'),
         (STATE,'selectionAction','(Ljava/lang/String;)Ljava/lang/String;'),
         (PICKER,'<init>','(Landroid/content/Context;Ljava/util/List;Ljava/util/function/IntConsumer;)V'),
         (PICKER,'updateRows','()V'),
         ('Landroid/widget/KeypadImePicker$2;','getView','(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;')}


def wrapper_code_exact(rows,wrapper):
    constructor=rows.get((wrapper,'<init>',CTOR))
    expected=dict(frame=dict(registers=2,ins=2,outs=1),access='0x11001',
        instructions=['invoke-direct {v0}, Ljava/lang/Object;.<init>:()V',
                      'iput-object v1, v0, '+str(wrapper)+'.f$0:'+PICKER,'return-void'],
        catches=['catches       : (none)'])
    callback=rows.get((wrapper,'onKey',KEYSIG),{})
    frame=callback.get('frame',{});lines=callback.get('instructions',[])
    if constructor!=expected or frame.get('ins')!=4 or frame.get('outs')!=4 or frame.get('registers',0)<4:
        return False
    if callback.get('access')!='0x0011' or callback.get('catches')!=['catches       : (none)'] or len(lines)!=4:
        return False
    if not all(isinstance(line,str) for line in lines):return False
    field=re.fullmatch(r'iget-object (v\d+), (v\d+), '+re.escape(str(wrapper)+'.f$0:'+PICKER),lines[0])
    if not field:return False
    base=frame['registers']-4
    args=['v'+str(base+i) for i in range(1,4)]
    if field[2]!='v'+str(base) or field[1] in args:return False
    expected_call='invoke-virtual {'+', '.join([field[1]]+args)+'}, '+PICKER+'.'+KEYCALLBACK[1]+':'+KEYSIG
    result=re.fullmatch(r'move-result (v\d+)',lines[2])
    return bool(lines[1]==expected_call and result and lines[3]=='return '+result[1])


def compare_methods(before,after):
    added=set(after)-set(before);removed=set(before)-set(after)
    changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
    new_owners={k[0] for k in after}-{k[0] for k in before}
    wrappers={owner for owner in new_owners if owner.startswith(WRAPPER)}
    wrapper=next(iter(wrappers)) if len(wrappers)==1 else None
    expected=POLICY_ADDED|{KEYCALLBACK}
    if wrapper:expected|={(wrapper,'<init>',CTOR),(wrapper,'onKey',KEYSIG)}
    target=PICKER+'.'+KEYCALLBACK[1]+':'+KEYSIG
    forwards=[(k,line) for k,body in after.items() if k[0] in wrappers
              for line in body['instructions'] if isinstance(line,str)
              and line.startswith('invoke-') and line.endswith(', '+target)]
    forwarding=(len(forwards)==1 and forwards[0][0]==(wrapper,'onKey',KEYSIG))
    wrapper_exact=bool(wrapper and wrapper_code_exact(after,wrapper))
    passed=(added==expected and not removed and changed==CHANGED and new_owners==wrappers
            and len(wrappers)==1 and forwarding and wrapper_exact)
    return dict(before_methods=len(before),after_methods=len(after),added=sorted(added),
        removed=sorted(removed),changed=sorted(changed),expected_changed=sorted(CHANGED),
        new_key_wrapper=wrapper,new_wrapper_forwards_exact_onkey=forwarding,
        new_wrapper_code_exact=wrapper_exact,
        unrelated_existing_method_bodies_unchanged=not (changed-CHANGED) and not removed,
        expected_method_delta_only=passed,
        scope='All method instruction/register/catch bodies. Exact six changed methods, two policy APIs, one callback and its two-method wrapper; no removed methods.')


def compare_metadata(before,after,method_audit):
    wrapper=method_audit.get('new_key_wrapper')
    expected=deepcopy(before)
    if STATE not in expected or PICKER not in expected:
        return dict(expected_metadata_delta_only=False,reason='Required baseline classes missing')
    for owner,name,signature in POLICY_ADDED:
        expected[owner]['methods'][(name,signature)]=(0x1,3)
    # Same public synthetic virtual access/kind as native51's other picker lambdas.
    expected[PICKER]['methods'][KEYCALLBACK[1:]]=(0x1001,3)
    expected_wrapper=dict(superclass='Ljava/lang/Object;',interfaces=['Landroid/content/DialogInterface$OnKeyListener;'],
        access=0x1011,fields={('f$0',PICKER):(0x1011,1)},
        methods={('<init>',CTOR):(0x11001,2),('onKey',KEYSIG):(0x11,3)})
    if wrapper:expected[wrapper]=expected_wrapper
    unexpected=[owner for owner in expected.keys()&after.keys() if expected[owner]!=after[owner]]
    missing=set(expected)-set(after);extra=set(after)-set(expected)
    fields_same=all(before[k]['fields']==after[k]['fields'] for k in before.keys()&after.keys())
    passed=bool(method_audit.get('expected_method_delta_only') and wrapper and
                not unexpected and not missing and not extra and fields_same)
    return dict(before_classes=len(before),after_classes=len(after),
        added_classes=sorted(set(after)-set(before)),removed_classes=sorted(set(before)-set(after)),
        unexpected_changed_classes=sorted(unexpected),missing_expected_classes=sorted(missing),extra_classes=sorted(extra),
        every_existing_field_definition_unchanged=fields_same,
        exact_new_wrapper_fields_access_interfaces_methods=bool(wrapper and after.get(wrapper)==expected_wrapper),
        expected_metadata_delta_only=passed,
        scope='All declared classes/superclasses/interfaces/access, fields/types/access/kind, and method declarations including native/abstract/access/kind.',
        exclusions=['Annotations','Debug/source metadata','Runtime behavior'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','controller-source','state-source','dexdump','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    a=p.parse_args()
    if sha(a.baseline)!=BASE or sha(a.candidate)!=a.candidate_sha256 or a.candidate_sha256==BASE:
        raise ValueError('Unreviewed baseline/candidate')
    if sha(a.controller_source)!=SOURCE or sha(a.state_source)!=STATE_SOURCE:
        raise ValueError('Unreviewed controller/state source')
    a.output.mkdir(parents=True,exist_ok=False)
    before=inventory(a.baseline,a.output/'before',a.dexdump)
    after=inventory(a.candidate,a.output/'after',a.dexdump)
    methods=compare_methods(before,after)
    declarations=compare_metadata(metadata(a.baseline),metadata(a.candidate),methods)
    report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,
        controller_source_sha256=SOURCE,state_source_sha256=STATE_SOURCE,dexdump_sha256=sha(a.dexdump),
        methods=methods,metadata=declarations,native_runtime_verified=False,
        passed=methods['expected_method_delta_only'] and declarations['expected_metadata_delta_only'])
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    changed=[k for k in sorted(before.keys()&after.keys()) if before[k]!=after[k]]
    rows=[dict(method=k,before=before[k],after=after[k]) for k in changed]
    rows.extend(dict(method=k,before=None,after=after[k]) for k in sorted(set(after)-set(before)))
    rows.extend(dict(method=k,before=before[k],after=None) for k in sorted(set(before)-set(after)))
    (a.output/'method-diffs.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],before=len(before),after=len(after),
                         changed=len(methods['changed']),added=len(methods['added']),removed=len(methods['removed']))))
    if not report['passed']:raise ValueError('Unexpected native delta; preserve output and review, never widen automatically')


if __name__=='__main__':main()

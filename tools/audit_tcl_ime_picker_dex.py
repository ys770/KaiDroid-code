"""Audit the original-picker framework delta against exact accepted49."""
import argparse
import json
from pathlib import Path
from audit_resolver_title_dex import inventory, sha

BASE = '2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'
OWNER = 'Landroid/widget/KeypadImeController;'
PICKER = 'Landroid/widget/KeypadImePicker;'
ALERT = 'Landroid/app/AlertDialog;'
CHANGED = {(OWNER, name, signature) for name, signature in [
    ('dismissPicker','()V'), ('pickerFocused','()Z'), ('refreshOwner','()V'),
    ('showPicker','()V'), ('lambda$new$1$KeypadImeController','()V')]}
CALLBACKS = {
    (OWNER,'lambda$showPicker$4$KeypadImeController',
     '(Landroid/view/View;JLjava/util/List;Landroid/content/DialogInterface;I)V'):
    (OWNER,'lambda$showPicker$4$KeypadImeController','(Landroid/view/View;JLjava/util/List;I)V'),
    (OWNER,'lambda$showPicker$5$KeypadImeController','(Landroid/app/AlertDialog;Z)V'):
    (OWNER,'lambda$showPicker$5$KeypadImeController','(Landroid/widget/KeypadImePicker;Z)V'),
    (OWNER,'lambda$showPicker$6$KeypadImeController',
     '(Landroid/view/View;Landroid/view/ViewTreeObserver$OnWindowFocusChangeListener;Landroid/app/AlertDialog;Landroid/content/DialogInterface;)V'):
    (OWNER,'lambda$showPicker$6$KeypadImeController',
     '(Landroid/view/View;Landroid/view/ViewTreeObserver$OnWindowFocusChangeListener;Landroid/widget/KeypadImePicker;Landroid/content/DialogInterface;)V'),
}


def inherited_dialog_types(value):
    """Only normalize static reference types of inherited Dialog operations."""
    if isinstance(value, str):
        return value.replace(ALERT, 'Landroid/app/Dialog;').replace(PICKER, 'Landroid/app/Dialog;')
    if isinstance(value, list): return [inherited_dialog_types(v) for v in value]
    if isinstance(value, dict): return {k:inherited_dialog_types(v) for k,v in value.items()}
    return value


def wrapper_classes(rows):
    prefix = 'Landroid/widget/-$$Lambda$KeypadImeController$'
    return {key[0] for key, body in rows.items() if key[0].startswith(prefix)
            and any(isinstance(line,str) and OWNER+'.lambda$showPicker$' in line
                    for line in body['instructions'])}


def helper_class(owner):
    return (owner == PICKER or owner.startswith(PICKER[:-1]+'$')
            or owner.startswith('Landroid/widget/-$$Lambda$KeypadImePicker$'))


def wrapper_targets_exact(rows, owners, callbacks):
    targets = {owner+'.'+name+':'+signature for owner,name,signature in callbacks}
    observed = []
    for owner in owners:
        methods = {k:v for k,v in rows.items() if k[0] == owner}
        forwards = [(k,line.rsplit(', ',1)[-1]) for k,v in methods.items()
                    for line in v['instructions'] if isinstance(line,str)
                    and OWNER+'.lambda$showPicker$' in line]
        if len(methods) != 2 or len(forwards) != 1 or not any(k[1]=='<init>' for k in methods):
            return False
        key,target = forwards[0]
        if target not in targets: return False
        expected = ('accept','(I)V') if '$4$' in target else (
            ('onWindowFocusChanged','(Z)V') if '$5$' in target else
            ('onDismiss','(Landroid/content/DialogInterface;)V'))
        # Old selection uses DialogInterface.OnClickListener instead of IntConsumer.
        if '$4$' in target and 'Landroid/content/DialogInterface;I)' in target:
            expected = ('onClick','(Landroid/content/DialogInterface;I)V')
        if key[1:] != expected: return False
        observed.append(target)
    return len(observed)==len(targets) and set(observed)==targets


def compare(before, after):
    added = set(after)-set(before)
    removed = set(before)-set(after)
    changed = {key for key in before.keys() & after.keys() if before[key] != after[key]}
    old_wrappers, new_wrappers = wrapper_classes(before), wrapper_classes(after)
    expected_removed = set(CALLBACKS) | {k for k in before if k[0] in old_wrappers}
    expected_added = set(CALLBACKS.values()) | {k for k in after if k[0] in new_wrappers or helper_class(k[0])}
    # Four lifecycle bodies may change only their AlertDialog/Picker reference
    # types. Every ownership/focus predicate, branch, register and catch stays.
    typed = CHANGED - {(OWNER,'showPicker','()V')}
    same_lifecycle = all(k in before and k in after and
        inherited_dialog_types(before[k]) == inherited_dialog_types(after[k]) for k in typed)
    typed_callbacks = [pair for pair in CALLBACKS.items() if '$4$' not in pair[0][1]]
    same_focus_callbacks = all(old in before and new in after and
        inherited_dialog_types(before[old]) == inherited_dialog_types(after[new]) for old,new in typed_callbacks)
    helper_present = (PICKER,'<init>',
        '(Landroid/content/Context;Ljava/util/List;Ljava/util/function/IntConsumer;)V') in added
    wrappers_exact = (wrapper_targets_exact(before,old_wrappers,CALLBACKS)
                      and wrapper_targets_exact(after,new_wrappers,CALLBACKS.values()))
    passed = (changed == CHANGED and removed == expected_removed and added == expected_added
        and len(old_wrappers) == 3 and len(new_wrappers) == 3 and old_wrappers.isdisjoint(new_wrappers)
        and wrappers_exact and same_lifecycle and same_focus_callbacks and helper_present)
    return dict(before_methods=len(before),after_methods=len(after),added=sorted(added),removed=sorted(removed),
        changed=sorted(changed),expected_changed=sorted(CHANGED),
        old_picker_wrapper_classes=sorted(old_wrappers),new_picker_wrapper_classes=sorted(new_wrappers),
        lifecycle_code_unchanged_except_dialog_reference_types=same_lifecycle,
        focus_callbacks_unchanged_except_dialog_reference_types=same_focus_callbacks,
        picker_synthetic_wrappers_target_exact_callbacks=wrappers_exact,
        expected_picker_delta_only=passed,
        scope='All method code/register/catch bodies; exact source/build hashes separately cover fields and new helper source',
        exclusions=['Field definitions','Annotations','Debug metadata'],native_runtime_verified=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','dexdump','output'): p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    args=p.parse_args()
    if sha(args.baseline)!=BASE or sha(args.candidate)!=args.candidate_sha256 or args.candidate_sha256==BASE:
        raise ValueError('Unreviewed baseline/candidate identity')
    args.output.mkdir(parents=True,exist_ok=False)
    before=inventory(args.baseline,args.output/'before',args.dexdump)
    after=inventory(args.candidate,args.output/'after',args.dexdump)
    report=compare(before,after)
    report.update(baseline_sha256=BASE,candidate_sha256=args.candidate_sha256,dexdump_sha256=sha(args.dexdump))
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    diffs=[dict(method=k,before=before[k],after=after[k]) for k in sorted(before.keys()&after.keys()) if before[k]!=after[k]]
    (args.output/'method-diffs.json').write_text(json.dumps(diffs,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['expected_picker_delta_only','lifecycle_code_unchanged_except_dialog_reference_types']}))
    if not report['expected_picker_delta_only']:
        raise ValueError('Unexpected native delta; preserve and review, never widen automatically')


if __name__=='__main__': main()

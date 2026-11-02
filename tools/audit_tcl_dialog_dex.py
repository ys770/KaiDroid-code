"""Require the predicted dialog-only compiled method delta against accepted46."""
import argparse
import json
from pathlib import Path
from audit_resolver_title_dex import inventory, sha

BASE = '11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1'
DIALOG = 'Landroid/app/TctDialog;'
MESSAGE = 'Landroid/widget/TctDialogMessage;'
IME = 'Landroid/widget/KeypadImeController;'
SCROLL = 'Landroid/app/TctDialog$3;'
EXPECTED_CHANGED = {
    (DIALOG,'<init>','(Landroid/content/Context;I)V'),
    (DIALOG,'onCreate','(Landroid/os/Bundle;)V'),
    (DIALOG,'render','()V'),
    (DIALOG,'onStart','()V'),
    (MESSAGE,'<init>','(Landroid/content/Context;)V'),
    (MESSAGE,'<init>','(Landroid/content/Context;Landroid/util/AttributeSet;)V'),
    (IME,'windowFocusChanged','(Z)V'),
}
EXPECTED_ADDED = {
    (DIALOG,'dp','(I)I'),
    (DIALOG,'panelBackground','(IZ)Landroid/graphics/drawable/GradientDrawable;'),
    (MESSAGE,'setTitle','(Z)V'),
    (MESSAGE,'onMeasure','(II)V'),
    (SCROLL,'<init>','(Landroid/app/TctDialog;Landroid/content/Context;I)V'),
    (SCROLL,'onMeasure','(II)V'),
}
VARIANT_ADDITIONS = {
    ('Landroid/app/TctDialog$4;','<init>','(Landroid/app/TctDialog;Landroid/content/Context;I[Ljava/lang/CharSequence;Z)V'),
    ('Landroid/app/TctDialog$4;','getView','(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;'),
    ('Landroid/app/TctDialog$DialogListView;','<init>','(Landroid/content/Context;)V'),
    ('Landroid/app/TctDialog$DialogListView;','onKeyDown','(ILandroid/view/KeyEvent;)Z'),
    ('Landroid/app/TctDialog$DialogListView;','onMeasure','(II)V'),
    (DIALOG,'access$100','(Landroid/app/TctDialog;I)I'),
    (DIALOG,'access$200','(Landroid/app/TctDialog;IIIZ)Landroid/graphics/drawable/StateListDrawable;'),
    (DIALOG,'editBackground','(Z)Landroid/graphics/drawable/GradientDrawable;'),
    (DIALOG,'stateBackground','(IIIZ)Landroid/graphics/drawable/StateListDrawable;'),
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('baseline','candidate','dexdump','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    p.add_argument('--overlay-version',type=int,choices=(1,2,3),default=1)
    a=p.parse_args()
    if sha(a.baseline)!=BASE or sha(a.candidate)!=a.candidate_sha256 or a.candidate_sha256==BASE:
        raise ValueError('Unreviewed baseline/candidate identity')
    a.output.mkdir(parents=True,exist_ok=False)
    before=inventory(a.baseline,a.output/'before',a.dexdump)
    after=inventory(a.candidate,a.output/'after',a.dexdump)
    added=set(after)-set(before);removed=set(before)-set(after)
    changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
    chooser='Lcom/android/internal/app/ChooserActivity;'
    helper='Lcom/android/internal/app/TclResolverPresentation;'
    retained={k for k in before if k[0] in (chooser,helper,'Landroid/widget/MenuBar;')}
    retained_ok=bool(retained) and all(k in after and before[k]==after[k] for k in retained)
    expected_changed = set(EXPECTED_CHANGED)
    if a.overlay_version in (2,3):
        expected_changed.add((DIALOG,'setTitle','(Ljava/lang/CharSequence;)V'))
    expected_added=set(EXPECTED_ADDED)
    if a.overlay_version == 3:
        expected_changed.add((DIALOG,'dispatchKeyEvent','(Landroid/view/KeyEvent;)Z'))
        expected_added.update(VARIANT_ADDITIONS)
    passed=added==expected_added and changed==expected_changed and not removed and retained_ok
    report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,dexdump_sha256=sha(a.dexdump),
        before_methods=len(before),after_methods=len(after),added=sorted(added),removed=sorted(removed),
        changed=sorted(changed),predicted_added=sorted(expected_added),predicted_changed=sorted(expected_changed),
        overlay_version=a.overlay_version,
        expected_dialog_delta_only=passed,accepted_chooser_heading_menu_methods_unchanged=retained_ok,
        scope='All DEX method code/register/catch comparison; source review covers new fields and layout values',
        exclusions=['Field definitions','Annotations','Debug metadata'],runtime_verified=False)
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (a.output/'method-diffs.json').write_text(json.dumps([
        dict(method=k,before=before[k],after=after[k]) for k in sorted(changed)],indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('expected_dialog_delta_only','accepted_chooser_heading_menu_methods_unchanged')}))
    if not passed:
        raise ValueError('Unexpected compiled method delta; retain evidence and review, never widen silently')


if __name__=='__main__':main()

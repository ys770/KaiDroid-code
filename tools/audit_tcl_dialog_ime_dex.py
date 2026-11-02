"""Require exact owner-policy compiled method delta against accepted48."""
import argparse
import json
from pathlib import Path
from audit_resolver_title_dex import inventory, sha

BASE = '897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
MENU='Landroid/widget/MenuBar;'
EXPECTED_ADDED={(MENU,'setImeModeEnabled','(Z)V')}
EXPECTED_CHANGED={
    (MENU,'<init>','(Landroid/content/Context;Landroid/util/AttributeSet;)V'),
    (MENU,'setImeMode','(Ljava/lang/String;Ljava/lang/Runnable;)V'),
    (MENU,'onAttachedToWindow','()V'),
    ('Landroid/app/TctDialog;','<init>','(Landroid/content/Context;I)V'),
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('baseline','candidate','dexdump','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
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
    retained={k for k in before if k[0] in (chooser,helper) or
        k[0]==MENU and k[1] in ('onKeyDown','onKeyUp','activate','onWindowCallbackHandledKey','clearSoftKeyState')}
    retained_ok=bool(retained) and all(k in after and before[k]==after[k] for k in retained)
    expected_changed=set(EXPECTED_CHANGED);expected_added=set(EXPECTED_ADDED)
    passed=added==expected_added and changed==expected_changed and not removed and retained_ok
    report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,dexdump_sha256=sha(a.dexdump),
        before_methods=len(before),after_methods=len(after),added=sorted(added),removed=sorted(removed),
        changed=sorted(changed),predicted_added=sorted(expected_added),predicted_changed=sorted(expected_changed),
        overlay_version=4,
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

"""Audit full native11 method/metadata/raw flags; exact body diff needs independent review."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import zipfile
from audit_tcl_ime_guard05 import exact_inventory,diffs
from audit_tcl_ime_picker_metadata import metadata
from audit_resolver_title_dex import sha
from read_dex_hiddenapi import inventory as flag_inventory
from prepare_tcl_ime_footer_build_packet import FRAMEWORK,IMS_SHA,FLAGS
from prepare_tcl_ime_footer_flags import ADDED,validate as validate_csv,BASE as BASE_FLAGS
from prepare_tcl_dialog_adapter_build_packet import INPUTS
from audit_tcl_dialog_hiddenapi10 import GENERATOR

IMS='Landroid/inputmethodservice/InputMethodService;'
HELPER='Landroid/inputmethodservice/TclImeFooterLayout;'
CHANGED={(IMS,'initViews','()V'),(IMS,'onComputeInsets','(Landroid/inputmethodservice/InputMethodService$Insets;)V'),
         (IMS,'lambda$new$0$InputMethodService','(Landroid/view/ViewTreeObserver$InternalInsetsInfo;)V')}
HELPER_METHODS={('<init>','()V'):(65536,2),
 ('reserveFooter','(Ljava/lang/String;Landroid/view/View;)Z'):(8,2),
 ('updateSymbolsShown','(Ljava/lang/String;Landroid/widget/FrameLayout;Z)Z'):(8,2),
 ('adjustedTop','(Ljava/lang/String;IZ)I'):(8,2)}
NEW_METHODS={(HELPER,n,d) for n,d in HELPER_METHODS}


def compare_methods(old,new):
 changed={k for k in old.keys()&new.keys() if old[k]!=new[k]}
 if old.keys()-new.keys() or new.keys()-old.keys()!=NEW_METHODS or changed!=CHANGED:
  raise ValueError('Methods differ beyond three predicted IMS bodies and four added helper bodies')
 return dict(before_methods=len(old),after_methods=len(new),changed=sorted(changed),added=sorted(NEW_METHODS),
             all_other_existing_bodies_unchanged=True)


def compare_metadata(old,new):
 if old.keys()-new.keys() or new.keys()-old.keys()!={HELPER}:raise ValueError('Unexpected class delta')
 expected=deepcopy(old[IMS]);expected['fields'][('mTclSymbolsShown','Z')]=(2,1)
 if new[IMS]!=expected or any(new[n]!=old[n] for n in old if n!=IMS):raise ValueError('Existing declaration drift')
 helper=dict(superclass='Ljava/lang/Object;',interfaces=[],access=16,
             fields={('KIKA','Ljava/lang/String;'):(24,0),('FOOTER','I'):(24,0)},methods=HELPER_METHODS)
 if new[HELPER]!=helper:raise ValueError('New helper declarations/access differ from source prediction')
 return dict(before_classes=len(old),after_classes=len(new),all_existing_declarations_unchanged_except_one_private_ims_field=True,
             exact_one_package_private_final_helper=True)


def compare_flags(old,new):
 before={n:(r['flag'],r['member_kind']) for n,r in old.items()}
 after={n:(r['flag'],r['member_kind']) for n,r in new.items()}
 if before.keys()-after.keys() or after.keys()-before.keys()!=ADDED or any(after[n]!=before[n] for n in before):
  raise ValueError('Existing raw hiddenAPI flag drift or unexpected members')
 if any(v[0] is None for v in before.values()):raise ValueError('Missing baseline flags')
 for n in ADDED:
  kind=1 if n==IMS+'->mTclSymbolsShown:Z' else (0 if ':' in n.split('->',1)[1] else 2)
  if after[n]!=(2,kind):raise ValueError('New private API not exact blacklist2/member kind: '+n)
 return dict(retained_members=len(before),added_members=len(ADDED),all_existing_raw_flags_and_kinds_unchanged=True,
             exact_seven_added_raw2_private_members=True)


def archive_payloads(before,after):
 with zipfile.ZipFile(before) as old,zipfile.ZipFile(after) as new:
  a=old.namelist();b=new.namelist()
  if len(a)!=len(set(a)) or len(b)!=len(set(b)) or set(a)!=set(b):raise ValueError('Archive entry delta')
  changed=[n for n in a if old.read(n)!=new.read(n)]
  if not changed or any(not re.fullmatch(r'classes\d*\.dex',n) for n in changed):raise ValueError('Non-DEX archive payload changed')
 return dict(changed_dex_entries=changed,all_non_dex_payloads_identical=True)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','baseline-flags','candidate-flags','source-dir','dexdump','output'):
  p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True)
 p.add_argument('--reviewed-diff-sha256',help='Independent review of exact body diff; required for passed=true')
 a=p.parse_args()
 if sha(a.baseline)!=FRAMEWORK or sha(a.baseline_flags)!=BASE_FLAGS:raise ValueError('Wrong native10 baseline')
 if not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256) or a.candidate_sha256==FRAMEWORK or sha(a.candidate)!=a.candidate_sha256:raise ValueError('Wrong candidate bytes')
 for name,pin in {**{Path(n).name:d for n,d in INPUTS.items()},'InputMethodService.java':IMS_SHA,'generate_hiddenapi_lists.py':GENERATOR}.items():
  if sha(a.source_dir/name)!=pin:raise ValueError('Source input changed: '+name)
 if sha(a.candidate_flags)!=FLAGS:raise ValueError('Generated Linux CSV does not match exact source prediction')
 csv=validate_csv(a.baseline_flags.read_bytes(),a.candidate_flags.read_bytes())
 a.output.mkdir(parents=True,exist_ok=False)
 old=exact_inventory(a.baseline,a.output/'before',a.dexdump);new=exact_inventory(a.candidate,a.output/'candidate',a.dexdump)
 methods=compare_methods(old,new);decls=compare_metadata(metadata(a.baseline),metadata(a.candidate))
 old_flags,_=flag_inventory(a.baseline);new_flags,_=flag_inventory(a.candidate)
 flags=compare_flags(old_flags,new_flags);archives=archive_payloads(a.baseline,a.candidate)
 difference=a.output/'method-diffs.json';difference.write_text(json.dumps(diffs(old,new),indent=2)+'\n',encoding='utf-8')
 digest=sha(difference)
 if a.reviewed_diff_sha256 and a.reviewed_diff_sha256!=digest:raise ValueError('Independent body review does not match exact diff')
 report=dict(baseline_sha256=FRAMEWORK,candidate_sha256=a.candidate_sha256,candidate_flags_sha256=FLAGS,
  methods=methods,metadata=decls,raw_flags=flags,csv=csv,archives=archives,body_diff_sha256=digest,
  structural_checks_passed=True,independent_body_review_recorded=bool(a.reviewed_diff_sha256),
  passed=bool(a.reviewed_diff_sha256),native_acceptance_pending_independent_body_review=not bool(a.reviewed_diff_sha256),
  excluded=['DEX annotations/debug/static encoded initial values','Native runtime behavior, actual Kika and pixel equivalence'],
  installed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

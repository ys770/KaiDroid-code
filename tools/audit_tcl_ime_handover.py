"""Strict native12-to13 methods, declarations, complete CSV and raw flag audit."""
import argparse
import json
from pathlib import Path
import re
from audit_tcl_ime_guard05 import exact_inventory,diffs
from audit_tcl_ime_picker_metadata import metadata
from audit_tcl_ime_footer_native11 import archive_payloads
from audit_resolver_title_dex import sha
from read_dex_hiddenapi import inventory as raw_inventory
from prepare_tcl_ime_handover_flags import BASE,CSV,NATIVE,members,serial
from prepare_tcl_dialog_hiddenapi_candidate import rows

EXPECTED='faf76189eda12b26f695f62bd7ac215fbe00ec5e2e8895046f0ab4599f9a48a8'
PREDICTION='80e0ce14b29a7a1272a7c5cceee594b993eda1659a34933c9dc88f0700e0a631'
def decode(data):
 return {n:{**{k:v for k,v in entry.items() if k not in ('fields','methods')},**{k:{tuple(row[:2]):tuple(row[2:]) for row in entry[k]} for k in ('fields','methods')}} for n,entry in data.items()}
def compare_methods(old,new,proof):
 a,b=members(decode(proof['before'])),members(decode(proof['after']))
 added={(n.split('->',1)[0],n.split('->',1)[1].split('(',1)[0],'('+n.split('(',1)[1]) for n in b.keys()-a.keys() if b[n][0]=='methods'}
 c=NATIVE+'KeypadImeController;';s=NATIVE+'KeypadImeModeState;'
 changed={(c,'detach','()V'),(c,'refreshOwner','()V'),(c,'showPicker','()V'),
  (c,'lambda$showPicker$4$KeypadImeController','(Landroid/view/View;JLjava/util/List;I)V'),(s,'invalidate','()V')}
 actual={n for n in old.keys()&new.keys() if old[n]!=new[n]}
 if old.keys()-new.keys() or new.keys()-old.keys()!=added or actual!=changed:
  raise ValueError('Native method delta exceeds five changed/fifteen added/no removed')
 return dict(before_methods=len(old),after_methods=len(new),changed=sorted(actual),added=sorted(added),removed=[],all_other_existing_bodies_unchanged=True)
def compare_metadata(old,new,proof):
 before,after=decode(proof['before']),decode(proof['after']);expected=dict(old)
 if any(old.get(n)!=v for n,v in before.items()):raise ValueError('Native12 declaration proof drift')
 expected.update(after)
 if new!=expected:raise ValueError('Unexpected class/member/access/kind delta')
 return dict(added_classes=sorted(new.keys()-old.keys()),existing_declarations_retained=True,exact_sdk_predicted_private_delta=True)
def compare_flags(old,new,proof):
 if any(row.get('flag') is None for row in old.values()):raise ValueError('Missing baseline encoded API words')
 if old.keys()-new.keys() or new.keys()-old.keys()!=proof['added_members'].keys():raise ValueError('Raw member coverage differs')
 for n in old:
  if (old[n]['flag'],old[n]['member_kind'])!=(new[n]['flag'],new[n]['member_kind']):raise ValueError('Existing raw API word/kind changed: '+n)
 for n,flags in proof['added_members'].items():
  expected=24 if n.endswith('$3;->run()V') else 2
  kind=1 if ':' in n.split('->',1)[1] else 2 if '-><init>' in n or '->access$' in n or '->cancelSelection' in n or '->queueSelection' in n else 3
  if (new[n]['flag'],new[n]['member_kind'])!=(expected,kind):raise ValueError('New raw API flag/kind differs: '+n)
 return dict(retained_members=len(old),added_members=23,new_blacklist_raw2=22,new_inherited_runnable_raw24=1,all_existing_words_and_kinds_unchanged=True)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','baseline-flags','candidate-flags','prediction','dexdump','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);p.add_argument('--reviewed-diff-sha256')
 a=p.parse_args()
 if sha(a.baseline)!=BASE or sha(a.baseline_flags)!=CSV or sha(a.candidate_flags)!=EXPECTED or sha(a.candidate)!=a.candidate_sha256 or not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256) or a.candidate_sha256==BASE:raise ValueError('Wrong original/candidate/CSV')
 if sha(a.prediction)!=PREDICTION:raise ValueError('Prediction proof bytes changed')
 proof=json.loads(a.prediction.read_text())
 if proof['baseline_sha256']!=BASE or proof['expected_csv_sha256']!=EXPECTED or proof['added_rows']!=23:raise ValueError('Wrong prediction')
 oldcsv,newcsv=rows(a.baseline_flags.read_bytes()),rows(a.candidate_flags.read_bytes())
 if oldcsv.keys()-newcsv.keys() or newcsv.keys()-oldcsv.keys()!=proof['added_members'].keys() or any(newcsv[n]!=oldcsv[n] for n in oldcsv) or any(newcsv[n]!=v for n,v in proof['added_members'].items()):raise ValueError('Full CSV scope differs')
 a.output.mkdir(parents=True,exist_ok=False)
 old=exact_inventory(a.baseline,a.output/'before',a.dexdump);new=exact_inventory(a.candidate,a.output/'after',a.dexdump)
 method=compare_methods(old,new,proof);decl=compare_metadata(metadata(a.baseline),metadata(a.candidate),proof)
 rawold,_=raw_inventory(a.baseline);rawnew,_=raw_inventory(a.candidate);raw=compare_flags(rawold,rawnew,proof)
 diff=a.output/'method-diffs.json';diff.write_text(json.dumps(diffs(old,new),indent=2)+'\n');digest=sha(diff)
 if a.reviewed_diff_sha256 and a.reviewed_diff_sha256!=digest:raise ValueError('Independent body review digest differs')
 report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,methods=method,metadata=decl,raw_flags=raw,
  retained_csv_rows=len(oldcsv),added_csv_rows=23,all_old_csv_rows_unchanged=True,archives=archive_payloads(a.baseline,a.candidate),
  body_diff_sha256=digest,independent_body_review_recorded=bool(a.reviewed_diff_sha256),structural_checks_passed=True,
  exclusions=['Annotations','Debug/source metadata','Encoded static initial values'],passed=bool(a.reviewed_diff_sha256),installed=False,physical_or_full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()

"""Strict method/declaration/raw-API audit for native12 app-selector and title padding."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
from audit_tcl_ime_guard05 import exact_inventory,diffs
from audit_tcl_ime_picker_metadata import metadata
from audit_tcl_ime_footer_native11 import archive_payloads
from audit_resolver_title_dex import sha
from read_dex_hiddenapi import inventory as flag_inventory
from prepare_tcl_app_widgets_flags import ADDED as FLAGS_ADDED,validate as validate_csv

BASE='a5f20e01980dbc5a7ea71f883b24d7f77d2781b2407fda9aa0e298f7c4490330'
SDK_BASE='7c58c39339158c473f63e7b8ce194623568be2e352f375d8e4419a9ed86ae508'
CSV='6a9d085640be47d5d8a3409e102e422d2dde0cfa964409362a6881ee2ce61d8e'


def expected(prefix):
 menu=prefix+'MenuBar;';owner=prefix+'KeypadImeController;';picker=prefix+'KeypadImePicker;';row=prefix+'KeypadImePicker$StyledImeRow;';title=prefix+'TitleEditText;'
 changed={(owner,'showPicker','()V'),(picker,'<init>','(Landroid/content/Context;Ljava/util/List;Ljava/util/function/IntConsumer;)V'),
  (picker,'updateRows','()V'),(prefix+'KeypadImePicker$2;','getView','(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;'),
  (title,'<init>','(Landroid/content/Context;Landroid/util/AttributeSet;II)V')}
 added={(menu,'getInputMethodItemBackground','()I'),(picker,'<init>','(Landroid/content/Context;Ljava/util/List;ILjava/util/function/IntConsumer;)V'),
  (picker,'styleRow','(Landroid/widget/TextView;Z)V'),(row,'<init>','(Landroid/content/Context;)V'),(row,'setImeActive','(Z)V'),(row,'onCreateDrawableState','(I)[I')}
 return menu,picker,row,changed,added


def compare_methods(old,new,prefix):
 _,_,_,wanted_changed,wanted_added=expected(prefix)
 changed={k for k in old.keys()&new.keys() if old[k]!=new[k]}
 if old.keys()-new.keys() or new.keys()-old.keys()!=wanted_added or changed!=wanted_changed:
  raise ValueError('Method delta differs from five bodies/six additions/no removals')
 return dict(before_methods=len(old),after_methods=len(new),changed=sorted(changed),added=sorted(wanted_added),removed=[],all_other_existing_bodies_unchanged=True)


def compare_metadata(old,new,prefix):
 menu,picker,row,_,_=expected(prefix)
 if old.keys()-new.keys() or new.keys()-old.keys()!={row}:raise ValueError('Unexpected class delta')
 wanted=deepcopy(old)
 wanted[menu]['methods'][('getInputMethodItemBackground','()I')]=(0,3)
 wanted[picker]['fields'][('itemBackground','I')]=(18,1)
 wanted[picker]['methods'][('<init>','(Landroid/content/Context;Ljava/util/List;ILjava/util/function/IntConsumer;)V')]=(65536,2)
 wanted[picker]['methods'][('styleRow','(Landroid/widget/TextView;Z)V')]=(0,3)
 wanted[row]=dict(superclass='Landroid/widget/TextView;',interfaces=[],access=16,fields={('imeActive','Z'):(2,1)},
  methods={('<init>','(Landroid/content/Context;)V'):(65536,2),('setImeActive','(Z)V'):(0,3),('onCreateDrawableState','(I)[I'):(4,3)})
 if new!=wanted:raise ValueError('Class/member/access drift beyond exact nonpublic additions')
 return dict(added_class=row,added_instance_fields=2,all_old_declarations_access_and_kinds_unchanged=True,public_api_changed=False)


def compare_flags(old,new,inherited_override=False):
 before={n:(r['flag'],r['member_kind']) for n,r in old.items()};after={n:(r['flag'],r['member_kind']) for n,r in new.items()}
 if before.keys()-after.keys() or after.keys()-before.keys()!=FLAGS_ADDED or any(after[n]!=before[n] for n in before):
  raise ValueError('Existing raw API flags/kinds changed or member delta differs')
 if any(v[0] is None for v in before.values()):raise ValueError('Missing baseline raw flags')
 for name in FLAGS_ADDED:
  kind=1 if ':' in name.split('->',1)[1] else (2 if '-><init>' in name else 3)
  from prepare_tcl_app_widgets_flags_inherited import OVERRIDE
  expected=16 if inherited_override and name==OVERRIDE else 2
  if after[name]!=(expected,kind):raise ValueError('New API raw word/kind differs: '+name)
 return dict(retained_members=len(before),added_members=8,all_existing_encoded_words_and_kinds_unchanged=True,
  new_members_exact_raw2=not inherited_override,new_blacklist2_members=7 if inherited_override else 8,
  inherited_sdk_override_raw16=inherited_override)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','dexdump','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);p.add_argument('--sdk',action='store_true')
 p.add_argument('--baseline-flags',type=Path);p.add_argument('--candidate-flags',type=Path)
 p.add_argument('--reviewed-diff-sha256')
 p.add_argument('--inherited-override-flags',action='store_true',help='Exact native12 recovery: seven blacklist2 additions and one inherited SDK virtual override raw16')
 a=p.parse_args()
 if sha(a.baseline)!=(SDK_BASE if a.sdk else BASE) or not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256) or sha(a.candidate)!=a.candidate_sha256:
  raise ValueError('Wrong baseline/candidate bytes')
 if not a.sdk and not (a.baseline_flags and a.candidate_flags):raise ValueError('Native audit requires complete generated CSVs')
 if a.sdk and a.inherited_override_flags:raise ValueError('Inherited native flags do not apply to SDK relocation')
 a.output.mkdir(parents=True,exist_ok=False)
 old=exact_inventory(a.baseline,a.output/'before',a.dexdump);new=exact_inventory(a.candidate,a.output/'after',a.dexdump)
 old_meta,new_meta=metadata(a.baseline),metadata(a.candidate)
 prefix='Lorg/kaidroid/dialogprobe/compat/widget/' if a.sdk else 'Landroid/widget/'
 if a.sdk:
  root='Lorg/kaidroid/dialogprobe/compat/'
  old={k:v for k,v in old.items() if k[0].startswith(root)};new={k:v for k,v in new.items() if k[0].startswith(root)}
  old_meta={k:v for k,v in old_meta.items() if k.startswith(root)};new_meta={k:v for k,v in new_meta.items() if k.startswith(root)}
 method=compare_methods(old,new,prefix);decl=compare_metadata(old_meta,new_meta,prefix)
 extra={}
 if not a.sdk:
  expected_csv=CSV;validator=validate_csv
  if a.inherited_override_flags:
   from prepare_tcl_app_widgets_flags_inherited import CSV as expected_csv,validate as validator
  if sha(a.candidate_flags)!=expected_csv:raise ValueError('Generated CSV differs from full source prediction')
  extra['csv']=validator(a.baseline_flags.read_bytes(),a.candidate_flags.read_bytes())
  before,_=flag_inventory(a.baseline);after,_=flag_inventory(a.candidate)
  extra['raw_flags']=compare_flags(before,after,a.inherited_override_flags);extra['archives']=archive_payloads(a.baseline,a.candidate)
 diff=a.output/'method-diffs.json';diff.write_text(json.dumps(diffs(old,new),indent=2)+'\n',encoding='utf-8');digest=sha(diff)
 if a.reviewed_diff_sha256 and a.reviewed_diff_sha256!=digest:raise ValueError('Independent body review hash differs')
 report=dict(baseline_sha256=sha(a.baseline),candidate_sha256=a.candidate_sha256,sdk_only=a.sdk,methods=method,metadata=decl,
  body_diff_sha256=digest,structural_checks_passed=True,inherited_override_flags=a.inherited_override_flags,independent_body_review_recorded=bool(a.reviewed_diff_sha256),
  passed=bool(a.reviewed_diff_sha256),native_verified=not a.sdk and bool(a.reviewed_diff_sha256),**extra,
  exclusions=['Annotations','Debug/source metadata','Encoded static initial values'],installed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

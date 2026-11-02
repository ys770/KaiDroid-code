"""Verify exactly one compiled Contacts onCreate branch insertion and unchanged APK payloads."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import zipfile
from audit_tcl_ime_guard05 import exact_inventory
from audit_tcl_ime_picker_metadata import metadata
from audit_resolver_title_dex import sha
from prepare_contacts_permission_flow import APK,SIGNING

KEY=('Lcom/android/contacts/activities/PeopleActivity;','onCreate','(Landroid/os/Bundle;)V')
def shifted(value,at):
 if isinstance(value,str):return re.sub(r'@(\d+)',lambda m:'@'+str(int(m[1])+3 if int(m[1])>=at else int(m[1])),value)
 if isinstance(value,list):return [shifted(v,at) for v in value]
 if isinstance(value,dict):return {k:shifted(v,at) for k,v in value.items()}
 return value
def method(before,after):
 hits=[i for i,s in enumerate(before['instructions']) if isinstance(s,str) and 'startPermissionActivityIfNeeded' in s]
 if len(hits)!=1:raise ValueError('Original required-permission invocation differs')
 at=hits[0]+1
 if 'requestReadSMSPermissions' not in before['instructions'][at]:raise ValueError('Unexpected original continuation')
 expected=shifted(deepcopy(before),at)
 expected['instructions'][at:at]=['move-result v2','if-eqz v2, @'+str(at+3),'return-void']
 if after!=expected:raise ValueError('Compiled onCreate differs beyond exact conditional early return')
 return dict(inserted_instructions=3,scratch_register='v2',true_returns_before_sms=True,false_resumes_original_sms_and_body=True,old_frame_access_catches_retained=True)
def methods(before,after):
 changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
 if before.keys()!=after.keys() or changed!={KEY}:raise ValueError('Changed/added/removed method beyond PeopleActivity.onCreate')
 return method(before[KEY],after[KEY])
def payloads(before,after):
 with zipfile.ZipFile(before) as old,zipfile.ZipFile(after) as new:
  a,b=old.namelist(),new.namelist()
  if len(a)!=len(set(a)) or len(b)!=len(set(b)) or set(b)!=set(a)-SIGNING:raise ValueError('APK entry delta differs')
  changes=[n for n in b if old.read(n)!=new.read(n)]
  if changes!=['classes.dex']:raise ValueError('Resource/manifest/other-DEX payload changed')
 return dict(changed=['classes.dex'],all_resources_manifest_classes2_and_other_payloads_identical=True)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','dexdump','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);a=p.parse_args()
 if sha(a.baseline)!=APK or sha(a.candidate)!=a.candidate_sha256 or not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256):raise ValueError('Wrong APK bytes')
 archive=payloads(a.baseline,a.candidate);a.output.mkdir(parents=True,exist_ok=False)
 old=exact_inventory(a.baseline,a.output/'before',a.dexdump);new=exact_inventory(a.candidate,a.output/'after',a.dexdump)
 delta=methods(old,new)
 if metadata(a.baseline)!=metadata(a.candidate):raise ValueError('Class/member/access metadata changed')
 proof=dict(baseline_sha256=APK,candidate_sha256=a.candidate_sha256,methods_before=len(old),methods_after=len(new),changed_method=KEY,
  delta=delta,payloads=archive,all_other_method_bodies_and_declarations_identical=True,
  actual_compiled_delta_verified=True,annotations_debug_static_initial_values_not_mechanically_compared=True,
  runtime_lifecycle_and_permissions_verified=False,signed=False,installed=False,full_parity=False)
 (a.output/'method-diff.json').write_text(json.dumps(dict(before=old[KEY],after=new[KEY]),indent=2)+'\n')
 (a.output/'result.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
if __name__=='__main__':main()

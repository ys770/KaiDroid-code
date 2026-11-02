"""Require one exact three-instruction IMS guard and unchanged other DEX methods."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import zipfile
from audit_tcl_ime_guard05 import exact_inventory,diffs
from audit_tcl_ime_picker_metadata import metadata
from audit_resolver_title_dex import sha
from compress_apk_dex import is_signature
from prepare_messaging_ims_guard import BASE

TARGET=('Lcom/android/mms/util/ImsConnectionManager;','register','()V')
CREATE='invoke-static {v0}, Landroid/telephony/ims/ImsMmTelManager;.createForSubscriptionId:(I)Landroid/telephony/ims/ImsMmTelManager;'
VALIDATE='invoke-static {v0}, Landroid/telephony/SubscriptionManager;.isValidSubscriptionId:(I)Z'


def compare(before,after):
 if before.keys()!=after.keys() or TARGET not in before:raise ValueError('Declared concrete method set changed')
 changed={k for k in before if before[k]!=after[k]}
 if changed!={TARGET}:raise ValueError('Not exactly IMS register body changed')
 expected=deepcopy(before[TARGET]);code=expected['instructions']
 if code.count(CREATE)!=1:raise ValueError('Expected original IMS create instruction absent')
 pos=code.index(CREATE)
 # Existing early-exit target must remain the same logical return after insertion.
 exits=[line for line in code[:pos] if line.startswith('if-') and line.endswith('@'+str(len(code)-1))]
 if len(exits)!=2 or code[-1]!='return-void':raise ValueError('Original register exits changed')
 def shift(line):
  if not isinstance(line,str):return line
  return re.sub(r'@(\d+)',lambda m:'@'+str(int(m[1])+3 if int(m[1])>=pos else int(m[1])),line)
 expected['instructions']=[shift(line) for line in code]
 expected['instructions'][pos:pos]=[VALIDATE,'move-result v1','if-eqz v1, @'+str(len(code)+2)]
 expected['catches']=[shift(line) for line in expected['catches']]
 if after[TARGET]!=expected:raise ValueError('IMS body differs beyond exact validated-ID branch')
 return dict(before_methods=len(before),after_methods=len(after),changed_methods=[TARGET],
  exact_three_instruction_guard=True,every_other_method_body_unchanged=True)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('baseline','candidate','dexdump','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);a=p.parse_args()
 if sha(a.baseline)!=BASE or sha(a.candidate)!=a.candidate_sha256 or not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256):raise ValueError('Unreviewed APK identities')
 a.output.mkdir(parents=True,exist_ok=False)
 with zipfile.ZipFile(a.baseline) as old,zipfile.ZipFile(a.candidate) as new:
  names={n for n in old.namelist() if not is_signature(n)}
  if names!={n for n in new.namelist() if not is_signature(n)} or {n for n in names if old.read(n)!=new.read(n)}!={'classes.dex'}:raise ValueError('Unexpected archive payload change')
 before=exact_inventory(a.baseline,a.output/'before',a.dexdump);after=exact_inventory(a.candidate,a.output/'after',a.dexdump)
 code=compare(before,after);oldmeta=metadata(a.baseline);newmeta=metadata(a.candidate)
 if oldmeta!=newmeta:raise ValueError('Class/member declarations changed')
 (a.output/'method-diff.json').write_text(json.dumps(diffs(before,after),indent=2)+'\n',encoding='utf-8')
 report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,dexdump_sha256=sha(a.dexdump),
  methods=code,all_declared_metadata_unchanged=True,classes=len(oldmeta),
  all_other_zip_payloads_including_secondary_dex_unchanged=True,passed=True,
  exclusions=['DEX annotations','DEX debug/source metadata','DEX static encoded initial values','Runtime telephony behavior'],
  sdk_bytecode_controls_required=True,installed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

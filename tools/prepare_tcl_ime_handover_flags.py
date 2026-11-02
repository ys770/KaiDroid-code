"""Predict native13 member/flag delta from pinned compiled SDK units and native12."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_tcl_ime_picker_metadata import metadata
from prepare_tcl_dialog_hiddenapi_candidate import rows

BASE='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
CSV='d1c91728e194307c40157dc10c9c0e72ff31804a83ab2c407adbb6195764dc15'
SDK_BASE='f086f89a551d9b4c6697ce3d103f59d7855d3bca3d1827e22729daa0189b8b9c'
SDK_NEW='c91daea02d73b1f654954c4e17d0610c6c777f499843c739d9881fa8e0ee7436'
PREFIX='Lorg/kaidroid/dialogprobe/compat/widget/'
NATIVE='Landroid/widget/'
def sha(data):return hashlib.sha256(data).hexdigest()
def relocate(value):
 if isinstance(value,str):return value.replace(PREFIX,NATIVE).replace('Lorg/kaidroid/dialogprobe/spy/InputMethodManager;','Landroid/view/inputmethod/InputMethodManager;').replace('$org-kaidroid-dialogprobe-compat-widget-KeypadImeController','$KeypadImeController')
 if isinstance(value,tuple):return tuple(relocate(v) for v in value)
 if isinstance(value,list):return [relocate(v) for v in value]
 if isinstance(value,dict):return {relocate(k):relocate(v) for k,v in value.items()}
 return value
def selected(data):return {n:v for n,v in data.items() if '$$ExternalSyntheticLambda' not in n and any(n.startswith(NATIVE+k) for k in ('KeypadImeController;','KeypadImeController$','KeypadImeModeState;'))}
def sdk_metadata(path):
 data=selected(relocate(metadata(path)))
 # SDK D8 uses external wrappers/package access; retained platform D8 uses
 # -$$Lambda wrappers/public synthetic entrypoints. Require the normalized
 # baseline to equal native12 exactly before using this explicit mapping.
 for entry in data.values():
  for key,value in list(entry['methods'].items()):
   if key[0].startswith('lambda$'):
    if value!=(4096,3):raise ValueError('Unexpected SDK lambda access/kind')
    entry['methods'][key]=(4097,3)
 return data
def members(data):
 return {owner+'->'+name+(':' if kind=='fields' else '')+desc:(kind,flags) for owner,entry in data.items() for kind in ('fields','methods') for (name,desc),flags in entry[kind].items()}
def serial(data):
 return {n:{**{k:v for k,v in entry.items() if k not in ('fields','methods')},**{k:[[*key,*value] for key,value in sorted(entry[k].items())] for k in ('fields','methods')}} for n,entry in sorted(data.items())}
def predict(base,flags,sdk_base,sdk_new):
 for path,pin in ((base,BASE),(flags,CSV),(sdk_base,SDK_BASE),(sdk_new,SDK_NEW)):
  if sha(path.read_bytes())!=pin:raise ValueError('Unreviewed baseline/SDK bytes: '+str(path))
 old=selected(metadata(base));control=sdk_metadata(sdk_base);new=sdk_metadata(sdk_new)
 if old!=control:raise ValueError('Relocated SDK baseline declaration set differs from native12')
 a,b=members(old),members(new)
 if a.keys()-b.keys() or any(a[n]!=b[n] for n in a):raise ValueError('Existing target declarations removed or changed')
 added=b.keys()-a.keys();old_flags=rows(flags.read_bytes())
 if any(n in old_flags for n in added):raise ValueError('New member already classified')
 run='Landroid/widget/KeypadImeController$3;->run()V'
 inherited=old_flags.get('Ljava/lang/Runnable;->run()V')
 if run not in added or inherited!=['core-platform-api','public-api','system-api','test-api','whitelist']:
  raise ValueError('SDK Runnable override inheritance changed')
 if old_flags.get('Landroid/widget/ListView$FocusSelector;->run()V')!=inherited:
  raise ValueError('Existing hidden Runnable implementation inheritance differs')
 additions={n:(inherited if n==run else ['blacklist']) for n in sorted(added)}
 result=b''.join(line+b'\n' for line in sorted(flags.read_bytes().splitlines()+[(n+','+','.join(f)).encode() for n,f in additions.items()]))
 return result,dict(baseline_sha256=BASE,baseline_csv_sha256=CSV,sdk_baseline_sha256=SDK_BASE,sdk_candidate_sha256=SDK_NEW,
  before=serial(old),after=serial(new),added_members=additions,added_classes=sorted(new.keys()-old.keys()),
  retained_csv_rows=len(old_flags),added_rows=len(added),expected_csv_sha256=sha(result),all_existing_declarations_and_classifications_retained=True,
  sdk_normalizations=['Relocated widget descriptors and lambda suffixes','SDK-only IME service spy descriptor mapped back','External SDK lambda wrapper classes excluded from selected declaration comparison','SDK synthetic lambda package access mapped to baseline-proven native public synthetic access'],
  scope='SDK declaration/source-backed prediction; native generated CSV/raw DEX words must still match',native_verified=False)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('base','flags','sdk-base','sdk-new','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();result,proof=predict(a.base,a.flags,a.sdk_base,a.sdk_new);a.output.mkdir(parents=True,exist_ok=False)
 (a.output/'expected-flags.csv').write_bytes(result);(a.output/'prediction.json').write_text(json.dumps(proof,indent=2)+'\n')
 print(json.dumps({k:v for k,v in proof.items() if k not in ('before','after')}))
if __name__=='__main__':main()

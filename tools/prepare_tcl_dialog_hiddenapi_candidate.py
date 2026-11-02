"""Prepare exact two-signature whitelist/test-api generator insertion offline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

BASE='c005b96c34e5e557f0392eac14b11744fc8fa05040fe9878dff80c11c077fc04'
FLAGS='94ac602a65495508c2a3924e835a90b5c458fe8a081f7e89795178ae13f3c340'
SIGNATURES={
 'Landroid/app/TctDialog;->getListSelectedPoistion()I',
 'Landroid/app/TctDialog;->setListAdapter(Landroid/widget/ListAdapter;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/TctDialog;',
}
MARKER='    # Assign all remaining entries to the blacklist.\n'
INSERT='''    # Exact original TCL adapter APIs: whitelist + test-api encodes raw16.
    tcl_adapter_apis = {
        'Landroid/app/TctDialog;->getListSelectedPoistion()I',
        'Landroid/app/TctDialog;->setListAdapter(Landroid/widget/ListAdapter;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/TctDialog;',
    }
    tcl_unassigned = flags.filter_apis(lambda api, values: api in tcl_adapter_apis and not values)
    if tcl_unassigned != tcl_adapter_apis:
        raise ValueError('Exact TCL adapter APIs must exist and be unassigned before default blacklist')
    flags.assign_flag(FLAG_WHITELIST, tcl_adapter_apis, 'original TCL adapter contract')
    flags.assign_flag(FLAG_TEST_API, tcl_adapter_apis, 'original TCL adapter contract')

'''


def sha(data):return hashlib.sha256(data).hexdigest()


def source(data):
 if sha(data)!=BASE:raise ValueError('Requires exact exported Soong generator source')
 text=data.decode()
 if text.count(MARKER)!=1:raise ValueError('Default-blacklist insertion point changed')
 return text.replace(MARKER,INSERT+MARKER).encode()


def rows(data):
 result={}
 for line in data.decode().splitlines():
  signature,*flags=line.split(',')
  if not signature or signature in result or len(set(flags))!=len(flags):raise ValueError('Invalid/duplicate API flag CSV entry')
  result[signature]=flags
 return result


def simulation_input(data):
 if sha(data)!=FLAGS:raise ValueError('Requires exact native09 final flags CSV')
 before=rows(data)
 if any(before.get(name)!=['blacklist'] for name in SIGNATURES):raise ValueError('Target APIs not exactly blocked in baseline')
 return b''.join((line.split(b',',1)[0]+b'\n' if line.split(b',',1)[0].decode() in SIGNATURES else line+b'\n') for line in data.splitlines())


def compare_csv(before,after):
 old,new=rows(before),rows(after)
 changed={name for name in old.keys()&new.keys() if old[name]!=new[name]}
 valid=(old.keys()==new.keys() and changed==SIGNATURES and all(old[n]==['blacklist'] and new[n]==['test-api','whitelist'] for n in SIGNATURES))
 return dict(before_entries=len(old),after_entries=len(new),added=sorted(new.keys()-old.keys()),removed=sorted(old.keys()-new.keys()),
  changed={n:dict(before=old[n],after=new[n]) for n in sorted(changed)},exact_two_signature_delta=valid)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','flags','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();candidate=source(a.source.read_bytes());before=a.flags.read_bytes();unassigned=simulation_input(before)
 a.output.mkdir(parents=True,exist_ok=False)
 script=a.output/'generate_hiddenapi_lists.py';script.write_bytes(candidate)
 inputs=a.output/'simulation-unassigned.csv';inputs.write_bytes(unassigned)
 result=a.output/'simulation-flags.csv'
 proc=subprocess.run([sys.executable,str(script),'--csv',str(inputs),'--output',str(result)],capture_output=True,timeout=120)
 (a.output/'generator.stdout').write_bytes(proc.stdout);(a.output/'generator.stderr').write_bytes(proc.stderr);proc.check_returncode()
 delta=compare_csv(before,result.read_bytes())
 canonical=result.read_bytes().replace(b'\r\n',b'\n')
 expected=b''.join((line.split(b',',1)[0]+b',test-api,whitelist\n' if line.split(b',',1)[0].decode() in SIGNATURES else line+b'\n') for line in before.splitlines())
 if canonical!=expected:raise ValueError('Canonical Linux CSV differs beyond exact two rows')
 report=dict(scope='Offline source-supported generator candidate and complete-CSV simulation; not native encoding/runtime proof',
  original_source_sha256=BASE,candidate_source_sha256=sha(candidate),baseline_flags_sha256=FLAGS,
  simulation_input_note='Only these two final blacklist labels removed to reproduce their unassigned pre-default state; every other input flag retained.',
  simulation_flags_sha256=sha(result.read_bytes()),expected_linux_flags_sha256=sha(canonical),csv_audit=delta,
  raw_newline_format='CRLF' if b'\r\n' in result.read_bytes() else 'LF',canonical_linux_bytes_exact=True,
  required_encoded_flags={name:dict(before=2,after=16,donor=16) for name in sorted(SIGNATURES)},
  public_or_test_stubs_changed=False,shared_policy_changed=False,global_runtime_policy_changed=False,
  framework_java_changed=False,native09_or_image54_modified=False,native_encoding_verified=False,installed=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
 if not delta['exact_two_signature_delta']:raise ValueError('Unexpected full CSV delta; do not widen')


if __name__=='__main__':main()

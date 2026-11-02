"""Predict exactly eight nonpublic app-widget APIs through the retained generator."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from prepare_tcl_dialog_hiddenapi_candidate import rows,SIGNATURES
from audit_tcl_dialog_hiddenapi10 import GENERATOR

BASE='bb6da7de3b49099e28eb3aa102bd5e0d06cf02ab4316a49adc677e9491a3a979'
P='Landroid/widget/KeypadImePicker;'
R='Landroid/widget/KeypadImePicker$StyledImeRow;'
ADDED={
 'Landroid/widget/MenuBar;->getInputMethodItemBackground()I',
 P+'->itemBackground:I',
 P+'-><init>(Landroid/content/Context;Ljava/util/List;ILjava/util/function/IntConsumer;)V',
 P+'->styleRow(Landroid/widget/TextView;Z)V',
 R+'->imeActive:Z',R+'-><init>(Landroid/content/Context;)V',
 R+'->onCreateDrawableState(I)[I',R+'->setImeActive(Z)V'}


def sha(data):return hashlib.sha256(data).hexdigest()
def predict(data):
 if sha(data)!=BASE:raise ValueError('Require exact native11 CSV')
 old=rows(data)
 if ADDED&old.keys():raise ValueError('New widget APIs already exist')
 return b''.join(line+b'\n' for line in sorted(data.splitlines()+[n.encode()+b',blacklist' for n in ADDED]))
def validate(before,after):
 old,new=rows(before),rows(after)
 if old.keys()-new.keys() or new.keys()-old.keys()!=ADDED or any(new[n]!=old[n] for n in old) or any(new[n]!=['blacklist'] for n in ADDED):
  raise ValueError('CSV drift beyond eight new nonpublic members')
 if after!=predict(before):raise ValueError('CSV order/bytes/newlines differ')
 return dict(retained_rows=len(old),added_rows=len(ADDED),total_rows=len(new),all_old_classifications_unchanged=True)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('flags','generator','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();before=a.flags.read_bytes();expected=predict(before)
 if sha(a.generator.read_bytes())!=GENERATOR:raise ValueError('Wrong retained generator')
 a.output.mkdir(exist_ok=False,parents=True)
 unassigned=[line.split(b',',1)[0] if line.split(b',',1)[0].decode() in SIGNATURES else line for line in before.splitlines()]
 unassigned += [n.encode() for n in ADDED]
 source=a.output/'pre-default.csv';source.write_bytes(b''.join(n+b'\n' for n in sorted(unassigned)))
 raw=a.output/'generated-host.csv'
 r=subprocess.run([sys.executable,str(a.generator),'--csv',str(source),'--output',str(raw)],capture_output=True,timeout=120)
 (a.output/'generator.log').write_bytes(r.stdout+r.stderr);r.check_returncode()
 actual=raw.read_bytes().replace(b'\r\n',b'\n');delta=validate(before,actual)
 assert actual==expected
 (a.output/'expected-linux-flags.csv').write_bytes(actual)
 report=dict(scope='Offline source-generator simulation; native generation still required',baseline_sha256=BASE,generator_sha256=GENERATOR,
  expected_linux_sha256=sha(actual),delta=delta,added_members=sorted(ADDED),binary_or_runtime_policy_changed=False,native_verified=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
if __name__=='__main__':main()

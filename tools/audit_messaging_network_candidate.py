"""Audit exact receiver/job branches, helper scope and independently compiled source bytes."""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from messaging_network_toolchain import verify as verify_toolchain
from audit_tcl_ime_guard05 import exact_inventory,diffs
from audit_tcl_ime_picker_metadata import metadata
from audit_resolver_title_dex import sha
from compress_apk_dex import is_signature
from prepare_messaging_network_candidate import BASE,HELPERS

PREFIX='Lcom/android/mms/transaction/'
BOOT=PREFIX+'KaiBootRecovery;'
WORK=PREFIX+'KaiMmsWork;'
RECEIVER=PREFIX+'MmsSystemEventReceiver;'
JOB=PREFIX+'MmsJobService;'
PRIMARY={(RECEIVER,'onReceive','(Landroid/content/Context;Landroid/content/Intent;)V'),
 (RECEIVER,'wakeUpService','(Landroid/content/Context;)V'),
 (JOB,'onStartJob','(Landroid/app/job/JobParameters;)Z'),(JOB,'onStopJob','(Landroid/app/job/JobParameters;)Z')}
CHANGED=PRIMARY|{(BOOT,'stopMms','(Landroid/app/Service;I)V'),
 (BOOT,'checkMmsCompletion','(Landroid/app/Service;)V'),
 (BOOT,'lambda$checkMmsCompletion$0','(Lcom/android/mms/transaction/KaiBootRecovery$Session;Landroid/app/Service;)V')}
ADDED_BOOT={(BOOT,'reserveWorkStartId','()I'),(BOOT,'boundWorker','(Landroid/os/IBinder;)Landroid/app/Service;')}
ADDED_CLASSES={WORK,PREFIX+'KaiMmsWork$Session;'}


def shift(text,count):
 return re.sub(r'@(\d+)',lambda m:'@'+str(int(m[1])+count),text) if isinstance(text,str) else text


def primary_expected(key,body):
 result=deepcopy(body)
 if key[0]==RECEIVER:
  pattern=r'^invoke-virtual (\{[^}]+\}), Landroid/content/Context;.startService:\(Landroid/content/Intent;\)Landroid/content/ComponentName;$'
  changed=0
  for index,line in enumerate(result['instructions']):
   if not isinstance(line,str):continue
   match=re.fullmatch(pattern,line)
   if match:
    result['instructions'][index]='invoke-static '+match[1]+', '+WORK+'.enqueue:(Landroid/content/Context;Landroid/content/Intent;)V';changed+=1
  if changed!=(2 if key[1]=='onReceive' else 1):raise ValueError('Expected original direct/connectivity/SIM-loaded wakeup call set')
 else:
  action='start' if key[1]=='onStartJob' else 'stop'
  receiver=body['frame']['registers']-body['frame']['ins'];argument=receiver+1
  result['instructions']=[
   'invoke-static {v'+str(argument)+'}, '+WORK+'.isJob:(Landroid/app/job/JobParameters;)Z',
   'move-result v0','if-eqz v0, @6',
   'invoke-static {v'+str(receiver)+', v'+str(argument)+'}, '+WORK+'.'+action+':(Landroid/app/job/JobService;Landroid/app/job/JobParameters;)V',
   'const/4 v0, #bits32 0x00000001','return v0']+[shift(line,6) for line in body['instructions']]
  result['catches']=[shift(line,6) for line in body['catches']]
 return result


def compare(before,after):
 removed=before.keys()-after.keys();added=after.keys()-before.keys()
 changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
 expected_added_boot={k for k in added if k[0] not in ADDED_CLASSES}
 if removed or changed!=CHANGED or expected_added_boot!=ADDED_BOOT or any(k not in after for k in ADDED_BOOT):raise ValueError('Unexpected existing method delta')
 for key in PRIMARY:
  if after[key]!=primary_expected(key,before[key]):raise ValueError('Receiver/job branch differs beyond exact source prediction: '+str(key))
 return dict(before_methods=len(before),after_methods=len(after),removed=sorted(removed),added=sorted(added),changed=sorted(changed),
  exactly_four_primary_dispatch_methods_changed=True,exact_receiver_job_instructions=True,
  exactly_three_existing_boot_queue_methods_changed=True,every_other_existing_method_body_unchanged=True)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('baseline','candidate','helper-dir','sdk','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);a=p.parse_args()
 if sha(a.baseline)!=BASE or sha(a.candidate)!=a.candidate_sha256 or not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256):raise ValueError('Wrong APK inputs')
 for name,pin in HELPERS.items():
  if sha(a.helper_dir/name)!=pin:raise ValueError('Unreviewed helper source')
 toolchain=verify_toolchain(a.jdk,a.sdk)
 a.output.mkdir(parents=True,exist_ok=False)
 bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar';jdk=a.jdk.resolve();exe='.exe' if os.name=='nt' else ''
 classes=a.output/'classes';classes.mkdir();dex=a.output/'dex';dex.mkdir()
 def run(name,args):
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=120)
  (a.output/(name+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 run('reference-javac',[jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*[a.helper_dir/n for n in HELPERS]])
 run('reference-d8',[jdk/'bin'/('java'+exe),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 with zipfile.ZipFile(a.baseline) as old,zipfile.ZipFile(a.candidate) as new:
  names={n for n in old.namelist() if not is_signature(n)}
  if names!={n for n in new.namelist() if not is_signature(n)} or {n for n in names if old.read(n)!=new.read(n)}!={'classes.dex','classes2.dex'}:raise ValueError('Non-DEX archive payload changed')
  if new.read('classes2.dex')!=(dex/'classes.dex').read_bytes():raise ValueError('Secondary DEX not exact independent compilation of reviewed source')
 before=exact_inventory(a.baseline,a.output/'before',bt/('dexdump'+exe));after=exact_inventory(a.candidate,a.output/'after',bt/('dexdump'+exe))
 code=compare(before,after);oldmeta=metadata(a.baseline);newmeta=metadata(a.candidate)
 if oldmeta.keys()-newmeta.keys() or newmeta.keys()-oldmeta.keys()!=ADDED_CLASSES:raise ValueError('Unexpected new/removed classes')
 expected=deepcopy(oldmeta[BOOT])
 for _,name,descriptor in ADDED_BOOT:expected['methods'][(name,descriptor)]=(9,2)
 if newmeta[BOOT]!=expected or any(newmeta[n]!=oldmeta[n] for n in oldmeta if n!=BOOT):raise ValueError('Existing class/member metadata changed')
 (a.output/'method-diff.json').write_text(json.dumps(diffs(before,after),indent=2)+'\n',encoding='utf-8')
 report=dict(toolchain=toolchain,baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,helper_source_sha256=HELPERS,
  independently_compiled_helper_dex_sha256=sha(dex/'classes.dex'),secondary_dex_exact_reference_compile=True,
  methods=code,before_classes=len(oldmeta),after_classes=len(newmeta),added_classes=sorted(ADDED_CLASSES),
  all_existing_class_declarations_unchanged_except_two_explicit_boot_bridge_methods=True,
  manifest_resources_other_archive_bytes_identical=True,passed=True,signed=False,installed=False,full_parity=False,
  exclusions=['Primary DEX annotations/debug/static encoded initial values','Real carrier or pending-message behavior'])
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

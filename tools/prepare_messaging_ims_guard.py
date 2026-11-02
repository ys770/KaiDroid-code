"""Guard the actual IMS subscription ID in the exact installed Messaging APK.

Fresh local decode/rebuild only. No signing, installation or telephony actions.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile
from compress_apk_dex import is_signature

BASE='d6bbbdcd1097c96316a04f4b681256c7e340188979a4e0b3279facbb0e2bf699'
SOURCE='ba30a016962f092c9087a6b91978f524ace2e5cd28f6872a59bca803baa5004e'
RELATIVE='smali/com/android/mms/util/ImsConnectionManager.smali'
ANCHOR='''    invoke-static {}, Landroid/telephony/SubscriptionManager;->getDefaultSubscriptionId()I

    move-result v0

    invoke-static {v0}, Landroid/telephony/ims/ImsMmTelManager;->createForSubscriptionId(I)Landroid/telephony/ims/ImsMmTelManager;'''
REPLACEMENT='''    invoke-static {}, Landroid/telephony/SubscriptionManager;->getDefaultSubscriptionId()I

    move-result v0

    invoke-static {v0}, Landroid/telephony/SubscriptionManager;->isValidSubscriptionId(I)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {v0}, Landroid/telephony/ims/ImsMmTelManager;->createForSubscriptionId(I)Landroid/telephony/ims/ImsMmTelManager;'''


def sha(data):return hashlib.sha256(data).hexdigest()


def patch(data):
 if sha(data)!=SOURCE:raise ValueError('Not exact installed Messaging IMS source')
 text=data.decode('utf-8').replace('\r\n','\n')
 if text.count(ANCHOR)!=1:raise ValueError('Actual subscription/create site changed')
 return text.replace(ANCHOR,REPLACEMENT).encode('utf-8')


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('apk','java','apktool','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 if sha(a.apk.read_bytes())!=BASE:raise ValueError('Not exact installed d6bb Messaging baseline')
 a.output.mkdir(parents=True,exist_ok=False);decoded=a.output/'decoded'
 def run(name,args):
  # A controller timeout is ambiguous: preserve output and never retry here.
  result=subprocess.run(list(map(str,args)),capture_output=True,timeout=180)
  (a.output/(name+'.log')).write_bytes(result.stdout+result.stderr);result.check_returncode()
 run('decode',[a.java,'-jar',a.apktool,'d','-r','--no-assets','-o',decoded,a.apk])
 before={p.relative_to(decoded).as_posix():sha(p.read_bytes()) for p in decoded.glob('smali*/**/*.smali')}
 path=decoded/RELATIVE;path.write_bytes(patch(path.read_bytes()))
 after={p.relative_to(decoded).as_posix():sha(p.read_bytes()) for p in decoded.glob('smali*/**/*.smali')}
 if before.keys()!=after.keys() or {n for n in before if before[n]!=after[n]}!={RELATIVE}:raise ValueError('Unexpected source delta')
 rebuilt=a.output/'rebuilt.apk';run('build',[a.java,'-jar',a.apktool,'b',decoded,'-o',rebuilt])
 candidate=a.output/'Messaging-ims-guard-unsigned.apk'
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(rebuilt) as built,zipfile.ZipFile(candidate,'x') as new:
  for info in old.infolist():
   if not is_signature(info.filename):
    new.writestr(copy.copy(info),built.read('classes.dex') if info.filename=='classes.dex' else old.read(info.filename))
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(candidate) as new:
  names={n for n in old.namelist() if not is_signature(n)}
  if len(new.namelist())!=len(names) or names!=set(new.namelist()) or new.testzip() is not None:raise ValueError('ZIP entry set/CRC changed')
  if {n for n in names if old.read(n)!=new.read(n)}!={'classes.dex'}:raise ValueError('Unexpected archive payload change')
 report=dict(baseline_sha256=BASE,candidate_sha256=sha(candidate.read_bytes()),baseline_ims_smali_sha256=SOURCE,
  candidate_ims_smali_sha256=sha(path.read_bytes()),changed_source=[RELATIVE],changed_archive_payload=['classes.dex'],
  manifest_resources_secondary_dex_all_other_payloads_identical=True,
  scope='Validate actual default subscription before creating IMS manager; retain original SMS gate, ID selection, callbacks, SIM-state retry and unregistration',
  methods_metadata_audit_passed=False,sdk_bytecode_controls_passed=False,signed=False,installed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

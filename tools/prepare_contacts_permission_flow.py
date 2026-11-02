"""Stage one Contacts onCreate permission handoff correction; unsigned and offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

APK='20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248'
TOOL='66cf4524a4a45a7f56567d08b2c9b6ec237bcdd78cee69fd4a59c8a0243aeafa'
OWNER='smali/com/android/contacts/activities/PeopleActivity.smali'
SOURCE='4b9b7ecc99f7f1d0d24e871ef36dbb7007c73f91c47092fe59ac2543597a0822'
SIGNING={'META-INF/SHARED.SF','META-INF/SHARED.RSA','META-INF/MANIFEST.MF'}
def sha(data):return hashlib.sha256(data).hexdigest()
def patch(data):
 if sha(data)!=SOURCE:raise ValueError('Wrong installed PeopleActivity smali')
 text=data.decode().replace('\r\n','\n');blocks=list(re.finditer(r'(?ms)^\.method protected onCreate\(Landroid/os/Bundle;\)V\n.*?^\.end method',text))
 if len(blocks)!=1:raise ValueError('Ambiguous onCreate')
 block=blocks[0].group();anchor='    invoke-static {p0}, Lcom/android/contacts/activities/RequestPermissionsActivity;->startPermissionActivityIfNeeded(Landroid/app/Activity;)Z\n'
 if block.count(anchor)!=1 or ':kaidroid_permissions_ready' in text:raise ValueError('Permission handoff anchor changed')
 if '.locals 7' not in block or '    invoke-virtual {p0}, Lcom/android/contacts/activities/PeopleActivity;->requestReadSMSPermissions()V' not in block:raise ValueError('Register/continuation shape differs')
 new=block.replace(anchor,anchor+'''
    move-result v2

    if-eqz v2, :kaidroid_permissions_ready

    return-void

    :kaidroid_permissions_ready
''')
 return (text[:blocks[0].start()]+new+text[blocks[0].end():]).encode()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('apk','decoded','apktool','java','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 if sha(a.apk.read_bytes())!=APK or sha(a.apktool.read_bytes())!=TOOL:raise ValueError('Wrong APK/assembler tool')
 original=(a.decoded/OWNER).read_bytes();changed=patch(original)
 if any(p.is_symlink() for p in a.decoded.rglob('*')):raise ValueError('Symlinked decoded inputs')
 a.output.mkdir(parents=True,exist_ok=False);owned=a.output/'decoded';shutil.copytree(a.decoded,owned)
 (owned/OWNER).write_bytes(changed)
 before={p.relative_to(a.decoded).as_posix():sha(p.read_bytes()) for p in a.decoded.rglob('*') if p.is_file()}
 after={p.relative_to(owned).as_posix():sha(p.read_bytes()) for p in owned.rglob('*') if p.is_file()}
 if before.keys()!=after.keys() or {n for n in before if before[n]!=after[n]}!={OWNER}:raise ValueError('Decoded source delta exceeds PeopleActivity')
 rebuilt=a.output/'rebuilt.apk'
 cmd=[str(a.java),'-jar',str(a.apktool),'b',str(owned),'-o',str(rebuilt)]
 with (a.output/'assemble.stdout').open('wb') as out,(a.output/'assemble.stderr').open('wb') as err:
  result=subprocess.run(cmd,stdout=out,stderr=err,timeout=180)
 result.check_returncode()
 candidate=a.output/'FPContacts.unsigned.apk'
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(rebuilt) as compiled,zipfile.ZipFile(candidate,'x') as new:
  if len(old.namelist())!=len(set(old.namelist())):raise ValueError('Duplicate baseline ZIP entries')
  dex=compiled.read('classes.dex')
  if dex==old.read('classes.dex'):raise ValueError('No compiled correction')
  for item in old.infolist():
   if item.filename not in SIGNING:new.writestr(item,dex if item.filename=='classes.dex' else old.read(item.filename))
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(candidate) as new:
  if set(new.namelist())!=set(old.namelist())-SIGNING:raise ValueError('Unexpected APK entry delta')
  changes=[n for n in new.namelist() if old.read(n)!=new.read(n)]
  if changes!=['classes.dex']:raise ValueError('Payload drift beyond primary DEX')
 proof=dict(baseline_apk_sha256=APK,apktool_sha256=TOOL,original_smali_sha256=SOURCE,candidate_smali_sha256=sha(changed),
  candidate_apk_sha256=sha(candidate.read_bytes()),changed_zip_payloads=changes,all_other_payloads_identical=True,
  actual_compiled_method_audit_pending=True,original_decoded_inputs_modified=False,signed=False,installed=False,full_parity=False)
 (a.output/'candidate.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
if __name__=='__main__':main()

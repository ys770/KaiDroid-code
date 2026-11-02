"""Inventory image39 updated system APKs and compare all regular image APKs.
Read-only device/image operation; writes a new ignored capture and sanitized report.
Requires PYTHONPATH=work/kyocera-extfs-python; run from repository root.
Does not remove updates or prove semantic equivalence from differing APK hashes.
"""
import subprocess,json
from pathlib import Path
p=Path('artifacts/runtime/image39-system-app-overrides01');p.mkdir(exist_ok=False);a=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED']
def shell(c):
 r=subprocess.run(a+['shell',c],capture_output=True,timeout=60);r.check_returncode();return r.stdout.decode().replace('\r','').strip()
boot=shell('cat /proc/sys/kernel/random/boot_id');assert boot=='00000000-0000-0000-0001-000000000006'
assert shell('getprop ro.kaidroid.image')=='39'
listing=shell('pm list packages -f -s');(p/'packages.txt').write_text(listing)
known=json.loads(Path('docs/evidence/image39-local-transfer.json').read_text())['independently_extracted_files']
records=[]
for line in listing.splitlines():
 if not line.startswith('package:/data/app/'):continue
 path,pkg=line[8:].rsplit('=',1);assert path.startswith('/data/app/') and path.endswith('.apk')
 digest=shell('sha256sum '+path).split()[0]
 records.append({'package':pkg,'sha256':digest,'exact_image39_file_matches':[n for n,v in known.items() if v==digest]})
assert shell('cat /proc/sys/kernel/random/boot_id')==boot
r={'image':39,'boot':boot,'overrides':records,'scope':'Updated system apps only, from pm list packages -f -s. Exact hashes compared with the 52-file independently extracted image39 manifest. Absence of a match is not proof the APK is absent from the image; manifest coverage is limited. Non-system donor apps and data/settings are outside this inventory.','raw':str(p).replace('\\','/')}
(p/'report.json').write_text(json.dumps(r,indent=2)+'\n');Path('docs/evidence/image39-system-app-overrides01.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(records,indent=2))

from pathlib import Path
from dissect.extfs import ExtFS
import json,hashlib,stat
image=Path('work/engineering-system-39.raw.img')
with image.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()=='c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b'
items={}
with image.open('rb') as f:
 fs=ExtFS(f)
 def walk(node,path):
  if node.filetype==stat.S_IFDIR:
   for n in node.iterdir():
    if n.filename not in ('.','..'):walk(n,path+'/'+n.filename)
  elif node.filetype==stat.S_IFREG and path.endswith('.apk'):
   with node.open() as stream:items[path]=hashlib.file_digest(stream,'sha256').hexdigest()
 walk(fs.get('/system'),'/system')
p=Path('docs/evidence/image39-system-app-overrides01.json');r=json.loads(p.read_text())
for row in r['overrides']:row['exact_image39_file_matches']=[n for n,h in items.items() if h==row['sha256']]
r['image_apks_enumerated']=len(items);r['scope']='Updated system-app APK hashes compared against all regular .apk files under /system in the verified raw image39 filesystem. Symlinks and APKs packed inside archive/APEX files are not traversed. Different APK hashes do not alone prove different payloads or behavior. Non-system donor apps and settings are outside this inventory.'
p.write_text(json.dumps(r,indent=2)+'\n')
Path('artifacts/runtime/image39-system-app-overrides01/image-apk-hashes.json').write_text(json.dumps(items,indent=2)+'\n')
print('Image APKs:',len(items));print('Exact matches:',[(x['package'],x['exact_image39_file_matches']) for x in r['overrides'] if x['exact_image39_file_matches']])

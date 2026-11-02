import copy,gzip,hashlib,json,subprocess,sys,zipfile
from pathlib import Path
sys.path.insert(0,'tools')
from compress_apk_dex import is_signature
from compare_dexdump_methods import methods
root=Path('work/camera-startup-trace01')
base=Path('work/camera-fixed30-signed01/signed.apk')
assert hashlib.sha256(base.read_bytes()).hexdigest()=='1ae46bf64f93903c4cefd54d0198e754b914c3d048468e22c1970cfbb96c1b94'
output=root/'unsigned.apk'
with zipfile.ZipFile(base) as src,zipfile.ZipFile(root/'rebuilt.apk') as rebuilt,zipfile.ZipFile(output,'x') as dst:
 for info in src.infolist():
  if not is_signature(info.filename):
   dst.writestr(copy.copy(info),rebuilt.read('classes.dex') if info.filename=='classes.dex' else src.read(info.filename))
with zipfile.ZipFile(base) as src,zipfile.ZipFile(output) as dst:
 names={n for n in src.namelist() if not is_signature(n)}
 assert names==set(dst.namelist())
 assert sorted(n for n in names if src.read(n)!=dst.read(n))==['classes.dex']
parsed=[]
for label,apk in [('before',base),('after',output)]:
 dex=root/(label+'.dex');dex.write_bytes(zipfile.ZipFile(apk).read('classes.dex'))
 dump=root/(label+'.txt.gz')
 r=subprocess.run(['/opt/android-sdk/build-tools/35.0.0/dexdump.exe','-d',str(dex)],capture_output=True,check=True)
 with gzip.open(dump,'wb') as f:f.write(r.stdout)
 parsed.append(methods(dump,dex))
before,after=parsed
changed=sorted(k for k in before.keys()&after.keys() if before[k]!=after[k])
assert before.keys()==after.keys()
assert changed==[('Lcom/tcl/camera/module/video/AutoVideoModule;','startRecord','()V')]
report={'before_methods':len(before),'unchanged_methods':len(before)-1,'changed':changed,'only_changed_payload':'classes.dex','unsigned_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'installed':False}
(root/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

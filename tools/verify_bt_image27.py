from pathlib import Path
import hashlib,json,subprocess
import argparse
p=argparse.ArgumentParser(description='Independently extract and verify built image27 files and SELinux labels')
p.add_argument('--stage',type=Path,required=True)
r=p.parse_args().stage.resolve(strict=True)
raw=r/'compact-image/system.raw.img';out=r/'verify-packaged';out.mkdir()
assert raw.stat().st_size==834666496
staging=json.loads((r/'staging.json').read_text());actual={}
for name,expected in staging['changes'].items():
 dest=out/name.replace('/','_')
 subprocess.run(['/usr/sbin/debugfs','-R',f'dump /system/{name} {dest}',str(raw)],check=True,capture_output=True)
 digest=hashlib.sha256(dest.read_bytes()).hexdigest();assert digest==expected,name;actual[name]=digest
labels={}
for name in ['etc/kaidroid-bluetooth','etc/kaidroid-bluetooth/libbt-vendor-brt.so','etc/init/kaidroid-bluetooth.rc']:
 x=subprocess.run(['/usr/sbin/debugfs','-R',f'ea_list /system/{name}',str(raw)],capture_output=True,check=True).stdout.decode()
 labels[name]=x
 if name.startswith('etc/kaidroid-bluetooth'):assert 'u:object_r:vendor_file:s0' in x
with raw.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
report=dict(raw_sha256=digest,raw_bytes=raw.stat().st_size,packaged_sha256=actual,labels=labels,installed=False)
(r/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

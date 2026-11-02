import hashlib,json,os,shutil,stat
from pathlib import Path
r=Path('/opt/kaidroid/kaidroid-build-20261023');base=r/'engineering-tcl-ime-handover-stage-59';stage=r/'engineering-frame-backlight-stage-60'
assert not stage.exists();assert shutil.disk_usage(r).free>8*1024**3
assert json.loads((base/'outputs.json').read_text())['raw_sha256']=='ca8153c0d5f3165fa6b79b4f1b31663babef6a58d71590092edd5910ea723aad'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory(root):
 result={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=Path(folder)/name;s=p.lstat();key=p.relative_to(root).as_posix()
   result[key]=['link',os.readlink(p)] if p.is_symlink() else ['dir',stat.S_IMODE(s.st_mode)] if p.is_dir() else ['file',stat.S_IMODE(s.st_mode),sha(p)]
 return result
payload={
 'bin/init':(r/'display-resume-init01/init-candidate','0e921696b2e64fcafa7b2b805d9e9a0bd09b162456691279e1b096c8afe3413d'),
 'lib/libsurfaceflinger.so':(r/'display-resume-unit03/libsurfaceflinger-candidate02.so','f663d261b46b46fc17b3bb6541f7055622d4c22abc6015eea917c364eef2e645'),
 'system_ext/etc/selinux/system_ext_sepolicy.cil':(r/'display-resume-policy02/3-system_ext_sepolicy.cil','0ca8bbca68b0b6c052ef76047c1885c89b4488f7605e3c9f11d78578f9799a27'),
 'etc/selinux/kaidroid/precompiled_sepolicy':(r/'display-resume-policy02/precompiled_sepolicy','f57d2d9bb34fa7f2dcc0e2fc3499b98067c174343c736b0d3a5a631cdb4dbbb9')}
for p,h in payload.values():assert sha(p)==h
before=inventory(base/'compact-system');stage.mkdir()
shutil.copytree(base/'compact-system',stage/'compact-system',symlinks=True)
shutil.copytree(base/'compact-root',stage/'compact-root',symlinks=True)
(stage/'records').mkdir();(stage/'compact-image').mkdir();(stage/'tmp').mkdir()
for n,(p,h) in payload.items():
 dst=stage/'compact-system'/n;mode=dst.stat().st_mode;shutil.copyfile(p,dst);os.chmod(dst,stat.S_IMODE(mode));assert sha(dst)==h
prop=stage/'compact-system/build.prop';data=prop.read_bytes();assert data.count(b'ro.kaidroid.image=59')==1;assert b'ro.kaidroid.frame_backlight=' not in data
data=data.replace(b'ro.kaidroid.image=59',b'ro.kaidroid.image=60')+b'\nro.kaidroid.frame_backlight=true\n';prop.write_bytes(data)
shutil.copyfile(base/'records/file_contexts.txt',stage/'records/file_contexts.txt')
config=(base/'records/system_image_info.compact.txt').read_text();config=config.replace('/build/',str(r)+'/').replace(base.name,stage.name)
(stage/'records/system_image_info.compact.txt').write_text(config)
after=inventory(stage/'compact-system');assert set(before)==set(after)
changed=[n for n in before if before[n]!=after[n]];assert set(changed)==set(payload)|{'build.prop'}
for n in changed:assert before[n][:2]==after[n][:2]
assert inventory(base/'compact-system')==before
report={'image':60,'baseline_image':59,'baseline_raw_sha256':'ca8153c0d5f3165fa6b79b4f1b31663babef6a58d71590092edd5910ea723aad','changed':{n:{'before':before[n],'after':after[n]} for n in changed},'entries':len(before),'source_tree_preserved':True,'raw_closure_verified':False,'installed':False}
(stage/'baseline-tree.json').write_text(json.dumps(before,indent=2));(stage/'candidate-tree.json').write_text(json.dumps(after,indent=2));(stage/'staging.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))

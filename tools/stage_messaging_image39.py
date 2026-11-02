"""Create image39 staging; preserve baseline and all existing build-host files."""
import argparse,hashlib,json,os,shutil
from pathlib import Path
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def inventory(root):
 result={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=Path(folder)/name
   result[p.relative_to(root).as_posix()]=('link',os.readlink(p)) if p.is_symlink() else ('dir',p.stat().st_mode&0o7777) if p.is_dir() else ('file',p.stat().st_mode&0o7777,sha(p))
 return result
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args()
r=a.root.resolve(strict=True);base=r/'engineering-softkey-stage-38';out=r/'engineering-messaging-stage-39';bundle=r/'messaging-privapp-integration01'
expected={'system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk':'210871a165dd08acafa3db9228ae840976e4e7496bb7997b49f1588e0ad241b9','system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml':'927fca76afe6843bba958b8d64881287c9e03aa10b96ec48cea0c3136aa52cb5'}
assert json.loads((bundle/'report.json').read_text())['files']==expected
for name,digest in expected.items():assert sha(bundle/name)==digest
provider=r/'thread-attachment-build01/output/TelephonyProvider.apk';provider_name='priv-app/TelephonyProvider/TelephonyProvider.apk'
assert sha(provider)=='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'
before=inventory(base/'compact-system');assert before[provider_name][2]=='b90ad3f9d8ed87068000a14478b86287d1190439e40456a8589d6b0e76574bf9'
assert not any(n.startswith('priv-app/TelephonyProvider/oat/') for n in before)
assert sha(base/'compact-system/framework/framework.jar')=='b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f'
out.mkdir(exist_ok=False)
for name in ('compact-system','compact-root'):shutil.copytree(base/name,out/name,symlinks=True)
(out/'compact-image').mkdir();target=out/'compact-system'
for name in expected:
 q=target/name;assert not q.exists();q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(bundle/name,q);q.chmod(0o644)
shutil.copyfile(provider,target/provider_name)
props=(target/'build.prop').read_text();assert props.splitlines().count('ro.kaidroid.image=38')==1
(target/'build.prop').write_text(props.replace('ro.kaidroid.image=38','ro.kaidroid.image=39'))
shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
config=(base/'system_image_info.compact.txt').read_text();assert config.count('/build/'+base.name+'/')==2
(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
after=inventory(target);assert set(before)<=set(after)
changed={n for n in before if before[n]!=after[n]};assert changed=={'build.prop',provider_name}
added=set(after)-set(before);assert added==set(expected)|{'system_ext/priv-app/KaiDroidTclMessaging'}
assert inventory(base/'compact-system')==before
assert inventory(base/'compact-root')==inventory(out/'compact-root')
report={'image':39,'baseline':38,'baseline_unchanged':True,'changed':{n:sha(target/n) for n in sorted(changed)},'added':sorted(added),'payload':expected,'provider_schema':68,'installed':False,'framework_unchanged':True}
(out/'staging.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

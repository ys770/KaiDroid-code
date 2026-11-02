"""Stage image39 retry with verified DEX-only APK packaging, preserving failed stage01."""
import argparse,hashlib,json,os,shutil
from pathlib import Path
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def inventory(root):
 result={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for n in dirs+files:
   p=Path(folder)/n;result[p.relative_to(root).as_posix()]=('l',os.readlink(p)) if p.is_symlink() else ('d',p.stat().st_mode&4095) if p.is_dir() else ('f',p.stat().st_mode&4095,sha(p))
 return result
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();r=a.root.resolve(strict=True)
base=r/'engineering-messaging-stage-39';out=r/'engineering-messaging-stage-39-retry02';payload=r/'dex-packaging39'
assert (base/'build.exit').read_text().strip()=='1'
before=inventory(base/'compact-system');expected={}
for label,path in [('settings','system_ext/priv-app/Settings/Settings.apk'),('messaging','system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk')]:
 report=json.loads((payload/label/'report.json').read_text());assert report['final_payload_verified'] and report['payload_unchanged'] and not report['unsigned']
 assert report['signer']=='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'
 assert sha(base/'compact-system'/path)==report['source_sha256']
 assert sha(payload/label/'signed.apk')==report['signed_sha256'];expected[path]=report
out.mkdir(exist_ok=False)
for name in ('compact-system','compact-root'):shutil.copytree(base/name,out/name,symlinks=True)
(out/'compact-image').mkdir()
for label,path in [('settings','system_ext/priv-app/Settings/Settings.apk'),('messaging','system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk')]:shutil.copyfile(payload/label/'signed.apk',out/'compact-system'/path)
shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt');config=(base/'system_image_info.compact.txt').read_text();assert config.count('/build/'+base.name+'/')==2
(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
after=inventory(out/'compact-system');assert set(after)==set(before);assert {n for n in before if before[n]!=after[n]}==set(expected)
assert inventory(base/'compact-system')==before;assert inventory(base/'compact-root')==inventory(out/'compact-root')
assert sha(out/'compact-system/priv-app/TelephonyProvider/TelephonyProvider.apk')=='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'
report={'image':39,'retry':2,'baseline_stage_unchanged':True,'changes':expected,'installed':False,'savings_bytes':sum(v['source_bytes']-v['signed_bytes'] for v in expected.values())}
(out/'staging.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'staged':str(out),'savings_bytes':report['savings_bytes']}))

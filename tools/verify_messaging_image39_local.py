"""Verify image39 packaged APKs and inherited image38 runtime independently."""
import argparse,hashlib,json
from pathlib import Path
from dissect.extfs import ExtFS
p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1]
raw='c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b'
assert a.image.stat().st_size==834666496
with a.image.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==raw
baseline=json.loads((root/'docs/evidence/image38-local-transfer.json').read_text());assert baseline['raw_sha256']=='02c99b62666d2da0dd155d342e177ab268f8f11c91d369bfb1eee83b53f2ffc6'
expected=baseline['independently_extracted_files'].copy();expected.update({'build.prop':'7594eb1f303842f11bde9644ebc839fe37a7ed96b1b8b565a9aa8e5d33c5e0fd','priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c','system_ext/priv-app/Settings/Settings.apk':'b5599fdb14e98233a48ef5035822657aac6ae784c8b8b387a66651c9eff1b3e3','system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk':'3618ef4ac1f199e3782bd1adbf13b88c55307e4c794cf429dd5625a601b710bf','system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml':'927fca76afe6843bba958b8d64881287c9e03aa10b96ec48cea0c3136aa52cb5'})
a.output.mkdir(parents=True,exist_ok=False)
with a.image.open('rb') as f:
 fs=ExtFS(f)
 for n,digest in expected.items():
  data=fs.get('/system/'+n).open().read();assert hashlib.sha256(data).hexdigest()==digest,n
  if n.endswith('.apk') and ('Messaging' in n or '/Settings/' in n or 'TelephonyProvider' in n):(a.output/Path(n).name).write_bytes(data)
 props=fs.get('/system/build.prop').open().read().decode().splitlines()
 for prop in ['ro.kaidroid.image=39','ro.kaidroid.power_endcall=true','ro.kaidroid.rgb565_client_target=true','ro.kaidroid.force_client_composition=true']:assert props.count(prop)==1
 rc=fs.get('/system/etc/init/kaidroid-hall.rc').open().read().decode();assert '\n    disabled\n' in rc and '\non ' not in rc
report={'raw_sha256':raw,'raw_bytes':a.image.stat().st_size,'independently_extracted_files':expected,'installed':False}
(a.output/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'verified_files':len(expected),'raw_sha256':raw}))

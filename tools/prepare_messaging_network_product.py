"""Prepare a fresh private AOSP module bundle, without editing a build tree."""
import argparse,json,re,shutil,subprocess
from pathlib import Path
from prepare_messaging_network_payload import SIGNED
from update_messaging_network import CERT,sha

PROVIDER='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'
PERMISSIONS='927fca76afe6843bba958b8d64881287c9e03aa10b96ec48cea0c3136aa52cb5'
APK='system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk'
XML='system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml'


def validate(payload,provider):
 expected={APK:SIGNED,XML:PERMISSIONS}
 report=json.loads((payload/'report.json').read_text())
 if report.get('package')!='com.android.mms' or report.get('signed_apk_sha256')!=SIGNED or report.get('files')!=expected:
  raise ValueError('Not accepted exact parent Messaging overlay')
 for n,pin in expected.items():
  path=payload/n
  if path.resolve(strict=True)!=path or path.is_symlink() or sha(path)!=pin:raise ValueError('Messaging payload differs: '+n)
 if provider.resolve(strict=True)!=provider or provider.is_symlink() or sha(provider)!=PROVIDER:raise ValueError('Exact accepted schema68 provider704 required; never fall back to67/MTK')
 return expected


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('payload','provider','java','apksigner','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();root=Path(__file__).resolve().parents[1]
 a.payload=a.payload.resolve(strict=True);a.provider=a.provider.absolute()
 validate(a.payload,a.provider)
 needed=(a.payload/APK).stat().st_size+a.provider.stat().st_size+128*1024**2
 if shutil.disk_usage(a.output.parent).free<needed:raise ValueError('Insufficient local space; no duplication into existing files')
 a.output.mkdir(parents=True,exist_ok=False)
 def signature(label,path):
  result=subprocess.run([str(a.java),'-jar',str(a.apksigner),'verify','--print-certs',str(path)],capture_output=True,timeout=60)
  (a.output/(label+'-signature.log')).write_bytes(result.stdout+result.stderr);result.check_returncode()
  certs=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)',result.stdout.decode())
  if certs!=[CERT]:raise ValueError('Wrong verified platform certificate: '+label)
 signature('messaging',a.payload/APK);signature('provider',a.provider)
 sources={'Messaging.apk':a.payload/APK,'TelephonyProvider.apk':a.provider,
  'privapp-permissions-kaidroid-messaging.xml':a.payload/XML,'Android.mk':root/'framework/apps/Messaging/Android.mk'}
 for n,path in sources.items():shutil.copyfile(path,a.output/n)
 if sha(a.output/'Messaging.apk')!=SIGNED or sha(a.output/'TelephonyProvider.apk')!=PROVIDER or sha(a.output/'privapp-permissions-kaidroid-messaging.xml')!=PERMISSIONS:raise ValueError('Copied module payload differs')
 report=dict(scope='Private fresh-product prebuilt module bundle; not a built image',
  files={n:sha(a.output/n) for n in sources},certificate_verified=CERT,
  messaging_package='com.android.mms',messaging_version=2403041,messaging_signed_apk_sha256=SIGNED,
  provider_package='com.android.providers.telephony',provider_schema=68,provider_apk_sha256=PROVIDER,
  install_paths={'Messaging.apk':'system/system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk',
   'TelephonyProvider.apk':'system/priv-app/KaiDroidTelephonyProvider68/TelephonyProvider.apk',
   'privapp-permissions-kaidroid-messaging.xml':'system/system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml'},
  module_names=['KaiDroidTclMessaging','KaiDroidTelephonyProvider68','kaidroid-tcl-messaging-permissions'],
  replaces_aosp_modules=['messaging','Mms','TelephonyProvider'],
  provider_partition_preserved='system',messaging_partition_preserved='system_ext',
  apk_rebuild_or_resign=False,shared_build_tree_modified=False,built=False,installed=False,full_parity=False,
  validation_required=['Fresh AOSP module graph and installed file hashes/certificates',
   'No duplicate provider/SMS implementation or stale dex preopt',
   'System and active Messaging APK hashes agree; retain existing data-app update if equal',
   'Preserve existing UID10100, SMS role, grants and app/provider data',
   'Retain provider phone shared UID and schema68; no data clear or schema downgrade',
   'Fresh-data and retained-data boots remain separate; populated carrier behavior unverified'])
 (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

"""Stage audited native10 export recovery over immutable54; never launch or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_NAME='engineering-tcl-calendar-adapter-stage-54'
STAGE_NAME='engineering-tcl-dialog-access-stage-55'
COMPILED='tcl-dialog-build10'
RECOVERED='export-recovery01'
PARTITION=834666496
BASE_RAW='b53162ebca3a11fd57e3d99ba7d4c9998130ddefdcf90be085995bcf9829fcd8'
BASE_MANIFEST='bb24aa37af9ec27465b798454daaeb4784b054373e3deef31ad568e8835615f6'
BASE_OUTPUTS='d773f1967c0a0312bc68a130e5774cc3441b53edfe51d5a15e71930c5a8cd4cd'
OLD_FRAMEWORK='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
AUDIT_BASE09='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
CACHE_FRAMEWORK='897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
PACK_CONTEXTS='c1e6f8a77cabb369f175632d39cc23514792eeffe13988624f9d35facf6a5540'
PACK_CONFIG54='9d19960bcacac2a7cb12bfd5e4669026451783879637f461513db0e2b05d5e41'
PINS={
 'system_ext/priv-app/SystemUI/SystemUI.apk':'aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46',
 'priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
 'framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
 'framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d',
 'etc/kaidroid-camera/libmmcamera2_stats_modules.so':'41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0',
 'etc/init/kaidroid-camera.rc':'5432fe41994dae1caf317f6570e373eedeba79f449667faac85c68f91c2feafd',
 'etc/selinux/plat_file_contexts':'c1c5be48e72d56edf41b904af6fafb50c2c499fb1b2768675f7fb5510d70c350',
 'etc/selinux/plat_sepolicy.cil':'0957520f073b0c8c030b6f2336938034c79e4288b59d42d55f6acfe051ea4408',
}
PROTECTED_MODES={n:(0o664 if n=='etc/selinux/plat_file_contexts' else 0o644) for n in PINS}
# Observed native10 strict audit + separate export recovery; original build remains terminal1.
FRAMEWORK='429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53'
COMPILE_STAGE='c9960256dd0af13d2381bac700c81221e20776308c3d952395847c68916e6da0'
EXPORT='6cb452828ce2db9b1bddaa6c7a31d325582eab0ca8fc8cac2ed2f880e06e1b63'
FILES='1462f5acd79095af9f82c98b27e9a48c5e6340c56ab86f9e66ba965aa2cd688c'
CACHE_PROOF='ad0fd76fa0f6ee00e9e269a49e0b0a566a15a9ac0f4ace059e0d5d9dd6eb1d5c'
COMPILED_CID='8ca7555194314ee610aa73dd8d03d55b9de79dd310c38e358aac4f8e9af143c9'
PROJECTED_CHANGED_ENTRIES=129
AUDIT='834e0f680ae13136131f1d6c7b8ac2a86d464f365feb69ffa3df01240387eafa'
AUDIT_RAW='6da05121777f12c48fe8c19dc9f2c224af9b97541e64f84ce7d0330defa8e614'
RECOVERY='875ea33b9ca2238ce14d6daeeee50cc4d4412af36719edfd180ed183c6dd43ca'
RECOVERY_RAW='e84160080d752a8060fc930219dd050adc77fcd48f70fa7961d263d64c614dee'
PACK_SCRIPT='03600d5aa0ebf33e5373b28fac54714d691e6d8bcac21dca83fffe827af2b978'
CONTROL_NAMES={'build.sh','stage-check.py','launch.sh','compiled-audit.json','recovery-proof.json','compiled-staging.json','compiled-outputs.json','cache-preservation.json','system-inventory.json','root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt'}
EXPECTED_CHANGED={'build.prop','framework/arm/boot-framework.art','framework/arm/boot-framework.oat',
 'framework/arm/boot-voip-common.art','framework/boot-framework.vdex',
 'framework/framework.jar','framework/oat/arm/com.android.location.provider.odex',
 'framework/oat/arm/ethernet-service.odex','framework/oat/arm/services.art','framework/oat/arm/services.odex'}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''):h.update(data)
 return h.hexdigest()


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def require_observed_pins():
 names=['FRAMEWORK','COMPILE_STAGE','EXPORT','FILES','CACHE_PROOF','COMPILED_CID','AUDIT','AUDIT_RAW','RECOVERY','RECOVERY_RAW','PACK_SCRIPT']
 missing=[name for name in names if not isinstance(globals()[name],str) or not re.fullmatch('[0-9a-f]{64}',globals()[name])]
 if type(PROJECTED_CHANGED_ENTRIES) is not int or PROJECTED_CHANGED_ENTRIES<=0:missing.append('PROJECTED_CHANGED_ENTRIES')
 if missing:raise ValueError('Native10/recovery-proof pins pending; no stage/pack allowed: '+', '.join(missing))


def inventory(root):
 rows={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=Path(folder)/name
   rows[p.relative_to(root).as_posix()]=(['link',os.readlink(p)] if p.is_symlink() else
      ['dir',p.stat().st_mode&0o7777] if p.is_dir() else ['file',p.stat().st_mode&0o7777,sha(p)])
 return rows


def validate_protected(rows):
 for n,d in PINS.items():
  if rows.get(n)!=['file',PROTECTED_MODES[n],d]:raise ValueError('Protected54 exact payload/mode changed: '+n)


def compare_staged(before,after,export):
 if before.keys()!=after.keys():raise ValueError('Staged path set changed')
 expected={n for n,d in export.items() if n not in before or before[n][0]!='file' or before[n][2]!=d}|{'build.prop'}
 changed={n for n in before if before[n]!=after[n]}
 if changed!=expected or expected!=EXPECTED_CHANGED:raise ValueError('Unexpected staged content delta')
 for n in changed:
  if before[n][:2]!=after[n][:2]:raise ValueError('Staged type/mode changed: '+n)
 for n,d in export.items():
  if after[n][0]!='file' or after[n][2]!=d:raise ValueError('Missing exported payload: '+n)
 validate_protected(before);validate_protected(after)
 return changed


def validate_audit(value):
 require_observed_pins()
 required={'core/java/android/app/TctDialog.java':'c28919ef89c53efed268df916caefd9144bda7395db00f0d1dc7a86c7d084cc7',
  'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
  'core/java/android/widget/KeypadImeController.java':'d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd',
  'core/java/android/widget/KeypadImeModeState.java':'cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806'}
 if value.get('source_inputs')!=required or canonical(value)!=AUDIT or value.get('passed') is not True or value.get('candidate_sha256')!=FRAMEWORK or value.get('baseline_sha256')!=OLD_FRAMEWORK or value.get('flags',{}).get('exact_two_raw_flag_changes') is not True or value.get('binary',{}).get('passed') is not True or value.get('all_method_bodies_unchanged') is not True or value.get('all_declared_metadata_unchanged') is not True:
  raise ValueError('Not exact strict native10 flag-only audit')


def validate_recovery_review(value):
 require_observed_pins();state=value.get('original_terminal_state',{})
 if canonical(value)!=RECOVERY or value.get('passed') is not True or value.get('terminal') is not True or value.get('container_id')!=COMPILED_CID or state.get('ExitCode')!=1 or state.get('OOMKilled') or state.get('Running') or value.get('compiler_restarted') is not False or value.get('original_failed_status_preserved') is not True or value.get('outputs_sha256')!=EXPORT or value.get('framework_sha256')!=FRAMEWORK or value.get('audit_sha256')!=AUDIT_RAW or value.get('cache_preservation_sha256')!=CACHE_PROOF or value.get('full_cache_proof_verified') is not True:
  raise ValueError('Not exact observed export-only recovery preserving terminal1')


def validate_export(metadata,export):
 require_observed_pins()
 files=export.get('files',{});before=metadata.get('before_closure',{})
 if canonical(files)!=FILES or len(files)!=30 or set(files)!=set(metadata.get('closure',[])) or set(files)!=set(before) or files.get('framework/framework.jar')!=FRAMEWORK or before.get('framework/framework.jar')!=CACHE_FRAMEWORK or metadata.get('baseline_image')!=48 or metadata.get('dialog_overlay_version')!=6 or export.get('dialog_overlay_version')!=6 or metadata.get('accepted_framework_baseline')!=OLD_FRAMEWORK or export.get('accepted_framework_baseline')!=OLD_FRAMEWORK or len(metadata.get('art_apex',{}))!=24 or any(export.get(k) is not True for k in ['art_apex_unchanged','baseline_preserved','export_only_recovery','cache_preservation_verified']):
  raise ValueError('Unreviewed10 framework export closure')
 if export.get('original_build_exit_code')!=1 or export.get('source_manifest_sha256')!=COMPILE_STAGE or export.get('strict_native_audit_sha256')!=AUDIT_RAW or export.get('cache_preservation_sha256')!=CACHE_PROOF or export.get('hiddenapi_generated_flags_sha256')!='9926fe86df5b86b04e9b4eae065d2aa5a1b65f3e640f20e46210e265ff70716c' or export.get('hiddenapi_generator_sha256')!='9d60003265ad857c8ba802b34aac909da60436d40d4f356fc9985a277e8a7898':raise ValueError('Recovery flags/proofs/terminal1 disposition changed')
 required={'KeypadImeController.java':'d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd',
           'KeypadImeModeState.java':'cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806',
           'MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
           'TctDialog.java':'c28919ef89c53efed268df916caefd9144bda7395db00f0d1dc7a86c7d084cc7'}
 if any(metadata.get('inputs',{}).get(n)!=d for n,d in required.items()):raise ValueError('Source policy inputs drifted')
 for n,d in files.items():
  if not re.fullmatch(r'framework/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',n) or '..' in Path(n).parts or not re.fullmatch('[0-9a-f]{64}',d):raise ValueError('Unsafe export path/hash')
  if n in PINS and d!=PINS[n]:raise ValueError('Protected resource/service changed')
 return files


def validate_cache(proof,metadata):
 require_observed_pins();state=proof.get('terminal_state',{})
 if proof.get('container_id')!=COMPILED_CID or proof.get('original_lower_all_files_content_metadata_unchanged') is not True or proof.get('lower_entries')!=565530 or proof.get('projected_changed_entries')!=PROJECTED_CHANGED_ENTRIES or proof.get('projected_removed_entries')!=[] or proof.get('before_inventory_sha256')!=metadata['layered_output']['before_inventory_sha256'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1:
  raise ValueError('Exact terminal10 cache preservation proof missing/failed')


def pack_config(text):
 key='avb_system_add_hashtree_footer_args='
 lines=[line for line in text.splitlines() if line.startswith(key)]
 if len(lines)!=1 or lines[0].split().count('--do_not_generate_fec')!=1 or text.count('/build/'+BASE_NAME+'/')!=2:
  raise ValueError('Image54 FEC0/config path contract lost')
 return text.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/')


def validate_baseline_manifest(m,out):
 if m.get('image')!=54 or m.get('baseline_image')!=53 or m.get('framework_sha256')!=OLD_FRAMEWORK or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True or out.get('image')!=54 or out.get('baseline_image')!=53 or out.get('raw_sha256')!=BASE_RAW or out.get('staging_sha256')!=BASE_MANIFEST or out.get('raw_bytes')!=PARTITION or out.get('optional_fec') is not False or out.get('signed_hashtree_verified') is not True or out.get('avb_verified') is not True:
  raise ValueError('Immutable54 AVB/framework disposition changed')
 if set(m.get('metadata_files_sha256',{}))!=(CONTROL_NAMES-{'recovery-proof.json'}|{'body-review.json'}):raise ValueError('Immutable54 metadata control set changed')


def baseline(base):
 if base.resolve(strict=True)!=base or sha(base/'staging.json')!=BASE_MANIFEST or sha(base/'outputs.json')!=BASE_OUTPUTS or sha(base/'compact-image/system.raw.img')!=BASE_RAW or (base/'build.exit').read_text().strip()!='0':raise ValueError('Immutable54 identity/terminal state changed')
 m=json.loads((base/'staging.json').read_text());out=json.loads((base/'outputs.json').read_text())
 validate_baseline_manifest(m,out)
 for n,d in m['metadata_files_sha256'].items():
  if (base/n).is_symlink() or sha(base/n)!=d:raise ValueError('Image54 control changed: '+n)
 if sha(base/'file_contexts.txt')!=PACK_CONTEXTS or sha(base/'system_image_info.compact.txt')!=PACK_CONFIG54:raise ValueError('Image54 labels/config changed')
 before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
 if before!=json.loads((base/'system-inventory.json').read_text()) or roots!=json.loads((base/'root-inventory.json').read_text()):raise ValueError('Immutable54 packed inventories drifted')
 validate_protected(before)
 if before.get('framework/framework.jar')!=['file',0o644,OLD_FRAMEWORK]:raise ValueError('Image54 framework payload/mode changed')
 return before,roots


def check_stage(stage):
 require_observed_pins();m=json.loads((stage/'staging.json').read_text())
 if (stage/'staging.complete').read_text().strip()!=sha(stage/'staging.json') or m.get('image')!=55 or m.get('baseline_image')!=54 or m.get('base_raw_sha256')!=BASE_RAW or m.get('base_manifest_sha256')!=BASE_MANIFEST or m.get('framework_sha256')!=FRAMEWORK or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True:raise ValueError('Incomplete/unreviewed55 stage')
 if set(m.get('metadata_files_sha256',{}))!=CONTROL_NAMES or sha(stage/'build.sh')!=PACK_SCRIPT:raise ValueError('Stage required control set/build script changed')
 if m.get('build_manifest_sha256')!=COMPILE_STAGE or m.get('outputs_sha256')!=EXPORT or m.get('compiled_audit_canonical_sha256')!=AUDIT or m.get('recovery_review_canonical_sha256')!=RECOVERY or m.get('cache_preservation_sha256')!=CACHE_PROOF or m.get('cache_preservation_verified') is not True:raise ValueError('Stage lost compiled/review/cache proof gates')
 for n,d in m['metadata_files_sha256'].items():
  if (stage/n).is_symlink() or sha(stage/n)!=d:raise ValueError('Stage control changed: '+n)
 if sha(stage/'compiled-audit.json')!=AUDIT_RAW or sha(stage/'recovery-proof.json')!=RECOVERY_RAW:raise ValueError('Exact review proof bytes changed')
 validate_audit(json.loads((stage/'compiled-audit.json').read_text()));validate_recovery_review(json.loads((stage/'recovery-proof.json').read_text()))
 meta=json.loads((stage/'compiled-staging.json').read_text());exports=json.loads((stage/'compiled-outputs.json').read_text())
 if sha(stage/'compiled-staging.json')!=COMPILE_STAGE or sha(stage/'compiled-outputs.json')!=EXPORT or sha(stage/'cache-preservation.json')!=CACHE_PROOF:raise ValueError('Compiled proof bytes changed')
 files=validate_export(meta,exports);validate_cache(json.loads((stage/'cache-preservation.json').read_text()),meta)
 before,roots=baseline(stage.parent/BASE_NAME);after=inventory(stage/'compact-system')
 alarms={n:v[2] for n,v in before.items() if n.startswith('product/media/audio/alarms/') and v[0]=='file'}
 if len(alarms)!=8 or m.get('preserved_alarm_files')!=alarms or m.get('art_apex')!=meta['art_apex']:raise ValueError('Alarm/ART closure manifest drift')
 changed=compare_staged(before,after,files)
 if after!=json.loads((stage/'system-inventory.json').read_text()) or roots!=inventory(stage/'compact-root') or roots!=json.loads((stage/'root-inventory.json').read_text()) or before!=json.loads((stage/'baseline-system-inventory.json').read_text()):raise ValueError('Stage/baseline/root inventory changed')
 if set(m['changed'])!=changed or m.get('exported_files')!=files or m.get('protected54_sha256')!=PINS:raise ValueError('Stage closure manifest changed')
 for n in changed:
  if m['changed'][n]!={'before':before[n],'after':after[n]}:raise ValueError('Stage changed payload record mismatch')
 props=(stage.parent/BASE_NAME/'compact-system/build.prop').read_bytes()
 if props.splitlines().count(b'ro.kaidroid.image=54')!=1 or props.count(b'ro.kaidroid.image=54')!=1 or (stage/'compact-system/build.prop').read_bytes()!=props.replace(b'ro.kaidroid.image=54',b'ro.kaidroid.image=55',1):raise ValueError('Unexpected revision mutation')
 if (stage/'system_image_info.compact.txt').read_text()!=pack_config((stage.parent/BASE_NAME/'system_image_info.compact.txt').read_text()):raise ValueError('Pack config drift')
 if shutil.disk_usage(stage).free<2*PARTITION+20*1024**3:raise ValueError('Insufficient pack headroom/emergency floor')
 return m


def launcher():
 return '''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-tcl-dialog-access-stage-55"
test -f "$stage/staging.complete"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
for name in ninja soong_build e2fsdroid; do
 if pgrep -x "$name" >/dev/null; then
  echo 'Build active; observe same job.' >&2; exit 1
 else
  observation=$?
  test "$observation" -eq 1
 fi
done
containers="$(sudo docker ps -q)"
test -z "$containers"
python3 "$stage/stage-check.py" --check-stage "$stage"
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
test "$(cat "$stage/container-image-id")" = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
sudo docker run -d --network none --name kaidroid-tcl-dialog-access-image55 \\
 -v "$root:/build:ro" \\
 -v "$stage:/build/engineering-tcl-dialog-access-stage-55:rw" \\
 kaidroid-build:20261023 bash /build/engineering-tcl-dialog-access-stage-55/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def stage(root,build_script,audit,recovery_review):
 require_observed_pins()
 if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:raise ValueError('Use attested Linux builder1000:1000')
 root=root.resolve(strict=True)
 if str(root)!=ROOT:raise ValueError('Unexpected build root')
 base=root/BASE_NAME;compiled=root/COMPILED;recovered=compiled/RECOVERED;out=root/STAGE_NAME
 if out.exists():raise FileExistsError(out)
 if compiled.resolve(strict=True)!=compiled:raise ValueError('Symlinked compiled stage')
 for name in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',name],capture_output=True).returncode!=1:raise ValueError('Build active or observation failed')
 if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container active; coordinate')
 info=json.loads(subprocess.check_output(['sudo','docker','inspect',COMPILED_CID],text=True))[0];state=info['State']
 if info['Id']!=COMPILED_CID or info.get('Name')!='/kaidroid-tcl-dialog-build10' or info.get('Image')!='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d' or info['Config'].get('User')!='builder' or info['Config'].get('Cmd')!=['bash','/build/tcl-dialog-build10/build.sh'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1 or (compiled/'build.exit').read_text().strip()!='1' or (compiled/'container-id').read_text().strip()!=COMPILED_CID:raise ValueError('Compiled10 exact terminal container required')
 for path,pin in [(compiled/'staging.json',COMPILE_STAGE),(recovered/'outputs.json',EXPORT),(compiled/'cache-preservation.json',CACHE_PROOF),(build_script,PACK_SCRIPT)]:
  if path.is_symlink() or sha(path)!=pin:raise ValueError('Unreviewed compiled proof/pack script')
 if recovered.resolve(strict=True)!=recovered or sha(recovered/'recovery.json')!=RECOVERY_RAW or sha(audit)!=AUDIT_RAW or sha(recovery_review)!=RECOVERY_RAW:raise ValueError('Exact audit/recovery proof bytes changed')
 validate_audit(json.loads(audit.read_text()));validate_recovery_review(json.loads(recovery_review.read_text()))
 for name,pin in json.loads(recovery_review.read_text())['originals_sha256'].items():
  if not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or (compiled/name).is_symlink() or sha(compiled/name)!=pin:raise ValueError('Original terminal1 log/control changed: '+name)
 meta=json.loads((compiled/'staging.json').read_text());exports=json.loads((recovered/'outputs.json').read_text());files=validate_export(meta,exports)
 proof=json.loads((compiled/'cache-preservation.json').read_text());validate_cache(proof,meta)
 for n,key in [('cache-lower-before.json','before_inventory_sha256'),('cache-upper-after.json','upper_inventory_sha256'),('cache-view-delta.json','view_delta_sha256')]:
  if sha(compiled/n)!=proof[key]:raise ValueError('Cache journal changed: '+n)
 before,roots=baseline(base)
 for n,d in meta['art_apex'].items():
  if before.get(n,[])!=['file',0o644,d]:raise ValueError('ART baseline changed: '+n)
 for n,d in files.items():
  if (recovered/'output'/n).is_symlink() or sha(recovered/'output'/n)!=d:raise ValueError('Export payload changed: '+n)
 props=(base/'compact-system/build.prop').read_bytes();config=pack_config((base/'system_image_info.compact.txt').read_text())
 if props.splitlines().count(b'ro.kaidroid.image=54')!=1 or props.count(b'ro.kaidroid.image=54')!=1:raise ValueError('Wrong base revision')
 copies=sum((Path(folder)/n).stat().st_size for tree in ('compact-system','compact-root') for folder,_,names in os.walk(base/tree,followlinks=False) for n in names if not (Path(folder)/n).is_symlink())
 free=shutil.disk_usage(root).free
 if free<copies+2*PARTITION+20*1024**3:raise ValueError('Insufficient copy/image/emergency-floor capacity')
 out.mkdir()
 for tree in ('compact-system','compact-root'):shutil.copytree(base/tree,out/tree,symlinks=True)
 (out/'compact-image').mkdir()
 for n in files:shutil.copyfile(recovered/'output'/n,out/'compact-system'/n)
 (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=54',b'ro.kaidroid.image=55',1))
 shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt');(out/'system_image_info.compact.txt').write_text(config,encoding='utf-8')
 after=inventory(out/'compact-system');changed=compare_staged(before,after,files)
 if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:raise ValueError('Immutable baseline/root closure changed')
 alarms={n:v[2] for n,v in before.items() if n.startswith('product/media/audio/alarms/') and v[0]=='file'}
 if len(alarms)!=8:raise ValueError('Alarm closure changed')
 for source,name in [(build_script,'build.sh'),(Path(__file__),'stage-check.py'),(audit,'compiled-audit.json'),(recovery_review,'recovery-proof.json'),(compiled/'staging.json','compiled-staging.json'),(recovered/'outputs.json','compiled-outputs.json'),(compiled/'cache-preservation.json','cache-preservation.json')]:shutil.copyfile(source,out/name)
 (out/'launch.sh').write_text(launcher(),encoding='utf-8')
 for n,v in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]:
  (out/n).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
 controls=['build.sh','stage-check.py','launch.sh','compiled-audit.json','recovery-proof.json','compiled-staging.json','compiled-outputs.json','cache-preservation.json','system-inventory.json','root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt']
 m=dict(image=55,baseline_image=54,base_raw_sha256=BASE_RAW,base_manifest_sha256=BASE_MANIFEST,framework_sha256=FRAMEWORK,
   build_manifest_sha256=COMPILE_STAGE,outputs_sha256=EXPORT,compiled_audit_canonical_sha256=AUDIT,recovery_review_canonical_sha256=RECOVERY,
   cache_preservation_sha256=CACHE_PROOF,cache_preservation_verified=True,exported_files=files,art_apex=meta['art_apex'],preserved_alarm_files=alarms,protected54_sha256=PINS,
   changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},metadata_files_sha256={n:sha(out/n) for n in controls},copy_bytes=copies,free_bytes_before=free,system_partition_bytes=PARTITION,
   optional_fec=False,signed_hashtree_required=True,baseline_stage_unchanged=True,root_unchanged=True,built=False,installed=False,raw_uid_gid_xattr_verification_required=True)
 (out/'staging.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8');(out/'staging.complete').write_text(sha(out/'staging.json')+'\n')
 print(json.dumps(m))


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check-stage',type=Path)
 for n in ('root','build-script','audit','recovery-proof'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 if a.check_stage:check_stage(a.check_stage)
 elif all((a.root,a.build_script,a.audit,a.recovery_proof)):stage(a.root,a.build_script,a.audit,a.recovery_proof)
 else:p.error('Require --check-stage or --root/--build-script/--audit/--recovery-proof')

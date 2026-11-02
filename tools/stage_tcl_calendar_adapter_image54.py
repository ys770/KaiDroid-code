"""Stage terminal/audited adapter2 over immutable53; never launch or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_NAME='engineering-tcl-ime-guard-stage-53'
STAGE_NAME='engineering-tcl-calendar-adapter-stage-54'
COMPILED='tcl-dialog-build09'
PARTITION=834666496
BASE_RAW='f587f445ce66e397718110762c7e952fcb19c03feef4b1ae35c7638209c51f56'
BASE_MANIFEST='4ed37c11ee869bc85c2d8a993126311326438778625feb85e8a75a601d7b8dea'
BASE_OUTPUTS='b3744c15e26c946415ea76a933234224435da8921b95ecf3e2a7d90866dd7a8a'
OLD_FRAMEWORK='78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2'
AUDIT_BASE08='78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2'
CACHE_FRAMEWORK='897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
PACK_CONTEXTS='c1e6f8a77cabb369f175632d39cc23514792eeffe13988624f9d35facf6a5540'
PACK_CONFIG53='e0ad4be23d5898d50a22b4853ce7869869de53df0fb78fbcb17bd857723f6e5b'
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
# Observed terminal09 proofs supplied by hardware; native08 is the audit baseline.
FRAMEWORK='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
COMPILE_STAGE='a6df424e87b68c89dee426344304fdf9ffc6927fa2b977a33d5f00ad50f5a264'
EXPORT='7b72f5d7f8b819d8c1c6e70c04d4791b647fc1f3f78fdbd65047b46ccd42a3d0'
FILES='a12f036d39245ece48f6ce02c93002b7d0224dc2fd06ad0ed9468cc2b9546f45'
CACHE_PROOF='e155e8859371b572945f453696776850349b823590cc33d4617ae9168ff0650d'
COMPILED_CID='7906f73642bf9dc8e34c5ebe420c90db3ac0e7dab8c4e2c0234690ff5771dfa3'
PROJECTED_CHANGED_ENTRIES=129
AUDIT='26a87b3438ca3f08871421946e2c834e1331d49a0fcbe1035acccef31dd79c94'
AUDIT_RAW='97a9207606d1ea4f331e184e2a2523e7ab1f98126b3fb04fc4458895c72bcda3'
BODY_REVIEW='e975b84daa2c66775f08791154239d9c8201324c0f5bac9c0fece5178841044c'
BODY_REVIEW_RAW='31ccf4acf5023254bf90532bdce50d5cffd4cd777370e08210e63a87205d1d90'
METHOD_DIFF='da197a2bf7f69547529d46b2d0f4cd9787736086cde0407fec9ded65e70082a5'
PACK_SCRIPT='e0ff283c8e0d4aa4e021b041484de99c2fa37bf4b8b86e8e2657595e2567eb9e'
CONTROL_NAMES={'build.sh','stage-check.py','launch.sh','compiled-audit.json','body-review.json','compiled-staging.json','compiled-outputs.json','cache-preservation.json','system-inventory.json','root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt'}
EXPECTED_CHANGED={'build.prop','framework/arm/boot-framework.art','framework/arm/boot-framework.oat',
 'framework/arm/boot-telephony-common.art','framework/arm/boot-voip-common.art','framework/boot-framework.vdex',
 'framework/framework.jar','framework/oat/arm/com.android.location.provider.odex',
 'framework/oat/arm/ethernet-service.odex','framework/oat/arm/services.art','framework/oat/arm/services.odex'}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''):h.update(data)
 return h.hexdigest()


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def require_observed_pins():
 names=['FRAMEWORK','COMPILE_STAGE','EXPORT','FILES','CACHE_PROOF','COMPILED_CID','AUDIT','AUDIT_RAW','BODY_REVIEW','BODY_REVIEW_RAW','METHOD_DIFF','PACK_SCRIPT']
 missing=[name for name in names if not isinstance(globals()[name],str) or not re.fullmatch('[0-9a-f]{64}',globals()[name])]
 if type(PROJECTED_CHANGED_ENTRIES) is not int or PROJECTED_CHANGED_ENTRIES<=0:missing.append('PROJECTED_CHANGED_ENTRIES')
 if missing:raise ValueError('Build09/body-review pins pending; no stage/pack allowed: '+', '.join(missing))


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
  if rows.get(n)!=['file',PROTECTED_MODES[n],d]:raise ValueError('Protected53 exact payload/mode changed: '+n)


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
 if canonical(value)!=AUDIT or value.get('passed') is not True or value.get('candidate_sha256')!=FRAMEWORK or value.get('baseline_sha256')!=AUDIT_BASE08 or value.get('source_inputs')!=required or value.get('numeric_literals_compared_as_exact_encoded_dex_bits') is not True or value.get('predictions_fixed_before_native09_output') is not True or value.get('new_class_or_wrapper_allowed') is not False:
  raise ValueError('Not exact reviewed adapter2 native audit')
 if value.get('methods',{}).get('expected_method_delta_only') is not True or value.get('metadata',{}).get('expected_metadata_delta_only') is not True:
  raise ValueError('Native method/metadata gates incomplete')


def validate_body_review(value):
 require_observed_pins()
 if canonical(value)!=BODY_REVIEW or value.get('framework_sha256')!=FRAMEWORK or value.get('audit_result_sha256')!=AUDIT_RAW or value.get('method_diff_sha256')!=METHOD_DIFF or value.get('passed') is not True or set(value.get('review',{}))!={'setListAdapter','getListSelectedPoistion','render','dispatchKeyEvent'} or value.get('unrelated_methods_and_class_declarations_protected_by_full_audit') is not True:
  raise ValueError('Actual09 four-method body review pending/failed')


def validate_export(metadata,export):
 require_observed_pins()
 files=export.get('files',{});before=metadata.get('before_closure',{})
 if canonical(files)!=FILES or len(files)!=30 or set(files)!=set(metadata.get('closure',[])) or set(files)!=set(before) or files.get('framework/framework.jar')!=FRAMEWORK or before.get('framework/framework.jar')!=CACHE_FRAMEWORK or metadata.get('baseline_image')!=48 or metadata.get('dialog_overlay_version')!=6 or export.get('dialog_overlay_version')!=6 or metadata.get('accepted_framework_baseline')!=AUDIT_BASE08 or export.get('accepted_framework_baseline')!=AUDIT_BASE08 or len(metadata.get('art_apex',{}))!=24 or any(export.get(k) is not True for k in ['art_apex_unchanged','baseline_preserved','new_class_in_dex']):
  raise ValueError('Unreviewed09 framework export closure')
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
 if proof.get('container_id')!=COMPILED_CID or proof.get('original_lower_all_files_content_metadata_unchanged') is not True or proof.get('lower_entries')!=565530 or proof.get('projected_changed_entries')!=PROJECTED_CHANGED_ENTRIES or proof.get('projected_removed_entries')!=[] or proof.get('before_inventory_sha256')!=metadata['layered_output']['before_inventory_sha256'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=0:
  raise ValueError('Exact terminal09 cache preservation proof missing/failed')


def pack_config(text):
 key='avb_system_add_hashtree_footer_args='
 lines=[line for line in text.splitlines() if line.startswith(key)]
 if len(lines)!=1 or lines[0].split().count('--do_not_generate_fec')!=1 or text.count('/build/'+BASE_NAME+'/')!=2:
  raise ValueError('Image53 FEC0/config path contract lost')
 return text.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/')


def validate_baseline_manifest(m,out):
 if m.get('image')!=53 or m.get('baseline_image')!=52 or m.get('framework_sha256')!=OLD_FRAMEWORK or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True or out.get('image')!=53 or out.get('baseline_image')!=52 or out.get('raw_sha256')!=BASE_RAW or out.get('staging_sha256')!=BASE_MANIFEST or out.get('raw_bytes')!=PARTITION or out.get('optional_fec') is not False or out.get('signed_hashtree_verified') is not True or out.get('avb_verified') is not True:
  raise ValueError('Immutable53 AVB/framework disposition changed')
 if set(m.get('metadata_files_sha256',{}))!=CONTROL_NAMES:raise ValueError('Immutable53 metadata control set changed')


def baseline(base):
 if base.resolve(strict=True)!=base or sha(base/'staging.json')!=BASE_MANIFEST or sha(base/'outputs.json')!=BASE_OUTPUTS or sha(base/'compact-image/system.raw.img')!=BASE_RAW or (base/'build.exit').read_text().strip()!='0':raise ValueError('Immutable53 identity/terminal state changed')
 m=json.loads((base/'staging.json').read_text());out=json.loads((base/'outputs.json').read_text())
 validate_baseline_manifest(m,out)
 for n,d in m['metadata_files_sha256'].items():
  if (base/n).is_symlink() or sha(base/n)!=d:raise ValueError('Image53 control changed: '+n)
 if sha(base/'file_contexts.txt')!=PACK_CONTEXTS or sha(base/'system_image_info.compact.txt')!=PACK_CONFIG53:raise ValueError('Image53 labels/config changed')
 before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
 if before!=json.loads((base/'system-inventory.json').read_text()) or roots!=json.loads((base/'root-inventory.json').read_text()):raise ValueError('Immutable53 packed inventories drifted')
 validate_protected(before)
 if before.get('framework/framework.jar')!=['file',0o644,OLD_FRAMEWORK]:raise ValueError('Image53 framework payload/mode changed')
 return before,roots


def check_stage(stage):
 require_observed_pins();m=json.loads((stage/'staging.json').read_text())
 if (stage/'staging.complete').read_text().strip()!=sha(stage/'staging.json') or m.get('image')!=54 or m.get('baseline_image')!=53 or m.get('base_raw_sha256')!=BASE_RAW or m.get('base_manifest_sha256')!=BASE_MANIFEST or m.get('framework_sha256')!=FRAMEWORK or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True:raise ValueError('Incomplete/unreviewed54 stage')
 if set(m.get('metadata_files_sha256',{}))!=CONTROL_NAMES or sha(stage/'build.sh')!=PACK_SCRIPT:raise ValueError('Stage required control set/build script changed')
 if m.get('build_manifest_sha256')!=COMPILE_STAGE or m.get('outputs_sha256')!=EXPORT or m.get('compiled_audit_canonical_sha256')!=AUDIT or m.get('body_review_canonical_sha256')!=BODY_REVIEW or m.get('cache_preservation_sha256')!=CACHE_PROOF or m.get('cache_preservation_verified') is not True:raise ValueError('Stage lost compiled/review/cache proof gates')
 for n,d in m['metadata_files_sha256'].items():
  if (stage/n).is_symlink() or sha(stage/n)!=d:raise ValueError('Stage control changed: '+n)
 if sha(stage/'compiled-audit.json')!=AUDIT_RAW or sha(stage/'body-review.json')!=BODY_REVIEW_RAW:raise ValueError('Exact review proof bytes changed')
 validate_audit(json.loads((stage/'compiled-audit.json').read_text()));validate_body_review(json.loads((stage/'body-review.json').read_text()))
 meta=json.loads((stage/'compiled-staging.json').read_text());exports=json.loads((stage/'compiled-outputs.json').read_text())
 if sha(stage/'compiled-staging.json')!=COMPILE_STAGE or sha(stage/'compiled-outputs.json')!=EXPORT or sha(stage/'cache-preservation.json')!=CACHE_PROOF:raise ValueError('Compiled proof bytes changed')
 files=validate_export(meta,exports);validate_cache(json.loads((stage/'cache-preservation.json').read_text()),meta)
 before,roots=baseline(stage.parent/BASE_NAME);after=inventory(stage/'compact-system')
 alarms={n:v[2] for n,v in before.items() if n.startswith('product/media/audio/alarms/') and v[0]=='file'}
 if len(alarms)!=8 or m.get('preserved_alarm_files')!=alarms or m.get('art_apex')!=meta['art_apex']:raise ValueError('Alarm/ART closure manifest drift')
 changed=compare_staged(before,after,files)
 if after!=json.loads((stage/'system-inventory.json').read_text()) or roots!=inventory(stage/'compact-root') or roots!=json.loads((stage/'root-inventory.json').read_text()) or before!=json.loads((stage/'baseline-system-inventory.json').read_text()):raise ValueError('Stage/baseline/root inventory changed')
 if set(m['changed'])!=changed or m.get('exported_files')!=files or m.get('protected53_sha256')!=PINS:raise ValueError('Stage closure manifest changed')
 for n in changed:
  if m['changed'][n]!={'before':before[n],'after':after[n]}:raise ValueError('Stage changed payload record mismatch')
 props=(stage.parent/BASE_NAME/'compact-system/build.prop').read_bytes()
 if props.splitlines().count(b'ro.kaidroid.image=53')!=1 or props.count(b'ro.kaidroid.image=53')!=1 or (stage/'compact-system/build.prop').read_bytes()!=props.replace(b'ro.kaidroid.image=53',b'ro.kaidroid.image=54',1):raise ValueError('Unexpected revision mutation')
 if (stage/'system_image_info.compact.txt').read_text()!=pack_config((stage.parent/BASE_NAME/'system_image_info.compact.txt').read_text()):raise ValueError('Pack config drift')
 if shutil.disk_usage(stage).free<2*PARTITION+20*1024**3:raise ValueError('Insufficient pack headroom/emergency floor')
 return m


def launcher():
 return '''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-tcl-calendar-adapter-stage-54"
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
sudo docker run -d --network none --name kaidroid-tcl-calendar-adapter-image54 \\
 -v "$root:/build:ro" \\
 -v "$stage:/build/engineering-tcl-calendar-adapter-stage-54:rw" \\
 kaidroid-build:20261023 bash /build/engineering-tcl-calendar-adapter-stage-54/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def stage(root,build_script,audit,body_review):
 require_observed_pins()
 if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:raise ValueError('Use attested Linux builder1000:1000')
 root=root.resolve(strict=True)
 if str(root)!=ROOT:raise ValueError('Unexpected build root')
 base=root/BASE_NAME;compiled=root/COMPILED;out=root/STAGE_NAME
 if out.exists():raise FileExistsError(out)
 if compiled.resolve(strict=True)!=compiled:raise ValueError('Symlinked compiled stage')
 for name in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',name],capture_output=True).returncode!=1:raise ValueError('Build active or observation failed')
 if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container active; coordinate')
 info=json.loads(subprocess.check_output(['sudo','docker','inspect',COMPILED_CID],text=True))[0];state=info['State']
 if info['Id']!=COMPILED_CID or info.get('Name')!='/kaidroid-tcl-dialog-build09' or info.get('Image')!='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d' or info['Config'].get('User')!='builder' or info['Config'].get('Cmd')!=['bash','/build/tcl-dialog-build09/build.sh'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=0 or (compiled/'build.exit').read_text().strip()!='0' or (compiled/'container-id').read_text().strip()!=COMPILED_CID:raise ValueError('Compiled09 exact terminal container required')
 for path,pin in [(compiled/'staging.json',COMPILE_STAGE),(compiled/'outputs.json',EXPORT),(compiled/'cache-preservation.json',CACHE_PROOF),(build_script,PACK_SCRIPT)]:
  if path.is_symlink() or sha(path)!=pin:raise ValueError('Unreviewed compiled proof/pack script')
 if sha(audit)!=AUDIT_RAW or sha(body_review)!=BODY_REVIEW_RAW:raise ValueError('Exact audit/body proof bytes changed')
 validate_audit(json.loads(audit.read_text()));validate_body_review(json.loads(body_review.read_text()))
 meta=json.loads((compiled/'staging.json').read_text());exports=json.loads((compiled/'outputs.json').read_text());files=validate_export(meta,exports)
 proof=json.loads((compiled/'cache-preservation.json').read_text());validate_cache(proof,meta)
 for n,key in [('cache-lower-before.json','before_inventory_sha256'),('cache-upper-after.json','upper_inventory_sha256'),('cache-view-delta.json','view_delta_sha256')]:
  if sha(compiled/n)!=proof[key]:raise ValueError('Cache journal changed: '+n)
 before,roots=baseline(base)
 for n,d in meta['art_apex'].items():
  if before.get(n,[])!=['file',0o644,d]:raise ValueError('ART baseline changed: '+n)
 for n,d in files.items():
  if (compiled/'output'/n).is_symlink() or sha(compiled/'output'/n)!=d:raise ValueError('Export payload changed: '+n)
 props=(base/'compact-system/build.prop').read_bytes();config=pack_config((base/'system_image_info.compact.txt').read_text())
 if props.splitlines().count(b'ro.kaidroid.image=53')!=1 or props.count(b'ro.kaidroid.image=53')!=1:raise ValueError('Wrong base revision')
 copies=sum((Path(folder)/n).stat().st_size for tree in ('compact-system','compact-root') for folder,_,names in os.walk(base/tree,followlinks=False) for n in names if not (Path(folder)/n).is_symlink())
 free=shutil.disk_usage(root).free
 if free<copies+2*PARTITION+20*1024**3:raise ValueError('Insufficient copy/image/emergency-floor capacity')
 out.mkdir()
 for tree in ('compact-system','compact-root'):shutil.copytree(base/tree,out/tree,symlinks=True)
 (out/'compact-image').mkdir()
 for n in files:shutil.copyfile(compiled/'output'/n,out/'compact-system'/n)
 (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=53',b'ro.kaidroid.image=54',1))
 shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt');(out/'system_image_info.compact.txt').write_text(config,encoding='utf-8')
 after=inventory(out/'compact-system');changed=compare_staged(before,after,files)
 if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:raise ValueError('Immutable baseline/root closure changed')
 alarms={n:v[2] for n,v in before.items() if n.startswith('product/media/audio/alarms/') and v[0]=='file'}
 if len(alarms)!=8:raise ValueError('Alarm closure changed')
 for source,name in [(build_script,'build.sh'),(Path(__file__),'stage-check.py'),(audit,'compiled-audit.json'),(body_review,'body-review.json'),(compiled/'staging.json','compiled-staging.json'),(compiled/'outputs.json','compiled-outputs.json'),(compiled/'cache-preservation.json','cache-preservation.json')]:shutil.copyfile(source,out/name)
 (out/'launch.sh').write_text(launcher(),encoding='utf-8')
 for n,v in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]:
  (out/n).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
 controls=['build.sh','stage-check.py','launch.sh','compiled-audit.json','body-review.json','compiled-staging.json','compiled-outputs.json','cache-preservation.json','system-inventory.json','root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt']
 m=dict(image=54,baseline_image=53,base_raw_sha256=BASE_RAW,base_manifest_sha256=BASE_MANIFEST,framework_sha256=FRAMEWORK,
   build_manifest_sha256=COMPILE_STAGE,outputs_sha256=EXPORT,compiled_audit_canonical_sha256=AUDIT,body_review_canonical_sha256=BODY_REVIEW,
   cache_preservation_sha256=CACHE_PROOF,cache_preservation_verified=True,exported_files=files,art_apex=meta['art_apex'],preserved_alarm_files=alarms,protected53_sha256=PINS,
   changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},metadata_files_sha256={n:sha(out/n) for n in controls},copy_bytes=copies,free_bytes_before=free,system_partition_bytes=PARTITION,
   optional_fec=False,signed_hashtree_required=True,baseline_stage_unchanged=True,root_unchanged=True,built=False,installed=False,raw_uid_gid_xattr_verification_required=True)
 (out/'staging.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8');(out/'staging.complete').write_text(sha(out/'staging.json')+'\n')
 print(json.dumps(m))


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check-stage',type=Path)
 for n in ('root','build-script','audit','body-review'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 if a.check_stage:check_stage(a.check_stage)
 elif all((a.root,a.build_script,a.audit,a.body_review)):stage(a.root,a.build_script,a.audit,a.body_review)
 else:p.error('Require --check-stage or --root/--build-script/--audit/--body-review')

"""Copy audited terminal native10 outputs only; preserve failed build/logs, never compile."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
STAGE='tcl-dialog-build10'
CID='8ca7555194314ee610aa73dd8d03d55b9de79dd310c38e358aac4f8e9af143c9'
MANIFEST='c9960256dd0af13d2381bac700c81221e20776308c3d952395847c68916e6da0'
CONTROLS='3ab2c9187f05364afd21420cd463481a4fd452102d62746a8aa17889e31fda23'
LOG='84a13e2a2928507dbd945e80ca7b0dc3fadc67e99210197cda6ddc09731f5046'
FRAMEWORK='429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53'
FLAGS='9926fe86df5b86b04e9b4eae065d2aa5a1b65f3e640f20e46210e265ff70716c'
AUDIT_RAW='6da05121777f12c48fe8c19dc9f2c224af9b97541e64f84ce7d0330defa8e614'
AUDIT='834e0f680ae13136131f1d6c7b8ac2a86d464f365feb69ffa3df01240387eafa'
CACHE_PROOF='ad0fd76fa0f6ee00e9e269a49e0b0a566a15a9ac0f4ace059e0d5d9dd6eb1d5c'
IMAGE='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
CORE_CONTROLS={'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_audit(value):
 if canonical(value)!=AUDIT or value.get('candidate_sha256')!=FRAMEWORK or value.get('generated_flags_sha256')!=FLAGS or value.get('passed') is not True or value.get('flags',{}).get('exact_two_raw_flag_changes') is not True or value.get('binary',{}).get('passed') is not True or value.get('all_method_bodies_unchanged') is not True or value.get('all_declared_metadata_unchanged') is not True:
  raise ValueError('Not exact observed strict native10 audit')


def validate_terminal(info):
 state=info.get('State',{});config=info.get('Config',{})
 if info.get('Id')!=CID or info.get('Name')!='/kaidroid-'+STAGE or info.get('Image')!=IMAGE or config.get('User')!='builder' or config.get('Cmd')!=['bash','/build/'+STAGE+'/build.sh'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1:
  raise ValueError('Not exact original terminal1/nonOOM container')
 return state


def validate_stage(stage):
 if sha(stage/'staging.json')!=MANIFEST or sha(stage/'control-inputs.json')!=CONTROLS or sha(stage/'build.log')!=LOG or (stage/'build.exit').read_text().strip()!='1' or (stage/'container-id').read_text().strip()!=CID or (stage/'preparation.complete').read_text().strip()!=MANIFEST:
  raise ValueError('Original failed stage/log/completion identity changed')
 controls=json.loads((stage/'control-inputs.json').read_text())
 if set(controls)!=CORE_CONTROLS:raise ValueError('Six-control set changed')
 for name,pin in controls.items():
  if (stage/name).resolve(strict=True)!=stage/name or sha(stage/name)!=pin:raise ValueError('Frozen controller changed: '+name)
 text=(stage/'build.log').read_text()
 if not text.rstrip().endswith('AssertionError: Full generated flags differ from exact two-row prediction') or '[369/369]' not in text or '"phase": "pre-export"' not in text:
  raise ValueError('Not the proven post-compilation newline gate failure')
 spec=json.loads((stage/'staging.json').read_text())
 if len(spec['inputs'])!=96 or len(spec['closure'])!=30 or len(spec['art_apex'])!=24:raise ValueError('Unexpected source/closure/ART shape')
 for name,pin in spec['inputs'].items():
  relative=Path(name);path=stage/'inputs'/relative
  if relative.is_absolute() or '..' in relative.parts or path.resolve(strict=True)!=path or sha(path)!=pin:raise ValueError('Frozen input changed: '+name)
 if (stage/'inputs/generate_hiddenapi_lists.py').stat().st_mode & 0o777!=0o755:raise ValueError('Private generator mode changed')
 if (stage/'output').exists() or (stage/'outputs.json').exists():raise ValueError('Original export already exists; no replacement/retry')
 return spec


def validate_product(product,spec):
 if sha(product/'framework/framework.jar')!=FRAMEWORK:raise ValueError('Audited framework changed')
 for name,pin in spec['art_apex'].items():
  if sha(product/name)!=pin:raise ValueError('Retained ART changed: '+name)
 for name in ('framework/framework-res.apk','framework/services.jar'):
  if sha(product/name)!=spec['before_closure'][name]:raise ValueError('Protected resources/services changed: '+name)
 files={}
 for name in spec['closure']:
  if not re.fullmatch(r'framework/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',name) or '..' in Path(name).parts:raise ValueError('Unreviewed export path')
  path=product/name
  if path.resolve(strict=True)!=path:raise ValueError('Symlinked export payload: '+name)
  files[name]=sha(path)
 return files


def validate_cache(value,spec):
 state=value.get('terminal_state',{})
 if value.get('container_id')!=CID or value.get('original_lower_all_files_content_metadata_unchanged') is not True or value.get('lower_entries')!=565530 or value.get('projected_changed_entries')!=129 or value.get('projected_removed_entries')!=[] or value.get('before_inventory_sha256')!=spec['layered_output']['before_inventory_sha256'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1:
  raise ValueError('Not exact terminal1 complete cache preservation proof')


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--audit',type=Path,required=True);a=p.parse_args()
 if os.name!='posix' or (os.geteuid(),os.getegid())!=(1000,1000):raise ValueError('Use attested Linux builder1000')
 root=a.root.absolute();stage=root/STAGE;recovery=stage/'export-recovery01'
 if str(root)!=ROOT or root.resolve(strict=True)!=root or stage.resolve(strict=True)!=stage or recovery.exists():raise ValueError('Wrong stage or recovery exists; observe original job, never repeat')
 for name in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',name],capture_output=True,timeout=15).returncode!=1:raise ValueError('Live build or failed process observation')
 if subprocess.check_output(['sudo','docker','ps','-q'],text=True,timeout=20).strip():raise ValueError('Container active; no export recovery')
 info=json.loads(subprocess.check_output(['sudo','docker','inspect',CID],text=True,timeout=20))[0];terminal=validate_terminal(info)
 spec=validate_stage(stage)
 if a.audit.is_symlink() or sha(a.audit)!=AUDIT_RAW:raise ValueError('Observed audit proof bytes changed')
 validate_audit(json.loads(a.audit.read_text()))
 if sha(stage/'cache-preservation.json')!=CACHE_PROOF:raise ValueError('Observed cache proof bytes changed')
 validate_cache(json.loads((stage/'cache-preservation.json').read_text()),spec)
 # Load only an exact already-hashed stage control; no foreign imports/actions.
 module_spec=importlib.util.spec_from_file_location('recovery_layer',stage/'layered_dialog_output.py')
 layer=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(layer)
 layer.verify_external_storage(stage);layer.verify_mounts(stage,spec)
 product=stage/'out/target/product/n139dl/system';flags=stage/'out/soong/hiddenapi/hiddenapi-flags.csv'
 if sha(flags)!=FLAGS:raise ValueError('Actual Linux CSV differs from exact LF/two-row prediction')
 files=validate_product(product,spec)
 originals={n:sha(stage/n) for n in CORE_CONTROLS|{'control-inputs.json','preparation.complete','build.log','build.exit','container-id'}}
 needed=sum((product/n).stat().st_size for n in files)+flags.stat().st_size
 if shutil.disk_usage(stage).free<=needed+20*1024**3 or shutil.disk_usage(root).free<=20*1024**3:raise ValueError('Export copy would breach volume floors')
 recovery.mkdir(mode=0o700)
 (recovery/'output').mkdir()
 initial=dict(scope='Audited export-only recovery; original build remains terminal1',original_stage=str(stage),container_id=CID,
  original_terminal_state=terminal,originals_sha256=originals,audit_sha256=AUDIT_RAW,framework_sha256=FRAMEWORK,
  generated_flags_sha256=FLAGS,compiler_restarted=False,original_failed_status_preserved=True,installed=False)
 with (recovery/'recovery-start.json').open('x',encoding='utf-8') as f:json.dump(initial,f,indent=2);f.write('\n')
 for name,pin in files.items():
  target=recovery/'output'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(product/name,target)
  if sha(target)!=pin:raise ValueError('Recovery copy changed: '+name)
 shutil.copyfile(flags,recovery/'hiddenapi-flags.csv');shutil.copyfile(a.audit,recovery/'compiled-audit.json')
 shutil.copyfile(stage/'cache-preservation.json',recovery/'cache-preservation.json')
 result=dict(files=files,baseline_image=spec['baseline_image'],baseline_preserved=True,art_apex_unchanged=True,
  accepted_framework_baseline=spec['accepted_framework_baseline'],dialog_overlay_version=spec['dialog_overlay_version'],
  hiddenapi_generated_flags_sha256=FLAGS,hiddenapi_generator_sha256=spec['hiddenapi_generator']['candidate_sha256'],
  source_manifest_sha256=MANIFEST,original_build_exit_code=1,export_only_recovery=True,
  strict_native_audit_sha256=AUDIT_RAW,cache_preservation_sha256=CACHE_PROOF,cache_preservation_verified=True,packed=False,installed=False)
 with (recovery/'outputs.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
 if originals!={n:sha(stage/n) for n in originals}:raise ValueError('Original failed job/controller files changed')
 layer.verify_mounts(stage,spec)
 report=dict(initial,terminal=True,passed=True,outputs_sha256=sha(recovery/'outputs.json'),exported_files=30,
  copied_flags_sha256=sha(recovery/'hiddenapi-flags.csv'),cache_preservation_sha256=CACHE_PROOF,full_cache_proof_verified=True,full_parity=False)
 with (recovery/'recovery.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report))


if __name__=='__main__':main()

"""Copy reviewed terminal native12 outputs only; preserve failed job, never compile."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT='/opt/kaidroid/kaidroid-build-20261023'
STAGE='tcl-dialog-build12'
CID='d463b0b93294f6d65712d46702eac3bb15b18a4c94f4714560489901c5a93aa3'
MANIFEST='794416e1fdc169b1374010c0550f1ea51d45eedc65f3c669bb64de06045a3600'
CONTROLS='9a4bea5999ebdfbff17baf554d0937739e6a4a90ab161dfe24be1e1e2b3decd4'
LOG='87d4510515d5e2acb3d4b2d1885e5de1da6c7b3e89f56b20bfd1b7962017b8da'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
FLAGS='d1c91728e194307c40157dc10c9c0e72ff31804a83ab2c407adbb6195764dc15'
AUDIT_RAW='a780e970acc7ad915576e95583294d6b1ccbf8ddeeda49eb409da11b4fc291f4'
AUDIT='543b16ffd0594fc37c2c20a543473649128f565db865a860e18706fd9bdd3bb3'
CACHE_PROOF='04b1802f3503e808c8218f18b3bc6b908b2377bcb7b360d1a91b2e2bee445907'
PLAN='793879241f640431756a88b0cf2abf1b7eb5dae00626a0dd777c246780ccdade'
GRAPH='f212be5a327c86f60fdd4d42c9a697eedfe640ecbadc0c87efb1224bc1583c26'
PLAN_REVIEW='eed5dbf118681de069c692cee8944eeb19c021e06a796a516daf6d96f8b2686c'
HIDDEN_PLAN='f246bd3233edbc5a09cf814e53cfb88a598a9994f84216c7621f6cc8a7c11fd5'
BODY_DIFF='367475308d86dabf33cc14baebb0b901b2c3081634b2945b9b93f9f6bdf154ae'
IMAGE='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
CORE_CONTROLS={'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_audit(value):
 if canonical(value)!=AUDIT:raise ValueError('Independent parent review content changed')
 if value.get('candidate_sha256')!=FRAMEWORK or value.get('baseline_sha256')!='a5f20e01980dbc5a7ea71f883b24d7f77d2781b2407fda9aa0e298f7c4490330' or value.get('full_acceptance') is not True or value.get('api_classification_review_pending') is not False or value.get('diff_sha256')!=BODY_DIFF or len(value.get('independent_body_review',[]))!=6:
  raise ValueError('Not completed native12 independent body review')
 flags=value.get('raw_flags',{});csv=value.get('csv',{});methods=value.get('methods',{})
 if flags.get('retained_members')!=284580 or flags.get('all_existing_encoded_words_and_kinds_unchanged') is not True or flags.get('new_blacklist2_members')!=7 or flags.get('inherited_sdk_override_raw16') is not True or csv.get('retained_rows')!=429762 or csv.get('total_rows')!=429770 or csv.get('all_old_classifications_unchanged') is not True or methods.get('before_methods')!=147658 or methods.get('after_methods')!=147664 or methods.get('all_other_existing_bodies_unchanged') is not True:
  raise ValueError('Native12 complete word/CSV/body inventory review missing')


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
 if not text.rstrip().endswith('AssertionError: Full generated flags differ from exact retained-plus-eight-private-API prediction') or '[369/369]' not in text or '"phase": "pre-export"' not in text:
  raise ValueError('Not the proven post-compilation inherited-flag gate failure')
 spec=json.loads((stage/'staging.json').read_text())
 if len(spec['inputs'])!=98 or len(spec['closure'])!=30 or len(set(spec['closure']))!=30 or len(spec['art_apex'])!=24:raise ValueError('Unexpected source/closure/ART shape')
 validate_inputs(stage,spec)
 if (stage/'inputs/generate_hiddenapi_lists.py').stat().st_mode & 0o777!=0o755:raise ValueError('Private generator mode changed')
 if (stage/'output').exists() or (stage/'outputs.json').exists():raise ValueError('Original export already exists; no replacement/retry')
 return spec


def validate_inputs(stage,spec):
 for name,pin in spec['inputs'].items():
  relative=Path(name);path=stage/'inputs'/relative
  if relative.anchor or '..' in relative.parts or path.resolve(strict=True)!=path or sha(path)!=pin:
   raise ValueError('Frozen input changed: '+name)


def validate_plan(stage):
 if sha(stage/'plan-review.json')!=PLAN_REVIEW or sha(stage/'hiddenapi-plan.json')!=HIDDEN_PLAN:
  raise ValueError('Exact released plan or hidden-API dependency proof changed')
 review=json.loads((stage/'plan-review.json').read_text())
 if sha(stage/'dependency-plan.log')!=PLAN or sha(stage/'source-graph.json')!=GRAPH or review.get('reviewed') is not True or review.get('plan_sha256')!=PLAN or review.get('source_graph_sha256')!=GRAPH or review.get('staging_sha256')!=MANIFEST or len(review.get('review_note','').strip())<20:
  raise ValueError('Released dependency/source plan differs')
 return review


def validate_baselines(root,spec):
 for name,pin in spec['baseline_pins'].items():
  relative=Path(name);path=root/relative
  if relative.anchor or '..' in relative.parts or path.resolve(strict=True)!=path or sha(path)!=pin:
   raise ValueError('Retained baseline changed: '+name)


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
 if value.get('container_id')!=CID or value.get('original_lower_all_files_content_metadata_unchanged') is not True or value.get('lower_entries')!=565530 or value.get('projected_changed_entries')!=146 or value.get('projected_removed_entries')!=[] or value.get('before_inventory_sha256')!=spec['layered_output']['before_inventory_sha256'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1:
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
 validate_plan(stage)
 validate_baselines(root,spec)
 if a.audit.is_symlink() or sha(a.audit)!=AUDIT_RAW:raise ValueError('Observed audit proof bytes changed')
 validate_audit(json.loads(a.audit.read_text()))
 if sha(stage/'cache-preservation.json')!=CACHE_PROOF:raise ValueError('Observed cache proof bytes changed')
 validate_cache(json.loads((stage/'cache-preservation.json').read_text()),spec)
 # Load only an exact already-hashed stage control; no foreign imports/actions.
 module_spec=importlib.util.spec_from_file_location('recovery_layer',stage/'layered_dialog_output.py')
 sys.dont_write_bytecode=True
 layer=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(layer)
 layer.verify_external_storage(stage);layer.verify_mounts(stage,spec)
 product=stage/'out/target/product/n139dl/system';flags=stage/'out/soong/hiddenapi/hiddenapi-flags.csv'
 if flags.resolve(strict=True)!=flags or sha(flags)!=FLAGS:raise ValueError('Actual Linux CSV differs from exact inherited-override prediction')
 files=validate_product(product,spec)
 originals={n:sha(stage/n) for n in CORE_CONTROLS|{'control-inputs.json','preparation.complete','build.log','build.exit','container-id','plan-review.json','dependency-plan.log','source-graph.json','hiddenapi-plan.json','cache-preservation.json'}}
 needed=sum((product/n).stat().st_size for n in files)+flags.stat().st_size
 if shutil.disk_usage(stage).free<=needed+20*1024**3 or shutil.disk_usage(root).free<=20*1024**3:raise ValueError('Export copy would breach volume floors')
 recovery.mkdir(mode=0o700)
 (recovery/'output').mkdir()
 initial=dict(scope='Audited export-only recovery; original build remains terminal1',original_stage=str(stage),container_id=CID,
  original_terminal_state=terminal,originals_sha256=originals,audit_sha256=AUDIT_RAW,framework_sha256=FRAMEWORK,
  reviewed_plan_sha256=PLAN,source_graph_sha256=GRAPH,body_diff_sha256=BODY_DIFF,
  generated_flags_sha256=FLAGS,compiler_restarted=False,original_failed_status_preserved=True,installed=False)
 with (recovery/'recovery-start.json').open('x',encoding='utf-8') as f:json.dump(initial,f,indent=2);f.write('\n')
 for name,pin in files.items():
  target=recovery/'output'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(product/name,target)
  if sha(target)!=pin:raise ValueError('Recovery copy changed: '+name)
 shutil.copyfile(flags,recovery/'hiddenapi-flags.csv');shutil.copyfile(a.audit,recovery/'compiled-audit.json')
 shutil.copyfile(stage/'cache-preservation.json',recovery/'cache-preservation.json')
 if sha(recovery/'hiddenapi-flags.csv')!=FLAGS or sha(recovery/'compiled-audit.json')!=AUDIT_RAW or sha(recovery/'cache-preservation.json')!=CACHE_PROOF:
  raise ValueError('Recovery proof/CSV copy changed')
 result=dict(files=files,baseline_image=spec['baseline_image'],baseline_preserved=True,art_apex_unchanged=True,
  accepted_framework_baseline=spec['accepted_framework_baseline'],dialog_overlay_version=spec['dialog_overlay_version'],
  hiddenapi_generated_flags_sha256=FLAGS,hiddenapi_generator_sha256=spec['hiddenapi_generator']['candidate_sha256'],
  source_manifest_sha256=MANIFEST,original_build_exit_code=1,export_only_recovery=True,
  strict_native_audit_sha256=AUDIT_RAW,cache_preservation_sha256=CACHE_PROOF,cache_preservation_verified=True,packed=False,installed=False)
 with (recovery/'outputs.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
 if originals!={n:sha(stage/n) for n in originals}:raise ValueError('Original failed job/controller files changed')
 if validate_product(product,spec)!=files:raise ValueError('Built export sources changed during copy')
 validate_inputs(stage,spec)
 validate_baselines(root,spec)
 layer.verify_mounts(stage,spec)
 report=dict(initial,terminal=True,passed=True,outputs_sha256=sha(recovery/'outputs.json'),exported_files=30,
  copied_flags_sha256=sha(recovery/'hiddenapi-flags.csv'),cache_preservation_sha256=CACHE_PROOF,full_cache_proof_verified=True,full_parity=False)
 with (recovery/'recovery.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report))


if __name__=='__main__':main()

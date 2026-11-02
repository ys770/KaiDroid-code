"""Image58-to59 exact handover contract; unbound checkout cannot stage an image."""
import hashlib,json,re
from pathlib import Path

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
BASE_NAME='engineering-tcl-app-widgets-stage-58-retry01'
NAME='engineering-tcl-ime-handover-stage-59'
BACKING='/mnt/ext1/kaidroid-tcl-ime-handover-image59'
UNIT='kaidroid-tcl-ime-handover-image59-watchdog.service'
BASE='807a0a5be41c4c6e1523e114588c9cd935fbcd49c0e4a3ab6d55781eb2dcb721'
BASE_MANIFEST='8ef809f80d2bdaccf061c2b9123fc013a915dea4bb0c2df89d1e80ea24587cf1'
BASE_OUTPUTS='dee0d92274e44d7ae6de36b32fb05d671927a1acdbbe32bd1c50193c08203de3'
PROPOSAL='UNBOUND_REQUIRES_REVIEWED_PACKET'
NATIVE='tcl-dialog-build14'
CID='5bdefa83e17f63f43d2bc0a758c6040b9c84681129dbfe41bd18038b66b4fff1'
FLAGS='faf76189eda12b26f695f62bd7ac215fbe00ec5e2e8895046f0ab4599f9a48a8'
OLD_FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
FRAMEWORK='04eeb83ba7b062a6da7610d20829fc088f9cdf89d9474540e74b65da9f4e28bf'
BUILDER='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
MMS='system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk'
PARTITION=834666496
FLOOR=20*1024**3
TOOLS={'ime_handover_image59_contract.py','ime_handover_image59_storage.py',
 'stage_tcl_ime_handover_image59.py','build_tcl_ime_handover_image59.sh',
 'verify_tcl_ime_handover_image59.py','tcl_dialog_external_storage.py',
 'image56_contract.py','reconcile_image59.py','image59_mount_graph.py'}

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):h.update(block)
 return h.hexdigest()

def dump(path,value):
 with path.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2);stream.write('\n')

def props59(raw):
 if raw.splitlines().count(b'ro.kaidroid.image=58')!=1 or raw.count(b'ro.kaidroid.image=58')!=1:raise ValueError('Exact image58 properties required')
 return raw.replace(b'ro.kaidroid.image=58',b'ro.kaidroid.image=59',1)

def config59(raw):
 before=('/build/'+BASE_NAME+'/').encode();after=('/build/'+NAME+'/').encode()
 if raw.count(before)!=2 or raw.count(b'--do_not_generate_fec')!=1:raise ValueError('Baseline58 pack paths/FEC differ')
 return raw.replace(before,after)

def proposal(path,pin=None):
 expected=PROPOSAL if pin is None else pin
 if not re.fullmatch('[0-9a-f]{64}',expected) or path.is_symlink() or sha(path)!=expected:raise ValueError('Exact reviewed59 proposal required')
 r=json.loads(path.read_text())
 if (r.get('image'),r.get('baseline_image'),r.get('base_raw_sha256'),r.get('base_manifest_sha256'),r.get('base_outputs_sha256'))!=(59,58,BASE,BASE_MANIFEST,BASE_OUTPUTS):raise ValueError('Unexpected58-to59 identity')
 if len(r.get('exported_files',{}))!=30 or r['exported_files'].get('framework/framework.jar')!=FRAMEWORK or r.get('content_inset_candidate_included') is not False or r.get('scrollbar_candidate_included') is not False or r.get('ims_candidate_included') is not False or r.get('contacts_update_folded_into_system') is not False:raise ValueError('Unexpected59 payload scope')
 if set(r['changed'])-({'build.prop'}|set(r['exported_files'])) or 'build.prop' not in r['changed'] or 'framework/framework.jar' not in r['changed'] or set(r['protected58'])&set(r['changed']):raise ValueError('Changed/protected path closure differs')
 for n in set(r['exported_files'])|set(r['protected58'])|set(r['changed']):
  if '\\' in n or Path(n).is_absolute() or '..' in Path(n).parts:raise ValueError('Noncanonical proposal path')
 return r

def validate_native_proofs(meta,exports,cache,review,r):
 if exports.get('files')!=r['exported_files'] or exports.get('accepted_framework_baseline')!=OLD_FRAMEWORK or exports.get('hiddenapi_generated_flags_sha256')!=FLAGS or exports.get('art_apex_unchanged') is not True or exports.get('baseline_preserved') is not True:raise ValueError('Native14 complete export closure differs')
 if len(meta.get('inputs',{}))!=98 or len(meta.get('art_apex',{}))!=24 or any(r['protected58'].get(n)!=d for n,d in meta['art_apex'].items()):raise ValueError('Native14 source/runtime ART differs')
 state=cache.get('terminal_state',{})
 if cache.get('container_id')!=CID or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('lower_entries')!=565530 or cache.get('before_inventory_sha256')!=meta['layered_output']['before_inventory_sha256']:raise ValueError('Native14 lower preservation missing')
 if state.get('Status')!='exited' or state.get('ExitCode')!=0 or state.get('Running') is not False or state.get('Restarting') is not False or state.get('OOMKilled') is not False or state.get('Pid')!=0:raise ValueError('Native14 must be terminal0/nonOOM')
 if review.get('passed') is not True or review.get('independent_body_review_recorded') is not True or review.get('structural_checks_passed') is not True or review.get('candidate_sha256')!=FRAMEWORK or review.get('baseline_sha256')!=OLD_FRAMEWORK or review.get('body_diff_sha256')!=r['reviewed_body_diff_sha256']:raise ValueError('Native14 independent reviewed-body proof missing')
 methods=review.get('methods',{});flags=review.get('raw_flags',{})
 if len(methods.get('changed',[]))!=5 or len(methods.get('added',[]))!=15 or methods.get('removed')!=[] or methods.get('all_other_existing_bodies_unchanged') is not True or flags.get('all_existing_words_and_kinds_unchanged') is not True or flags.get('added_members')!=23 or review.get('all_old_csv_rows_unchanged') is not True or review.get('added_csv_rows')!=23:raise ValueError('Native14 method/flag scope differs')
 if (methods.get('before_methods'),methods.get('after_methods'),review.get('retained_csv_rows'),flags.get('new_blacklist_raw2'),flags.get('new_inherited_runnable_raw24'))!=(147664,147679,429770,22,1):raise ValueError('Native14 full method/CSV inventory differs')
 declarations=review.get('metadata',{})
 if declarations.get('existing_declarations_retained') is not True or declarations.get('exact_sdk_predicted_private_delta') is not True or review.get('archives',{}).get('all_non_dex_payloads_identical') is not True:raise ValueError('Native14 declaration/nonDEX audit missing')

def compare_trees(before,after,r):
 if before.keys()!=after.keys():raise ValueError('Staged path coverage differs')
 changed={n for n in before if before[n]!=after[n]}
 if changed!=set(r['changed']):raise ValueError('Staged change closure differs')
 for n in changed:
  a,b=before[n],after[n];expected=r['changed'][n]
  if a[0]!='file' or b[0]!='file' or a[:2]!=b[:2] or a[2]!=expected['before']['sha256'] or b[2]!=expected['after']['sha256']:raise ValueError('Staged payload/mode differs: '+n)
 for n,pin in {**r['protected58'],**r['exported_files']}.items():
  if after[n][0]!='file' or after[n][2]!=pin:raise ValueError('Protected/exported file differs: '+n)
 return changed

def compare_raw(before,after,bx,ax,oldprops,newprops,r):
 if before.keys()!=after.keys() or bx.keys()!=before.keys() or ax.keys()!=after.keys() or bx!=ax:raise ValueError('Raw coverage/xattrs differ')
 changed={n for n in before if before[n]!=after[n]}
 if changed!={'/system/'+n for n in r['changed']}:raise ValueError('Raw change closure differs')
 for n,expected in r['changed'].items():
  if before['/system/'+n]!=expected['before'] or after['/system/'+n]!=expected['after']:raise ValueError('Raw content/UID/GID/mode/kind differs: '+n)
 for n,pin in r['protected58'].items():
  if before['/system/'+n].get('sha256')!=pin or after['/system/'+n].get('sha256')!=pin:raise ValueError('Protected58 payload differs: '+n)
 for n,pin in r['exported_files'].items():
  if after['/system/'+n].get('sha256')!=pin:raise ValueError('Complete30 export differs: '+n)
 if newprops!=props59(oldprops):raise ValueError('Additional property mutation')
 for props,rows in [(oldprops,before),(newprops,after)]:
  if rows['/system/build.prop'].get('sha256')!=hashlib.sha256(props).hexdigest():raise ValueError('Property hash differs')
 return changed

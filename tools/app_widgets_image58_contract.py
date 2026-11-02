"""Fixed image57-to58 app-widget contract; no host or phone mutations."""
import hashlib,json
from pathlib import Path

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
BASE_NAME='engineering-tcl-ime-footer-stage-57-retry02'
NAME='engineering-tcl-app-widgets-stage-58-retry01'
BACKING='/mnt/ext1/kaidroid-tcl-app-widgets-image58-retry01'
UNIT='kaidroid-tcl-app-widgets-image58-retry01-watchdog.service'
BASE='8c635d5060196f6dd56290ab32c63e2ba1f16c22f7d82e33844030c83363fa97'
BASE_MANIFEST='284386c47e6f577c8ff6dc6d934702ae6704b1a37615b418c71b7109cc674949'
BASE_OUTPUTS='60d6a18911d5187aee2ac029d7b0ad783e558bc26dc3ede065ed27ce3a24d13e'
PROPOSAL='ac1a639d7d6e26d889c88eed5acd4d0693ef0c3eb6b5580bd22ff1b45a9e8713'
NATIVE='tcl-dialog-build12'
CID='d463b0b93294f6d65712d46702eac3bb15b18a4c94f4714560489901c5a93aa3'
FLAGS='d1c91728e194307c40157dc10c9c0e72ff31804a83ab2c407adbb6195764dc15'
RECOVERY='1def8a52b57e955a28ce1f9097130a230083bfab2b2f4ad5ca2d90b750f26c12'
BUILDER='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
MMS='system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk'
PARTITION=834666496
FLOOR=20*1024**3
TOOLS={'app_widgets_image58_contract.py','app_widgets_image58_storage.py',
 'stage_tcl_app_widgets_image58.py','build_tcl_app_widgets_image58.sh',
 'verify_tcl_app_widgets_image58.py','tcl_dialog_external_storage.py','image56_contract.py','reconcile_image58.py','image58_mount_graph.py'}


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):h.update(block)
 return h.hexdigest()


def dump(path,value):
 with path.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2);stream.write('\n')


def proposal(path):
 if path.is_symlink() or sha(path)!=PROPOSAL:raise ValueError('Exact reviewed57 proposal required')
 r=json.loads(path.read_text())
 if r['image']!=58 or r['baseline_image']!=57 or r['base_raw_sha256']!=BASE or len(r['changed'])!=15 or len(r['exported_files'])!=30 or MMS in r['changed'] or r.get('content_inset_candidate_included') is not False:
  raise ValueError('Unexpected57 shape')
 return r


def props58(raw):
 if raw.splitlines().count(b'ro.kaidroid.image=57')!=1 or raw.count(b'ro.kaidroid.image=57')!=1:raise ValueError('Wrong56 properties')
 return raw.replace(b'ro.kaidroid.image=57',b'ro.kaidroid.image=58',1)


def config58(raw):
 before=('/build/'+BASE_NAME+'/').encode();after=('/build/'+NAME+'/').encode()
 if raw.count(before)!=2 or raw.count(b'--do_not_generate_fec')!=1:raise ValueError('Baseline pack path/FEC differs')
 return raw.replace(before,after)


def compare_trees(before,after,r):
 if before.keys()!=after.keys():raise ValueError('Staged path coverage changed')
 changed={n for n in before if before[n]!=after[n]}
 if changed!=set(r['changed']):raise ValueError('Not exact15 staged changes')
 for n in changed:
  a,b=before[n],after[n];expected=r['changed'][n]
  if a[0]!='file' or b[0]!='file' or a[:2]!=b[:2] or a[2]!=expected['before']['sha256'] or b[2]!=expected['after']['sha256']:
   raise ValueError('Staged payload/mode differs: '+n)
 for n,pin in {**r['protected57'],**r['exported_files']}.items():
  if after[n][0]!='file' or after[n][2]!=pin:raise ValueError('Protected/exported file differs: '+n)
 return changed


def validate_native_proofs(meta,exports,cache,review,r,recovery):
 state=cache.get('terminal_state',{})
 if exports.get('files')!=r['exported_files'] or exports.get('accepted_framework_baseline')!='a5f20e01980dbc5a7ea71f883b24d7f77d2781b2407fda9aa0e298f7c4490330' or exports.get('hiddenapi_generated_flags_sha256')!=FLAGS or exports.get('export_only_recovery') is not True or exports.get('original_build_exit_code')!=1 or exports.get('cache_preservation_verified') is not True:
  raise ValueError('Wrong recovered native12 export closure')
 if len(meta.get('inputs',{}))!=98 or len(meta.get('art_apex',{}))!=24 or any(r['protected57'].get(n)!=d for n,d in meta['art_apex'].items()):
  raise ValueError('Native source/retained24ART differs')
 if cache.get('container_id')!=CID or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('lower_entries')!=565530 or cache.get('projected_changed_entries')!=146 or cache.get('projected_removed_entries')!=[] or cache.get('before_inventory_sha256')!=meta['layered_output']['before_inventory_sha256']:
  raise ValueError('Native12 full-cache preservation differs')
 if state.get('Status')!='exited' or state.get('ExitCode')!=1 or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0:
  raise ValueError('Original native12 not terminal1/nonOOM')
 if review.get('full_acceptance') is not True or review.get('candidate_sha256')!=r['native12_framework_sha256'] or review.get('diff_sha256')!='367475308d86dabf33cc14baebb0b901b2c3081634b2945b9b93f9f6bdf154ae' or len(review.get('independent_body_review',[]))!=6 or review.get('raw_flags',{}).get('all_existing_encoded_words_and_kinds_unchanged') is not True:
  raise ValueError('Native12 independent exact-body review missing')
 if recovery.get('passed') is not True or recovery.get('terminal') is not True or recovery.get('container_id')!=CID or recovery.get('framework_sha256')!=r['native12_framework_sha256'] or recovery.get('generated_flags_sha256')!=FLAGS or recovery.get('compiler_restarted') is not False or recovery.get('original_failed_status_preserved') is not True or recovery.get('outputs_sha256')!=r['compiled_outputs_sha256']:
  raise ValueError('Native12 export-only recovery proof missing')


def compare_raw(before,after,bx,ax,oldprops,newprops,r):
 if before.keys()!=after.keys() or bx.keys()!=before.keys() or ax.keys()!=after.keys() or bx!=ax:raise ValueError('Raw path/xattr coverage differs')
 changed={n for n in before if before[n]!=after[n]}
 if changed!={'/system/'+n for n in r['changed']}:raise ValueError('Not exact15 raw changes')
 for n,expected in r['changed'].items():
  key='/system/'+n
  if before[key]!=expected['before'] or after[key]!=expected['after']:raise ValueError('Raw content/UID/GID/mode/kind differs: '+n)
 for n,pin in r['protected57'].items():
  if before['/system/'+n].get('sha256')!=pin or after['/system/'+n].get('sha256')!=pin:raise ValueError('Protected56 payload differs: '+n)
 for n,pin in r['exported_files'].items():
  if after['/system/'+n].get('sha256')!=pin:raise ValueError('Full30 export differs: '+n)
 if newprops!=props58(oldprops):raise ValueError('Additional property mutation')
 for props,rows in [(oldprops,before),(newprops,after)]:
  if rows['/system/build.prop'].get('sha256')!=hashlib.sha256(props).hexdigest():raise ValueError('Property bytes/hash differ')
 return changed

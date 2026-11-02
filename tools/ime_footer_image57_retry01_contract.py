"""Fixed image56-to57 content contract; no process, mount or phone mutations."""
import hashlib,json
from pathlib import Path

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
BASE_NAME='engineering-services-appimage-stage-56'
NAME='engineering-tcl-ime-footer-stage-57-retry01'
BACKING='/mnt/ext1/kaidroid-tcl-ime-footer-image57-retry01'
UNIT='kaidroid-tcl-ime-footer-image57-retry01-watchdog.service'
BASE='31276ba89d9a82184ded209f4eed8e69d23029bba47ccc32b0885944339bd25f'
BASE_MANIFEST='f4493272c4ef7ccec13de89123785c535bad3e8963aa57d3c4251565362fbae0'
BASE_OUTPUTS='b21ae7b1f7b103d7b3508c41f882f27b40d7e2e4bc5727134e46cf3c9a362c12'
PROPOSAL='2dea745aa610764e2b68024f67b9f48d41ff1be2636211e73d3815778bd80b70'
NATIVE='tcl-dialog-build11'
CID='027e91ff2bb67e0cb502c2e15d8eb1d7448f24604cd30ac8a8c624be6876e9b7'
BUILDER='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
MMS='system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk'
PARTITION=834666496
FLOOR=20*1024**3
TOOLS={'ime_footer_image57_retry01_contract.py','ime_footer_image57_retry01_storage.py',
 'stage_tcl_ime_footer_image57_retry01.py','build_tcl_ime_footer_image57_retry01.sh',
 'verify_tcl_ime_footer_image57_retry01.py','tcl_dialog_external_storage.py','image56_contract.py','reconcile_image57_pack.py'}


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
 if r['image']!=57 or r['baseline_image']!=56 or r['base_raw_sha256']!=BASE or len(r['changed'])!=13 or len(r['exported_files'])!=30:
  raise ValueError('Unexpected57 shape')
 return r


def props57(raw):
 if raw.splitlines().count(b'ro.kaidroid.image=56')!=1 or raw.count(b'ro.kaidroid.image=56')!=1:raise ValueError('Wrong56 properties')
 return raw.replace(b'ro.kaidroid.image=56',b'ro.kaidroid.image=57',1)


def config57(raw):
 before=('/build/'+BASE_NAME+'/').encode();after=('/build/'+NAME+'/').encode()
 if raw.count(before)!=2 or raw.count(b'--do_not_generate_fec')!=1:raise ValueError('Baseline pack path/FEC differs')
 return raw.replace(before,after)


def compare_trees(before,after,r):
 if before.keys()!=after.keys():raise ValueError('Staged path coverage changed')
 changed={n for n in before if before[n]!=after[n]}
 if changed!=set(r['changed']):raise ValueError('Not exact13 staged changes')
 for n in changed:
  a,b=before[n],after[n];expected=r['changed'][n]
  if a[0]!='file' or b[0]!='file' or a[:2]!=b[:2] or a[2]!=expected['before']['sha256'] or b[2]!=expected['after']['sha256']:
   raise ValueError('Staged payload/mode differs: '+n)
 for n,pin in {**r['protected56'],**r['exported_files']}.items():
  if after[n][0]!='file' or after[n][2]!=pin:raise ValueError('Protected/exported file differs: '+n)
 return changed


def validate_native_proofs(meta,exports,cache,review,r):
 state=cache.get('terminal_state',{})
 if exports.get('files')!=r['exported_files'] or exports.get('accepted_framework_baseline')!='429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53' or exports.get('hiddenapi_generated_flags_sha256')!='bb6da7de3b49099e28eb3aa102bd5e0d06cf02ab4316a49adc677e9491a3a979':
  raise ValueError('Wrong native11 export closure')
 if len(meta.get('inputs',{}))!=97 or len(meta.get('art_apex',{}))!=24 or any(r['protected56'].get(n)!=d for n,d in meta['art_apex'].items()):
  raise ValueError('Native source/retained24ART differs')
 if cache.get('container_id')!=CID or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('lower_entries')!=565530 or cache.get('projected_changed_entries')!=143 or cache.get('projected_removed_entries')!=[] or cache.get('before_inventory_sha256')!=meta['layered_output']['before_inventory_sha256']:
  raise ValueError('Native11 full-cache preservation differs')
 if state.get('Status')!='exited' or state.get('ExitCode')!=0 or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0:
  raise ValueError('Native11 not terminal0/nonOOM')
 structural=review.get('structural_audit',{});body=review.get('independent_body_review',{})
 if review.get('combined_source_binary_review_passed') is not True or structural.get('structural_checks_passed') is not True or structural.get('candidate_sha256')!=r['native11_framework_sha256'] or body.get('passed') is not True or body.get('diff_sha256')!=structural.get('body_diff_sha256') or body.get('source_sha256')!=meta['inputs'].get('InputMethodService.java'):
  raise ValueError('Native11 independent exact-body review missing')


def compare_raw(before,after,bx,ax,oldprops,newprops,r):
 if before.keys()!=after.keys() or bx.keys()!=before.keys() or ax.keys()!=after.keys() or bx!=ax:raise ValueError('Raw path/xattr coverage differs')
 changed={n for n in before if before[n]!=after[n]}
 if changed!={'/system/'+n for n in r['changed']}:raise ValueError('Not exact13 raw changes')
 for n,expected in r['changed'].items():
  key='/system/'+n
  if before[key]!=expected['before'] or after[key]!=expected['after']:raise ValueError('Raw content/UID/GID/mode/kind differs: '+n)
 for n,pin in r['protected56'].items():
  if before['/system/'+n].get('sha256')!=pin or after['/system/'+n].get('sha256')!=pin:raise ValueError('Protected56 payload differs: '+n)
 for n,pin in r['exported_files'].items():
  if after['/system/'+n].get('sha256')!=pin:raise ValueError('Full30 export differs: '+n)
 if newprops!=props57(oldprops):raise ValueError('Additional property mutation')
 for props,rows in [(oldprops,before),(newprops,after)]:
  if rows['/system/build.prop'].get('sha256')!=hashlib.sha256(props).hexdigest():raise ValueError('Property bytes/hash differ')
 return changed

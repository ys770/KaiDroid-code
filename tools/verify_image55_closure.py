"""Verify full immutable54-to-access55 raw contents/inode/xattr closure; never flash."""
import argparse
import json
from pathlib import Path
import stage_tcl_dialog_access_image55 as stage


def validate_manifest(m):
 stage.require_observed_pins()
 if m.get('image')!=55 or m.get('baseline_image')!=54 or m.get('base_raw_sha256')!=stage.BASE_RAW or m.get('base_manifest_sha256')!=stage.BASE_MANIFEST or m.get('framework_sha256')!=stage.FRAMEWORK or m.get('build_manifest_sha256')!=stage.COMPILE_STAGE or m.get('outputs_sha256')!=stage.EXPORT or m.get('compiled_audit_canonical_sha256')!=stage.AUDIT or m.get('recovery_review_canonical_sha256')!=stage.RECOVERY or m.get('cache_preservation_sha256')!=stage.CACHE_PROOF or m.get('cache_preservation_verified') is not True or stage.canonical(m.get('exported_files'))!=stage.FILES or len(m.get('preserved_alarm_files',{}))!=8 or len(m.get('art_apex',{}))!=24 or m.get('protected54_sha256')!=stage.PINS or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True:
  raise ValueError('Unreviewed image55 manifest')
 if set(m['changed'])!=stage.EXPECTED_CHANGED or not set(m['changed'])<=set(m['exported_files'])|{'build.prop'} or set(m['changed'])&set(stage.PINS):raise ValueError('Unreviewed change set')


def compare_raw(before,after,oldprops,newprops,m,bx,ax):
 validate_manifest(m)
 if before.keys()!=after.keys():raise ValueError('Raw entry set changed')
 changed={n for n in before if before[n]!=after[n]}
 if changed!={'/system/'+n for n in m['changed']}:raise ValueError('Raw changed set differs from reviewed stage')
 for name in changed:
  old,new=before[name],after[name]
  if {k:v for k,v in old.items() if k!='sha256'}!={k:v for k,v in new.items() if k!='sha256'}:raise ValueError('Raw inode mode/UID/GID/kind changed: '+name)
  expected=m['changed'][name.removeprefix('/system/')]
  if old.get('sha256')!=expected['before'][2] or new.get('sha256')!=expected['after'][2]:raise ValueError('Raw content differs from staged delta: '+name)
 for n,d in m['exported_files'].items():
  if after['/system/'+n].get('sha256')!=d:raise ValueError('Export content mismatch: '+n)
 for n,d in {**stage.PINS,**m['preserved_alarm_files'],**m['art_apex']}.items():
  if before['/system/'+n].get('sha256')!=d or after['/system/'+n].get('sha256')!=d:raise ValueError('Protected54 camera/SystemUI/provider/alarms/ART content changed: '+n)
 if before['/system/framework/framework.jar'].get('sha256')!=stage.OLD_FRAMEWORK:raise ValueError('Wrong baseline framework')
 if oldprops.splitlines().count(b'ro.kaidroid.image=54')!=1 or oldprops.count(b'ro.kaidroid.image=54')!=1 or newprops!=oldprops.replace(b'ro.kaidroid.image=54',b'ro.kaidroid.image=55',1):raise ValueError('Unexpected build.prop mutation')
 if bx!=ax or bx.keys()!=before.keys():raise ValueError('Raw extended attributes/path coverage changed')
 return changed


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','manifest','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True);p.add_argument('--manifest-sha256',required=True)
 a=p.parse_args()
 stage.require_observed_pins()
 if a.output.exists():raise FileExistsError(a.output)
 if stage.sha(a.manifest)!=a.manifest_sha256:raise ValueError('Unreviewed stage manifest bytes')
 m=json.loads(a.manifest.read_text());validate_manifest(m)
 for path,d in [(a.baseline,stage.BASE_RAW),(a.candidate,a.candidate_sha256)]:
  if path.stat().st_size!=stage.PARTITION or stage.sha(path)!=d:raise ValueError('Wrong raw image size/hash')
 from verify_image43_closure import inventory
 from verify_image40_xattrs import inventory as xattrs
 before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
 bx,_=xattrs(a.baseline);ax,counts=xattrs(a.candidate)
 changed=compare_raw(before,after,oldprops,newprops,m,bx,ax)
 r=dict(image=55,baseline_image=54,baseline_sha256=stage.BASE_RAW,candidate_sha256=a.candidate_sha256,manifest_sha256=a.manifest_sha256,
  filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,
  all_inode_modes_uid_gid_symlinks_identical=True,all_extended_attributes_identical=True,
  compared_xattrs=sum(counts.values()),retained54_camera_runtime_contexts_systemui_provider_alarms_art=True,
  exported_framework_files=30,installed=False,optional_fec=False,
  exclusions=['timestamps','inode allocation','runtime behavior'],avb_verification='Separate signed-FEC0 packager artifact required; filesystem verification alone is not AVB proof.')
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with a.output.open('x',encoding='utf-8') as f:f.write(json.dumps(r,indent=2)+'\n')
 print(json.dumps(r))


if __name__=='__main__':main()

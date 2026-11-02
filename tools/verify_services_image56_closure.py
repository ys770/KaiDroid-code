"""Independent complete raw55-to56 comparison; no flash or host launch mode."""
import argparse,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
import image56_contract as c

def verify(a):
 if a.output.exists():raise FileExistsError(a.output)
 if not re.fullmatch('[0-9a-f]{64}',a.candidate_sha256) or c.sha(a.manifest)!=a.manifest_sha256:raise ValueError('Unreviewed candidate/manifest hash')
 m=json.loads(a.manifest.read_text());r=c.proposal(a.proposal)
 if m['image']!=56 or m['baseline_image']!=55 or m['base_raw_sha256']!=c.BASE or m['proposal_sha256']!=c.PROPOSAL or m['raw_changes']!=r['changed'] or m['optional_fec'] is not False or m['signed_hashtree_required'] is not True:raise ValueError('Stage manifest differs')
 identities={}
 for path,pin in [(a.baseline,c.BASE),(a.candidate,a.candidate_sha256)]:
  if path.stat().st_size!=c.PARTITION or c.sha(path)!=pin:raise ValueError('Raw size/hash differs')
  identities[str(path)]=(path.stat().st_size,path.stat().st_mtime_ns)
 before,bx,props=c.raw_inventory(a.baseline);after,ax,newprops=c.raw_inventory(a.candidate)
 for path in (a.baseline,a.candidate):
  if identities[str(path)]!=(path.stat().st_size,path.stat().st_mtime_ns):raise ValueError('Raw changed during verification')
 changed=c.compare_raw(before,after,bx,ax,props,newprops)
 for group in ('retained_framework_exports','retained_art_java_preopt','retained_protected','retained_alarms'):
  for n,pin in r[group].items():
   if before['/system/'+n].get('sha256')!=pin or after['/system/'+n].get('sha256')!=pin:raise ValueError('Retained closure changed '+n)
 result=dict(image=56,baseline_image=55,base_raw_sha256=c.BASE,candidate_raw_sha256=a.candidate_sha256,stage_manifest_sha256=a.manifest_sha256,proposal_sha256=c.PROPOSAL,filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,all_modes_uid_gid_kind_symlinks_identical=True,all_xattrs_identical=True,xattr_count=sum(len(v) for v in ax.values()),retained_framework_art_preopt_protected_alarms=True,installed=False,avb_verification='Separate signed-FEC0 pack evidence required',exclusions=['timestamps','inode allocation','runtime behavior'])
 c.dump(a.output,result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','manifest','proposal','output'):p.add_argument('--'+n,type=Path,required=True)
 for n in ('candidate-sha256','manifest-sha256'):p.add_argument('--'+n,required=True)
 print(json.dumps(verify(p.parse_args())))

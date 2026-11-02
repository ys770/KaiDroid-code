"""Verify exact image44-to-45 payload, inode metadata and all ext4 xattrs."""
import argparse,hashlib,json
from pathlib import Path
from verify_image40_closure import inventory
from verify_image40_xattrs import inventory as xattrs
BASE='b9d55804123a82064e3e0c806767e119cf2d628929eeb9c9e1482d886a475471'
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','manifest','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--candidate-sha256',required=True)
 p.add_argument('--manifest-sha256',required=True)
 a=p.parse_args()
 m=json.loads(a.manifest.read_text())
 assert digest(a.manifest)==a.manifest_sha256,'Unreviewed manifest'
 assert m['image']==45 and m['baseline_image']==44 and m['base_raw_sha256']==BASE
 assert len(m['exported_files'])==30
 assert set(m['changed']) <= set(m['exported_files']) | {'build.prop'}
 for path,h in ((a.baseline,BASE),(a.candidate,a.candidate_sha256)):
  assert path.stat().st_size==834666496 and digest(path)==h,'Wrong raw image'
 before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
 assert before.keys()==after.keys(),'Path set differs'
 changed={n for n in before if before[n]!=after[n]}
 expected={'/system/'+n for n in m['changed']}
 assert len(expected)>1 and changed==expected,(changed,expected)
 for n in changed:
  assert {k:v for k,v in before[n].items() if k!='sha256'}=={k:v for k,v in after[n].items() if k!='sha256'},'Metadata changed: '+n
  d=m['changed'][n.removeprefix('/system/')]
  assert before[n]['sha256']==d['before'][2] and after[n]['sha256']==d['after'][2],n
 for n,h in m['exported_files'].items():assert after['/system/'+n]['sha256']==h,n
 assert oldprops.splitlines().count(b'ro.kaidroid.image=44')==1
 assert newprops==oldprops.replace(b'ro.kaidroid.image=44',b'ro.kaidroid.image=45')
 bx,bc=xattrs(a.baseline);ax,ac=xattrs(a.candidate)
 assert bx==ax,'Extended attributes differ'
 report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,manifest_sha256=a.manifest_sha256,filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,all_inode_modes_owners_identical=True,all_extended_attributes_identical=True,compared_xattrs=sum(ac.values()),installed=False,exclusions=['timestamps','inode allocation','runtime behavior'])
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report))
if __name__=='__main__':main()

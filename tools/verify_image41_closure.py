"""Verify exact image40-to-41 payload, inode metadata and all ext4 xattrs."""
import argparse,hashlib,json
from pathlib import Path
from verify_image40_closure import inventory
from verify_image40_xattrs import inventory as xattrs
BASE='82ce8d6041effb571108704c2c51f6d039eabaeaf02cedb3a2e05dd7ae33c604'
NEW='60d659580278bfe3dcc09ca92b1910d4f9d7af27ca8e62e87a67ff9e0d4ae5fe'
MANIFEST='8088569658fa18ee039406492efc025de24d3d1536ffa118bdc77d8a5cc55f78'
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','manifest','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 m=json.loads(a.manifest.read_text())
 selected={k:m[k] for k in ('changed','exported_files','base_raw_sha256')}
 assert hashlib.sha256(json.dumps(selected,sort_keys=True,separators=(',',':')).encode()).hexdigest()==MANIFEST,'Unreviewed manifest'
 for path,h in ((a.baseline,BASE),(a.candidate,NEW)):
  assert path.stat().st_size==834666496 and digest(path)==h,'Wrong raw image'
 before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
 assert before.keys()==after.keys(),'Path set differs'
 changed={n for n in before if before[n]!=after[n]}
 expected={'/system/'+n for n in m['changed']}
 assert len(expected)==12 and changed==expected,(changed,expected)
 for n in changed:
  assert {k:v for k,v in before[n].items() if k!='sha256'}=={k:v for k,v in after[n].items() if k!='sha256'},'Metadata changed: '+n
  d=m['changed'][n.removeprefix('/system/')]
  assert before[n]['sha256']==d['before'][2] and after[n]['sha256']==d['after'][2],n
 for n,h in m['exported_files'].items():assert after['/system/'+n]['sha256']==h,n
 assert oldprops.splitlines().count(b'ro.kaidroid.image=40')==1
 assert newprops==oldprops.replace(b'ro.kaidroid.image=40',b'ro.kaidroid.image=41')
 bx,bc=xattrs(a.baseline);ax,ac=xattrs(a.candidate)
 assert bx==ax,'Extended attributes differ'
 report=dict(baseline_sha256=BASE,candidate_sha256=NEW,manifest_sha256=MANIFEST,filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,all_inode_modes_owners_identical=True,all_extended_attributes_identical=True,compared_xattrs=sum(ac.values()),installed=False,exclusions=['timestamps','inode allocation','runtime behavior'])
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report))
if __name__=='__main__':main()

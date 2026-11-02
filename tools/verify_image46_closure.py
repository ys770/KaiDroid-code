"""Verify exact image45-to-46 payload, inode metadata and all ext4 xattrs."""
import argparse,hashlib,json
from pathlib import Path
from verify_image40_closure import inventory
from verify_image40_xattrs import inventory as xattrs
BASE='77b523c3504700d1b05fdf5eb82c54715cb7e790675e52b01bc52dc1f53491e2'
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
 assert m['image']==46 and m['baseline_image']==45 and m['base_raw_sha256']==BASE
 assert len(m['exported_files'])==30
 assert set(m['changed']) <= set(m['exported_files']) | {'build.prop'} | set(m['added_alarm_files']) | set(m['added_alarm_dirs'])
 for path,h in ((a.baseline,BASE),(a.candidate,a.candidate_sha256)):
  assert path.stat().st_size==834666496 and digest(path)==h,'Wrong raw image'
 before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
 additions={'/system/'+n for n in set(m['added_alarm_files'])|set(m['added_alarm_dirs'])}
 assert len(m['added_alarm_files'])==8 and set(m['added_alarm_dirs']) <= {'product/media','product/media/audio','product/media/audio/alarms'}
 assert m['alarm_archive_sha256']=='a2b49312c22bb620a741e0665ee63436215ee601d704094f1aaef62230407fd5'
 assert set(after)-set(before)==additions and not set(before)-set(after),'Unexpected path change'
 changed={n for n in before if before[n]!=after[n]} | additions
 expected={'/system/'+n for n in m['changed']}
 assert len(expected)>1 and changed==expected,(changed,expected)
 for n in changed-additions:
  assert {k:v for k,v in before[n].items() if k!='sha256'}=={k:v for k,v in after[n].items() if k!='sha256'},'Metadata changed: '+n
  d=m['changed'][n.removeprefix('/system/')]
  assert before[n]['sha256']==d['before'][2] and after[n]['sha256']==d['after'][2],n
 for n,h in m['exported_files'].items():assert after['/system/'+n]['sha256']==h,n
 assert oldprops.splitlines().count(b'ro.kaidroid.image=45')==1
 assert newprops==oldprops.replace(b'ro.kaidroid.image=45',b'ro.kaidroid.image=46')
 bx,bc=xattrs(a.baseline);ax,ac=xattrs(a.candidate)
 assert set(ax)-set(bx)==additions and not set(bx)-set(ax)
 assert all(ax[n]==attrs for n,attrs in bx.items()),'Existing xattrs differ'
 for n in additions:
  item=after[n];relative=n.removeprefix('/system/')
  is_file=relative in m['added_alarm_files']
  assert item['mode']==(0o100644 if is_file else 0o40755) and item['uid']==item['gid']==0
  if is_file:assert item['sha256']==m['added_alarm_files'][relative]
  assert set(ax[n])=={'security.selinux'}
  assert bytes.fromhex(ax[n]['security.selinux']).rstrip(b'\0')==b'u:object_r:system_file:s0'
 report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,manifest_sha256=a.manifest_sha256,filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,all_inode_modes_owners_identical=True,existing_extended_attributes_identical=True,added_alarm_labels_modes_owners_verified=True,added_paths=sorted(additions),compared_xattrs=sum(ac.values()),installed=False,exclusions=['timestamps','inode allocation','runtime behavior'])
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report))
if __name__=='__main__':main()

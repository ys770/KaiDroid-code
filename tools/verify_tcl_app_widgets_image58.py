"""Full57-to58 filesystem/inode/xattr comparison; no phone or image writes."""
import argparse,json,re
from pathlib import Path
import app_widgets_image58_contract as c
from image56_contract import raw_inventory


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','manifest','proposal','pack-receipt','output'):p.add_argument('--'+n,type=Path,required=True)
 for n in ('candidate-sha256','manifest-sha256','pack-receipt-sha256'):p.add_argument('--'+n,required=True)
 a=p.parse_args();r=c.proposal(a.proposal)
 for pin in (a.candidate_sha256,a.manifest_sha256,a.pack_receipt_sha256):
  if not re.fullmatch('[0-9a-f]{64}',pin):raise ValueError('Canonical SHA256 required')
 for path,pin in [(a.baseline,c.BASE),(a.candidate,a.candidate_sha256),(a.manifest,a.manifest_sha256),(a.pack_receipt,a.pack_receipt_sha256)]:
  if path.is_symlink() or c.sha(path)!=pin:raise ValueError('Unreviewed input: '+str(path))
 if a.baseline.stat().st_size!=c.PARTITION or a.candidate.stat().st_size!=c.PARTITION:raise ValueError('Partition size differs')
 m=json.loads(a.manifest.read_text());pack=json.loads(a.pack_receipt.read_text())
 if m.get('image')!=58 or m.get('baseline_image')!=57 or m.get('raw_changes')!=r['changed'] or m.get('exported_files')!=r['exported_files'] or m.get('proposal_sha256')!=c.PROPOSAL or set(m.get('changed',[]))!=set(r['changed']):raise ValueError('Stage manifest differs')
 if pack.get('image')!=58 or pack.get('baseline_image')!=57 or pack.get('raw_sha256')!=a.candidate_sha256 or pack.get('staging_sha256')!=a.manifest_sha256 or pack.get('raw_bytes')!=c.PARTITION or pack.get('avb_verified') is not True or pack.get('signed_hashtree_verified') is not True or pack.get('optional_fec') is not False:raise ValueError('Signed pack receipt differs')
 before,bx,old=raw_inventory(a.baseline);after,ax,new=raw_inventory(a.candidate)
 changed=c.compare_raw(before,after,bx,ax,old,new,r)
 result=dict(image=58,baseline_image=57,base_raw_sha256=c.BASE,candidate_raw_sha256=a.candidate_sha256,stage_manifest_sha256=a.manifest_sha256,pack_receipt_sha256=a.pack_receipt_sha256,proposal_sha256=c.PROPOSAL,
  filesystem_entries=len(before),changed=sorted(changed),all_other_contents_identical=True,all_modes_uid_gid_kind_symlinks_identical=True,all_xattrs_identical=True,xattr_count=sum(map(len,ax.values())),
  full30_framework_export_closure=True,retained57_libart_camera_systemui_services_provider_alarms_runtime_art=True,messaging_system_apk_sha256=r['messaging_apk_sha256'],
  installed=False,full_parity=False,exclusions=['timestamps','inode allocation','runtime behavior','Independent AVB verification is bound through the separate frozen pack receipt'])
 c.dump(a.output,result);print(json.dumps(result))


if __name__=='__main__':main()

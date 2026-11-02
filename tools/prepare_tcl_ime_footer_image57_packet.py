"""Freeze the13-path footer/Messaging image57 packet offline; never launch or flash."""
import argparse,gzip,io,json,tarfile
from pathlib import Path
import ime_footer_image57_contract as c


def packet_files(root,baseline_dir,native_dir,review,config_dir,messaging):
 r=c.proposal(root/'docs/evidence/tcl-ime-footer-image57-proposal01.json')
 files={'proposal.json':(root/'docs/evidence/tcl-ime-footer-image57-proposal01.json').read_bytes()}
 for n in c.TOOLS:files['tools/'+n]=(root/'tools'/n).read_bytes()
 for n in ('raw-inventory.json','xattrs.json'):
  files['baseline-'+('raw-inventory.json' if n=='raw-inventory.json' else n)]=(baseline_dir/n).read_bytes()
 files['payload/build.prop']=c.props57((baseline_dir/'build.prop').read_bytes())
 files['payload/'+c.MMS]=messaging.read_bytes()
 for source,dest in [('staging.json','native-staging.json'),('outputs.json','native-outputs.json'),('cache-preservation.json','native-cache.json')]:files['proofs/'+dest]=(native_dir/source).read_bytes()
 files['proofs/native-review.json']=review.read_bytes()
 files['config/file_contexts.txt']=(config_dir/'file_contexts.txt').read_bytes()
 files['config/system_image_info.compact56.txt']=(config_dir/'system_image_info.compact56.txt').read_bytes()
 files['config/system_image_info.compact57.txt']=c.config57(files['config/system_image_info.compact56.txt'])
 return files,r


def main():
 p=argparse.ArgumentParser(description=__doc__);root=Path(__file__).resolve().parents[1]
 defaults={'baseline-dir':'work/tcl-ime-footer-image57-baseline01','native-dir':'work/tcl-ime-footer-host-controls11-01','review':'docs/evidence/tcl-ime-footer-native11-parent-review01.json','config-dir':'work/image56-parent-input02/config','messaging':'work/messaging-network-image-payload01/'+c.MMS}
 for n,d in defaults.items():p.add_argument('--'+n,type=Path,default=root/d)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 files,r=packet_files(root,a.baseline_dir,a.native_dir,a.review,a.config_dir,a.messaging)
 import hashlib
 sha=lambda data:hashlib.sha256(data).hexdigest()
 m=dict(image=57,baseline_image=56,proposal_sha256=c.PROPOSAL,base_raw_sha256=c.BASE,stage=c.NAME,backing=c.BACKING,
  exact_changed_files=sorted(r['changed']),native_export_files=30,retained_runtime_art_entries=24,retained_alarm_files=8,retained56_libart=True,
  external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,external_floor_bytes=c.FLOOR,root_floor_bytes=c.FLOOR,
  files={n:sha(b) for n,b in sorted(files.items())},hardware_review_and_reservation_required=True,staged=False,built=False,installed=False,full_parity=False)
 files['packet.json']=(json.dumps(m,indent=2)+'\n').encode()
 a.output.mkdir(parents=True,exist_ok=False)
 for n,data in files.items():
  path=a.output/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 from stage_tcl_ime_footer_image57 import packet_check
 packet_check(a.output.resolve(),sha(files['packet.json']))
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for n,data in sorted(files.items()):
     info=tarfile.TarInfo(n);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
 print(json.dumps(dict(packet=str(a.output),packet_manifest_sha256=sha(files['packet.json']),archive=str(archive),archive_sha256=c.sha(archive),launched=False)))


if __name__=='__main__':main()

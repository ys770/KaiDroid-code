"""Freeze the13-path footer/Messaging image57 packet offline; never launch or flash."""
import argparse,gzip,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
import ime_footer_image57_retry01_contract as c
from check_pack_shell_text import canonical,smoke


def packet_files(root,baseline_dir,native_dir,review,config_dir,messaging):
 r=c.proposal(root/'docs/evidence/tcl-ime-footer-image57-retry01-proposal.json')
 files={'proposal.json':(root/'docs/evidence/tcl-ime-footer-image57-retry01-proposal.json').read_bytes()}
 for n in c.TOOLS:
  data=(root/'tools'/n).read_bytes()
  files['tools/'+n]=canonical(data) if n.endswith(('.sh','.py')) else data
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
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--bash',type=Path,default=Path('bash') if os.name=='nt' else Path(shutil.which('bash') or '/bin/bash'))
 a=p.parse_args()
 files,r=packet_files(root,a.baseline_dir,a.native_dir,a.review,a.config_dir,a.messaging)
 shell_check=smoke(files['tools/build_tcl_ime_footer_image57_retry01.sh'],a.bash)
 import hashlib
 sha=lambda data:hashlib.sha256(data).hexdigest()
 m=dict(image=57,baseline_image=56,proposal_sha256=c.PROPOSAL,base_raw_sha256=c.BASE,stage=c.NAME,backing=c.BACKING,
  exact_changed_files=sorted(r['changed']),native_export_files=30,retained_runtime_art_entries=24,retained_alarm_files=8,retained56_libart=True,
  external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,external_floor_bytes=c.FLOOR,root_floor_bytes=c.FLOOR,
  files={n:sha(b) for n,b in sorted(files.items())},shell_preamble_execution=shell_check,watchdog_unit=c.UNIT,
  hardware_review_and_reservation_required=True,staged=False,built=False,installed=False,full_parity=False)
 files['packet.json']=(json.dumps(m,indent=2)+'\n').encode()
 a.output.mkdir(parents=True,exist_ok=False)
 for n,data in files.items():
  path=a.output/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 from stage_tcl_ime_footer_image57_retry01 import packet_check
 packet_check(a.output.resolve(),sha(files['packet.json']))
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for n,data in sorted(files.items()):
     info=tarfile.TarInfo(n);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
 # Inspect the produced archive, then import its identical extracted sources in
 # an isolated Python process. Checkout imports cannot satisfy this check.
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  if len(members)!=len(files) or {m.name for m in members}!=set(files):raise ValueError('Archive entry coverage differs')
  for member in members:
   if not member.isfile() or member.mode!=0o644 or tar.extractfile(member).read()!=files[member.name]:raise ValueError('Actual archive bytes/type/mode differ: '+member.name)
  archived_smoke=smoke(tar.extractfile('tools/build_tcl_ime_footer_image57_retry01.sh').read(),a.bash)
 code="import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import stage_tcl_ime_footer_image57_retry01 as module;module.packet_check(Path(sys.argv[2]),sys.argv[3]);print(json.dumps({'isolated_packet_sources_imported':True,'packet_validated':True}))"
 result=subprocess.run([sys.executable,'-I','-B','-c',code,str((a.output/'tools').resolve()),str(a.output.resolve()),sha(files['packet.json'])],capture_output=True,timeout=60)
 result.check_returncode()
 verification=dict(actual_archive_bytes_and_modes_match=True,archive_shell_smoke=archived_smoke,isolated_import=json.loads(result.stdout),archive_sha256=c.sha(archive),passed=True)
 Path(str(a.output)+'.verification.json').write_bytes((json.dumps(verification,indent=2)+'\n').encode())
 print(json.dumps(dict(packet=str(a.output),packet_manifest_sha256=sha(files['packet.json']),archive=str(archive),archive_sha256=c.sha(archive),launched=False)))


if __name__=='__main__':main()

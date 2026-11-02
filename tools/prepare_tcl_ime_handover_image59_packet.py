"""Freeze a reviewed image59 packet offline; no SSH, Docker, ADB or staging."""
import argparse,gzip,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
import ime_handover_image59_contract as c
from check_pack_shell_text import canonical,smoke

def packet_files(root,proposal,pin,baseline,native,cache,review,config):
 r=c.proposal(proposal,pin)
 files={'proposal.json':proposal.read_bytes()}
 for n in sorted(c.TOOLS):
  data=(root/'tools'/n).read_bytes()
  files['tools/'+n]=canonical(data) if n.endswith(('.sh','.py')) else data
 marker=b"PROPOSAL='UNBOUND_REQUIRES_REVIEWED_PACKET'"
 if files['tools/ime_handover_image59_contract.py'].count(marker)!=1:raise ValueError('Unbound contract marker differs')
 files['tools/ime_handover_image59_contract.py']=files['tools/ime_handover_image59_contract.py'].replace(marker,("PROPOSAL='"+pin+"'").encode())
 files['baseline-raw-inventory.json']=(baseline/'raw-inventory.json').read_bytes()
 files['baseline-xattrs.json']=(baseline/'xattrs.json').read_bytes()
 files['payload/build.prop']=c.props59((baseline/'build.prop').read_bytes())
 files['proofs/native-staging.json']=(native/'staging.json').read_bytes()
 files['proofs/native-outputs.json']=(native/'outputs.json').read_bytes()
 files['proofs/native-cache.json']=cache.read_bytes();files['proofs/native-review.json']=review.read_bytes()
 files['config/file_contexts.txt']=(config/'file_contexts.txt').read_bytes()
 files['config/system_image_info.compact58.txt']=(config/'system_image_info.compact.txt').read_bytes()
 files['config/system_image_info.compact59.txt']=c.config59(files['config/system_image_info.compact58.txt'])
 return files,r

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('proposal','baseline','native','cache','review','config','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--proposal-sha256',required=True)
 p.add_argument('--bash',type=Path,default=Path('bash') if os.name=='nt' else Path(shutil.which('bash') or '/bin/bash'))
 a=p.parse_args();root=Path(__file__).resolve().parents[1]
 files,r=packet_files(root,a.proposal,a.proposal_sha256,a.baseline,a.native,a.cache,a.review,a.config)
 import hashlib
 sha=lambda data:hashlib.sha256(data).hexdigest()
 shell_check=smoke(files['tools/build_tcl_ime_handover_image59.sh'],a.bash)
 m=dict(image=59,baseline_image=58,proposal_sha256=a.proposal_sha256,base_raw_sha256=c.BASE,stage=c.NAME,backing=c.BACKING,
  exact_changed_files=sorted(r['changed']),native_export_files=30,retained_runtime_art_entries=24,retained_alarm_files=8,
  contacts_data_app_update_preserved_separately=True,external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,
  external_floor_bytes=c.FLOOR,root_floor_bytes=c.FLOOR,files={n:sha(b) for n,b in sorted(files.items())},
  shell_preamble_execution=shell_check,watchdog_unit=c.UNIT,hardware_review_and_reservation_required=True,
  staged=False,built=False,installed=False,full_parity=False)
 files['packet.json']=(json.dumps(m,indent=2)+'\n').encode()
 # Validate the exact files via isolated packet imports before creating archive.
 a.output.mkdir(parents=True,exist_ok=False)
 for n,data in sorted(files.items()):
  path=a.output/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 code="import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import stage_tcl_ime_handover_image59 as m;m.packet_check(Path(sys.argv[2]),sys.argv[3]);print(json.dumps({'isolated_packet_sources_imported':True,'packet_validated':True}))"
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 result=subprocess.run([sys.executable,'-I','-B','-c',code,str((a.output/'tools').resolve()),str(a.output.resolve()),sha(files['packet.json'])],capture_output=True,timeout=60,env=env)
 if result.returncode:raise ValueError('Isolated packet validation failed: '+result.stderr.decode(errors='replace'))
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for n,data in sorted(files.items()):
     info=tarfile.TarInfo(n);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  if len(members)!=len(files) or {m.name for m in members}!=set(files):raise ValueError('Archive entry coverage differs')
  for member in members:
   if not member.isfile() or member.mode!=0o644 or tar.extractfile(member).read()!=files[member.name]:raise ValueError('Archive bytes/type/mode differ: '+member.name)
  archived_smoke=smoke(tar.extractfile('tools/build_tcl_ime_handover_image59.sh').read(),a.bash)
 verification=dict(actual_archive_bytes_and_modes_match=True,archive_shell_smoke=archived_smoke,
  isolated_import=json.loads(result.stdout),archive_sha256=c.sha(archive),passed=True)
 c.dump(Path(str(a.output)+'.verification.json'),verification)
 print(json.dumps(dict(packet=str(a.output),packet_manifest_sha256=sha(files['packet.json']),archive=str(archive),archive_sha256=c.sha(archive),launched=False)))

if __name__=='__main__':main()

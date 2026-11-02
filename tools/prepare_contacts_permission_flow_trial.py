"""Bind the reviewed signed Contacts correction to the proven image58 helper offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile

OLD='20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248'
SIGNED='9935b312c5ba698e51f8be91b37799837f5c1c3bd13abdb29812e2b49d5cc9d4'
UNSIGNED='4a01ed4dfb3438b319f8030a9943bca2b6fd149cea920ebcdf6bc922f773d53b'
RECEIPT='04787aa4e8da151db0502e096d720e27c96dd3bd30bcc952dd20bcec028c1db7'
HELPER='77ec16f74a135e0e4a0b816c2a59ad560de424cefb873ef6c1e3db895ab2d209'
CERT='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'
def sha(data):return hashlib.sha256(data).hexdigest()
def verify_payload(unsigned,signed):
 if sha(unsigned.read_bytes())!=UNSIGNED or sha(signed.read_bytes())!=SIGNED:raise ValueError('Wrong reviewed unsigned/signed APK')
 with zipfile.ZipFile(unsigned) as a,zipfile.ZipFile(signed) as b:
  names=a.namelist();other=b.namelist()
  if len(names)!=len(set(names)) or len(other)!=len(set(other)) or set(other)-set(names)!={'META-INF/SHARED.SF','META-INF/SHARED.RSA','META-INF/MANIFEST.MF'} or set(names)-set(other) or any(a.read(n)!=b.read(n) for n in names):raise ValueError('Signed APK payload differs')
  info=b.getinfo('resources.arsc');raw=signed.read_bytes();name,extra=struct.unpack_from('<HH',raw,info.header_offset+26);offset=info.header_offset+30+name+extra
  if info.compress_type!=0 or offset%4:raise ValueError('Resources not stored/aligned4')
 return dict(all_unsigned_payloads_identical=True,resources_stored_aligned4=True)
def main():
 root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__)
 for n in ('jdk','sdk','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--baseline-trial',type=Path,default=root/'work/contacts-image58-trial04')
 p.add_argument('--signed-apk',type=Path,default=root/'work/contacts-permission-flow-signed01/FPContacts.apk')
 p.add_argument('--unsigned-apk',type=Path,default=root/'work/contacts-permission-flow-candidate01/FPContacts.unsigned.apk');a=p.parse_args()
 payload=verify_payload(a.unsigned_apk,a.signed_apk)
 data=(a.baseline_trial/'result.json').read_bytes()
 if sha(data)!=RECEIPT:raise ValueError('Wrong proven image58 trial')
 baseline=json.loads(data);original={}
 for name,pin in baseline['generated_inputs'].items():
  raw=(a.baseline_trial/name).read_bytes()
  if sha(raw)!=pin:raise ValueError('Guarded original trial changed: '+name)
  original[name]=raw
 if sum(b.count(OLD.encode()) for b in original.values())!=2:raise ValueError('Expected two exact APK guards')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 def run(name,args):
  result=subprocess.run(list(map(str,args)),cwd=out,capture_output=True,timeout=120)
  (out/(name+'.stdout')).write_bytes(result.stdout);(out/(name+'.stderr')).write_bytes(result.stderr);result.check_returncode();return result
 verify=run('signature',[a.jdk.resolve()/'bin/java.exe','-jar',a.sdk.resolve()/'build-tools/35.0.0/lib/apksigner.jar','verify','--min-sdk-version','30','--verbose','--print-certs',a.signed_apk.resolve()]).stdout.decode()
 if re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',verify)!=[CERT] or not re.search('Verified using v3.*: true',verify):raise ValueError('Wrong compatible signer/scheme')
 for name,raw in original.items():(out/name).write_bytes(raw.replace(OLD.encode(),SIGNED.encode()))
 run('build',[sys.executable,'-X','utf8',out/'build_contacts_permission_state.py','--sdk',a.sdk.resolve(),'--jdk',a.jdk.resolve(),'--output',out/'helper'])
 built=json.loads((out/'helper/build.json').read_text())
 if built.get('mutation_eligibility_assertions')!=124 or built.get('streaming_hash_cases')!=6:raise ValueError('Host helper controls missing')
 helper=built['jar_sha256'];smoke=out/'smoke_contacts_permission_state.py';text=smoke.read_bytes()
 if text.count(HELPER.encode())!=1:raise ValueError('Expected exact helper checksum guard')
 smoke.write_bytes(text.replace(HELPER.encode(),helper.encode()))
 tested=run('tests',[sys.executable,'-X','utf8','-m','unittest','discover','-s',out,'-p','test_*.py'])
 if not re.search(rb'Ran 24 tests',tested.stderr):raise ValueError('Expected24 same-directory trial controls')
 for name,raw in original.items():
  expected=raw.replace(OLD.encode(),SIGNED.encode())
  if name=='smoke_contacts_permission_state.py':expected=expected.replace(HELPER.encode(),helper.encode())
  if (out/name).read_bytes()!=expected:raise ValueError('Unrelated guard/source change: '+name)
 proof=dict(scope='Offline exact signed-APK/helper rebind; no phone operation',image=58,signed_apk_sha256=SIGNED,unsigned_apk_sha256=UNSIGNED,
  signer_certificate_sha256=CERT,signature_android30_v3_verified=True,payload=payload,
  helper_sha256=helper,mutation_eligibility_assertions=124,streaming_hash_cases=6,python_guard_controls=24,
  source_changes='Only old APK guard hash to reviewed signed hash, and new helper checksum',
  original_source_hashes={n:sha(b) for n,b in original.items()},generated_source_hashes={n:sha((out/n).read_bytes()) for n in original},
  phone_commands_issued=False,installed=False,runtime_verified=False,new_grants_retained=False,full_parity=False)
 (out/'result.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
if __name__=='__main__':main()

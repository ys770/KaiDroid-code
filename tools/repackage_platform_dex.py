"""Repackage DEX only, align, sign with existing platform identity and verify payloads."""
import argparse,hashlib,json,re,subprocess,zipfile
from pathlib import Path
from compress_apk_dex import compress,is_signature
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--sdk',type=Path,required=True);p.add_argument('--java',type=Path,required=True);p.add_argument('--keys',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False);bt=a.sdk/'build-tools/35.0.0';signer=[str(a.java),'-jar',str(bt/'lib/apksigner.jar')]
def run(name,cmd):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=120);(a.output/(name+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode();return r.stdout.decode()
def cert(apk,label):
 text=run(label,[*signer,'verify','--verbose','--print-certs',apk]);certs=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',text);assert certs==['c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'];return certs[0]
cert(a.source,'original-signature')
report=compress(a.source,a.output/'unsigned.apk',a.sha256)
run('align',[bt/'zipalign.exe','-p','4',a.output/'unsigned.apk',a.output/'aligned.apk'])
final=a.output/'signed.apk'
run('sign',[*signer,'sign','--key',a.keys/'platform.pk8','--cert',a.keys/'platform.x509.pem','--out',final,a.output/'aligned.apk'])
report['signer']=cert(final,'final-signature');run('alignment-check',[bt/'zipalign.exe','-c','-p','4',final])
with zipfile.ZipFile(a.source) as src,zipfile.ZipFile(final) as dst:
 old={n for n in src.namelist() if not is_signature(n)};new={n for n in dst.namelist() if not is_signature(n)};assert old==new
 for n in old:
  assert src.read(n)==dst.read(n),n
  if n not in report['compressed_entries']:assert src.getinfo(n).compress_type==dst.getinfo(n).compress_type,n
 assert dst.getinfo('resources.arsc').compress_type==0
report.update(signed_sha256=hashlib.sha256(final.read_bytes()).hexdigest(),signed_bytes=final.stat().st_size,final_payload_verified=True,unsigned=False)
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

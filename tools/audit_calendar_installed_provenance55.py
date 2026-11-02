"""Reconcile the captured Calendar971 signing variant with exact original payloads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile
from compress_apk_dex import is_signature

ORIGINAL='bb2c27d93c666a548f84d388c57b70551821fdf72404c1756d221c219ee95168'
CANDIDATE='475f987a6606580e0f69eb0d250e03a2c49780a197afe5d2d94511c76c916b90'
MATCHED='971e5f9d32ab5b4f8e616a6c5d44073d66a000631cd47c353abf5ca4bc540b0d'
CERT='a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'


def sha(data):return hashlib.sha256(data).hexdigest()


def payload(path):
 with zipfile.ZipFile(path) as z:
  names=z.namelist()
  if len(names)!=len(set(names)) or z.testzip() is not None:raise ValueError('Invalid duplicate/corrupt APK ZIP')
  return {n:sha(z.read(n)) for n in names if not is_signature(n)}


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('original','candidate','matched','java','apksigner','installed-hash-receipt','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 for path,pin in [(a.original,ORIGINAL),(a.candidate,CANDIDATE),(a.matched,MATCHED)]:
  if sha(path.read_bytes())!=pin:raise ValueError('Unexpected source/signing variant identity')
 receipt=a.installed_hash_receipt.read_text(encoding='utf-8').strip()
 if not re.fullmatch(MATCHED+r'\s+/data/app/[A-Za-z0-9_./=+~-]+/base\.apk',receipt):raise ValueError('Installed receipt is not exact matched variant')
 before=payload(a.original)
 if payload(a.candidate)!=before or payload(a.matched)!=before:raise ValueError('Original app payload changed')
 root=Path(__file__).resolve().parents[1]
 delivery=root/'docs/evidence/image36-stock-app-delivery01.json'
 rows=[r for r in json.loads(delivery.read_text())['apps'] if r['name']=='FPCalendar']
 if len(rows)!=1 or rows[0].get('candidate_sha256')!=MATCHED or rows[0].get('candidate_certificate')!=CERT:raise ValueError('Prior installed delivery provenance changed')
 a.output.mkdir(parents=True,exist_ok=False)
 result=subprocess.run([str(a.java),'-jar',str(a.apksigner),'verify','--verbose','--print-certs',str(a.matched)],capture_output=True,timeout=45)
 (a.output/'signature.txt').write_bytes(result.stdout+result.stderr);result.check_returncode()
 text=result.stdout.decode('utf-8')
 if re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',text)!=[CERT] or 'Verified using v3 scheme (APK Signature Scheme v3): true' not in text:raise ValueError('Expected prior installed testkey signer/v3 verification missing')
 report=dict(original_apk_sha256=ORIGINAL,previous_candidate_sha256=CANDIDATE,installed_variant_sha256=MATCHED,
  certificate_sha256=CERT,signature_verified=True,installed_receipt_sha256=sha(a.installed_hash_receipt.read_bytes()),
  all_original_non_signature_zip_payloads_byte_identical=True,payload_entries=len(before),
  classes_dex_sha256=before['classes.dex'],payload_inventory_sha256=sha(json.dumps(before,sort_keys=True,separators=(',',':')).encode()),
  manifest_resources_all_code_unchanged=True,prior_image36_delivery_records_same_variant=True,
  prior_delivery_receipt_sha256=sha(delivery.read_bytes()),
  passed=True,phone_operations_performed=False,runtime_reminder_trial_passed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

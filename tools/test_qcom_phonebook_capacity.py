"""Test capacity decoder using original-ARM aggregation output as synthetic fixture."""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixture_path = root / 'docs/evidence/qcom-capacity-aggregation01.json'
raw = fixture_path.read_bytes()
fixture = json.loads(raw)
if not fixture['passed'] or fixture['library_sha256'] != '47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd':
    raise ValueError('Unexpected fixture provenance')
words = fixture['cases'][2]['response_object_words']
sources = ['compat/java/org/kaidroid/contacts/QcomPhonebookCapacity.java',
           'tests/contacts/QcomPhonebookCapacityTest.java']
with tempfile.TemporaryDirectory(prefix='kaidroid-capacity-') as output:
    subprocess.run(['javac','--release','8','-d',output,*sources],cwd=root,capture_output=True,check=True,timeout=60)
    result = subprocess.run(['java','-cp',output,'QcomPhonebookCapacityTest',struct.pack('<10I',*words).hex()],
                            capture_output=True,text=True,check=True,timeout=30)
report = {'scope':'Host decoder; no Android integration or hardware validation',
          'fixture_sha256':hashlib.sha256(raw).hexdigest(),
          'source_sha256':{s:hashlib.sha256((root/s).read_bytes()).hexdigest() for s in sources},
          'test_exit':result.returncode,'test_stdout':result.stdout.strip(),
          'device_installed':False,'hardware_validated':False}
(root/'docs/evidence/qcom-phonebook-capacity-parser01.json').write_text(json.dumps(report,indent=2)+'\n')
print(result.stdout.strip())

"""Host raw-record decoder tests using synthetic original-ARM serializer outputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
fixture_bytes = (root / "docs/evidence/qcom-phonebook-records01.json").read_bytes()
fixture = json.loads(fixture_bytes)
if fixture["library_sha256"] != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Unexpected library provenance")
if [case["record_count"] for case in fixture["cases"]] != [0, 1, 1, 2]:
    raise ValueError("Unexpected fixture set")
sources = ["compat/java/org/kaidroid/contacts/QcomPhonebookRecords.java",
           "tests/contacts/QcomPhonebookRecordsTest.java"]
with tempfile.TemporaryDirectory(prefix="kaidroid-records-") as output:
    subprocess.run(["javac", "--release", "8", "-d", output, *sources], cwd=root,
                   capture_output=True, text=True, check=True, timeout=60)
    result = subprocess.run(["java", "-cp", output, "QcomPhonebookRecordsTest",
                             *[case["output_hex"] for case in fixture["cases"]]],
                            capture_output=True, text=True, check=True, timeout=30)
report = {
    "scope": "Host raw-field parser tests; no charset, modem semantics, capacity or Android integration validation",
    "source_sha256": {s: hashlib.sha256((root / s).read_bytes()).hexdigest() for s in sources},
    "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
    "test_exit": result.returncode, "test_stdout": result.stdout.strip(),
    "device_installed": False, "hardware_validated": False,
}
(root / "docs/evidence/qcom-phonebook-records-parser01.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(result.stdout.strip())

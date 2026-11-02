"""Test Java notification framing against recorded original-ARM serializer fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
fixture_path = root / "docs/evidence/qcom-phonebook-envelope01.json"
fixture_bytes = fixture_path.read_bytes()
fixture = json.loads(fixture_bytes)
if fixture["library_sha256"] != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Unexpected fixture provenance")
hexes = []
for size in (0, 4):
    case = next(c for c in fixture["cases"] if c["synthetic_payload_bytes"] == size and not c["allocation_fails"])
    value = case["output_hex_if_small"]
    if hashlib.sha256(bytes.fromhex(value)).hexdigest() != case["output_sha256"]:
        raise ValueError("Fixture hash mismatch")
    hexes.append(value)
sources = ["compat/java/org/kaidroid/contacts/QcomPhonebookNotification.java",
           "tests/contacts/QcomPhonebookNotificationTest.java"]
with tempfile.TemporaryDirectory(prefix="kaidroid-notification-") as output:
    subprocess.run(["javac", "--release", "8", "-d", output, *sources], cwd=root,
                   capture_output=True, text=True, timeout=60, check=True)
    result = subprocess.run(["java", "-cp", output, "QcomPhonebookNotificationTest", *hexes],
                            capture_output=True, text=True, timeout=30, check=True)
report = {
    "scope": "Host Java envelope parser, using two original-ARM synthetic fixtures; not record/capacity decoding or Android integration",
    "source_sha256": {s: hashlib.sha256((root / s).read_bytes()).hexdigest() for s in sources},
    "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
    "test_exit": result.returncode, "test_stdout": result.stdout.strip(),
    "device_installed": False, "hardware_validated": False,
}
(root / "docs/evidence/qcom-phonebook-notification-parser01.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(result.stdout.strip())

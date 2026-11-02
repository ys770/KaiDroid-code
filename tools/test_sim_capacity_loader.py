"""Compile/run the standalone capacity loader concurrency tests; no phone access."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
sources = ["compat/java/org/kaidroid/contacts/SimCapacityLoader.java",
           "tests/contacts/SimCapacityLoaderTest.java"]
with tempfile.TemporaryDirectory(prefix="kaidroid-capacity-") as output:
    compile_result = subprocess.run(
        ["javac", "--release", "8", "-d", output, *sources], cwd=root,
        capture_output=True, text=True, timeout=60, check=True)
    test_result = subprocess.run(["java", "-cp", output, "SimCapacityLoaderTest"],
                                 capture_output=True, text=True, timeout=30, check=True)
    evidence = {
        "scope": "Host Java concurrency tests only; no Android backend or app integration",
        "sources": {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sources},
        "compiler": subprocess.run(["javac", "-version"], capture_output=True,
                                   text=True, check=True).stdout.strip(),
        "release": 8,
        "compile_exit": compile_result.returncode,
        "test_exit": test_result.returncode,
        "test_stdout": test_result.stdout.strip(),
        "android_integrated": False,
        "hardware_validated": False,
    }
    (root / "docs/evidence/sim-capacity-loader-host01.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(test_result.stdout.strip())

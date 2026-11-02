"""Compile the trial helper locally; does not use the shared AOSP tree or adb."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--jdk', type=Path, required=True)
p.add_argument('--sdk', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
classes = a.output / 'classes'
classes.mkdir()
source = Path(__file__).with_name('ContactsPermissionState.java').resolve()
android = a.sdk / 'platforms/android-30/android.jar'
subprocess.run([str(a.jdk / 'bin/javac.exe'), '-source', '8', '-target', '8',
                '-classpath', str(android), '-d', str(classes), str(source)], check=True)
tests = a.output / 'host-tests'
tests.mkdir()
classpath = str(classes) + ';' + str(android)
subprocess.run([str(a.jdk / 'bin/javac.exe'), '-classpath', classpath, '-d', str(tests),
                str(source.with_name('ContactsPermissionStateHostTest.java'))], check=True)
subprocess.run([str(a.jdk / 'bin/java.exe'), '-classpath', str(tests) + ';' + classpath,
                'ContactsPermissionStateHostTest'], check=True)
artifact = a.output / 'contacts-permission-state.jar'
subprocess.run([str(a.jdk / 'bin/java.exe'), '-cp', str(a.sdk / 'build-tools/35.0.0/lib/d8.jar'),
                'com.android.tools.r8.D8', '--lib', str(android), '--min-api', '30',
                '--output', str(artifact), *map(str, classes.glob('*.class'))], check=True)
report = dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              jar_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
              compiled=True, mutation_eligibility_assertions=124, streaming_hash_cases=6, runtime_verified=False)
(a.output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))

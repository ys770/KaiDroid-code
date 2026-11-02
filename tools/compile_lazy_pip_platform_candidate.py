"""Compile/compare the held PiP source with real captured APIs; no annotation processing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from compile_wallpaper_platform_candidate import JARS, methods, canonical_encoding
from prepare_lazy_pip_candidate import SOURCE, PIN, candidate

EXTRA = {'SystemUISharedLib.jar': '325689bf9db5be92420ec832ac45b6593b8c83e48e69e25a57db1b712d9f382f',
         'dagger2-2.19.jar': '514b6f1e0727c6572e1d65cb27e4ae668b7aeaeb93a29515182965265b609939'}
CLASS = 'com.android.systemui.pip.PipUI'
OLD = 'public ' + CLASS + '(android.content.Context, com.android.systemui.statusbar.CommandQueue, com.android.systemui.pip.BasePipManager);'
NEW = 'public ' + CLASS + '(android.content.Context, com.android.systemui.statusbar.CommandQueue, dagger.Lazy<com.android.systemui.pip.BasePipManager>);'


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(a):
    jars = {a.base_jars / n: pin for n, pin in JARS.items()}
    jars.update({a.extra_jars / n: pin for n, pin in EXTRA.items()})
    for path, pin in jars.items():
        if sha(path) != pin: raise ValueError('API jar identity differs')
    raw = (a.source / SOURCE).read_bytes()
    changed = candidate(raw)
    if (a.candidate / SOURCE).read_bytes() != changed.encode(): raise ValueError('Candidate scope/content differs')
    a.output.mkdir(parents=True, exist_ok=False)
    bodies = {}; apis = {}; runs = []
    for label, source in [('baseline', a.source), ('candidate', a.candidate)]:
        folder = a.output / label; folder.mkdir()
        cmd = ['javac', '-source', '8', '-target', '8', '-proc:none', '-implicit:none',
               '-classpath', os.pathsep.join(str(p.resolve()) for p in jars), '-d', str(folder), str(source / SOURCE)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        (folder / 'javac.stdout').write_text(result.stdout); (folder / 'javac.stderr').write_text(result.stderr)
        result.check_returncode()
        files = list(folder.rglob('*.class'))
        if [p.relative_to(folder).as_posix() for p in files] != ['com/android/systemui/pip/PipUI.class']:
            raise ValueError('Unexpected compiled class closure')
        signature = subprocess.run(['javap', '-p', '-s', '-classpath', str(folder), CLASS], capture_output=True, text=True, check=True).stdout
        disasm = subprocess.run(['javap', '-p', '-c', '-s', '-classpath', str(folder), CLASS], capture_output=True, text=True, check=True).stdout
        (folder / 'PipUI.javap').write_text(disasm)
        apis[label] = [line.strip() for line in signature.splitlines() if line.startswith('  ') and line.endswith(';')]
        bodies[label] = methods(disasm)
        runs.append(dict(label=label, command=cmd, exit=0, stderr=result.stderr, class_sha256=sha(files[0]), class_bytes=files[0].stat().st_size))
    if apis['candidate'] != [NEW if s == OLD else s for s in apis['baseline']]: raise ValueError('Unexpected API/member delta')
    before = {NEW if k == OLD else k: v for k, v in bodies['baseline'].items()}
    after = bodies['candidate']
    if before.keys() != after.keys(): raise ValueError('Unexpected method closure')
    changes = sorted(k for k in before if canonical_encoding(before[k]) != canonical_encoding(after[k]))
    expected = sorted([NEW, 'public void showPictureInPictureMenu();', 'public void expandPip();', 'public void hidePipMenu(java.lang.Runnable, java.lang.Runnable);'])
    if changes != expected: raise ValueError('Unexpected semantic method delta: ' + repr(changes))
    return dict(source_sha256=PIN, candidate_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                jars={str(p): pin for p, pin in jars.items()}, runs=runs, changed_methods=changes,
                method_count=len(before), member_scope_pass=True, javac_version=subprocess.run(['javac', '-version'], capture_output=True, text=True, check=True).stdout.strip(),
                limits=['Real captured Android/SystemUI/Dagger APIs; host JDK Java8 source/target and bootstrap classes.',
                        'Annotation processing disabled: this does not regenerate or validate Dagger factories.',
                        'Classfile comparison excludes debug/annotation metadata and is not DEX/R8/APK signing, Android execution or memory proof.',
                        'Base API jars are retained shared build inputs, not claims of equality to current image47 isolated outputs.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'candidate', 'base-jars', 'extra-jars', 'output']: p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); report = run(a)
    (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(member_scope_pass=True, changed_methods=report['changed_methods']), indent=2))

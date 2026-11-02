"""Compile the chooser overlay against pinned existing framework ABI headers, offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HEADERS={'framework-minus-apex.jar':'1a6c31a5af0d1a6a65fd5f8334bd7073ed94fc2315b6d62a6f1c7dc4a291e851',
         'unsupportedappusage.jar':'fa822cd5e14e862bd46ce7b7b22baf7efb1ce06745e2f39cd55ca44d2246dd98'}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binding','headers','android-jar','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--menu-bar',type=Path,help='Include the separately reviewed wrap-only MenuBar source')
    a=p.parse_args();report=json.loads((a.binding/'report.json').read_text())
    files=[]
    for name,digest in report['files'].items():
        path=a.binding/name.replace('\\','/')
        if sha(path)!=digest:raise ValueError('Overlay changed after preparation')
        files.append(path.resolve())
    if len(files)!=2:raise ValueError('Expected only chooser and presentation')
    menu_sha=None
    if a.menu_bar:
        menu_sha=sha(a.menu_bar)
        if menu_sha!='4480147f9a82e04518df0ec4791bc63adbfc35bf00325ae25f25cc0ca8b020f7':
            raise ValueError('Wrong reviewed menu-wrap source')
        files.append(a.menu_bar.resolve())
    jars=[]
    for name,digest in HEADERS.items():
        path=a.headers/name
        if sha(path)!=digest:raise ValueError('Framework ABI header mismatch')
        jars.append(path.resolve())
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);(out/'classes').mkdir()
    args=[a.jdk.resolve()/'bin'/('javac.exe' if os.name=='nt' else 'javac'),
          '--release','8','-proc:none','-classpath',os.pathsep.join(map(str,[*jars,a.android_jar.resolve()])),
          '-d',out/'classes',*files]
    result=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=120)
    (out/'javac.log').write_text(result.stdout+result.stderr,encoding='utf-8');result.check_returncode()
    evidence=dict(scope='Isolated Java compile against actual image42 framework ABI headers +SDK30; not AOSP build/DEX/preopt/runtime proof',
        headers=HEADERS,android_jar_sha256=sha(a.android_jar),binding_report_sha256=sha(a.binding/'report.json'),
        input_sources=report['files'],result='PASS',classes=len(list((out/'classes').rglob('*.class'))),
        reviewed_menu_bar_sha256=menu_sha,
        annotation_processing=False,shared_host_mutations=False,installed=False)
    (out/'report.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence))


if __name__=='__main__':main()

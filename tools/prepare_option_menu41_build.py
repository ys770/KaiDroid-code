"""Prepare a fresh, fully isolated framework output clone; never launch a build."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

SOURCE='aosp/frameworks/base/core/java/android/widget/MenuBar.java'
OLD_SOURCE='73f871ffa9bda03951050d91cab118f6a8f6e663e1090fc68ce8767a1389cc26'
NEW_SOURCE='2dd271885ce018c662169aa4b1e7a755ce87ec89a89d338e977906be196c78b8'
BASE='engineering-lazy-wifi-stage-40'
PINS={SOURCE:OLD_SOURCE,
 'aosp/frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java':'eae4f86569e8ea885a0a2620c99216b50637de8e0d4424b0747773e142448afc',
 'engineering-lazy-wifi-stage-40/compact-image/system.raw.img':'82ce8d6041effb571108704c2c51f6d039eabaeaf02cedb3a2e05dd7ae33c604',
 'engineering-lazy-wifi-stage-40/compact-system/system_ext/priv-app/SystemUI/SystemUI.apk':'f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0',
 'engineering-lazy-wifi-stage-40/compact-system/priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'}
FRAMEWORK={'framework/framework.jar':'b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f',
 'framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
 'framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'}


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def idle():
    for name in ('ninja','soong_build','e2fsdroid'):
        result=subprocess.run(['pgrep','-x',name],capture_output=True)
        if result.returncode!=1:raise ValueError('Build process exists or inspection failed: '+name)


def prepare(root,candidate,stage,build_script):
    root=root.resolve(strict=True);stage=stage.absolute()
    if stage.parent!=root or not re.fullmatch(r'option-menu41-build[0-9]+',stage.name) or stage.exists():
        raise ValueError('Require a fresh named direct child of build root')
    idle()
    for name,digest in PINS.items():
        if sha(root/name)!=digest:raise ValueError('Baseline identity mismatch: '+name)
    if sha(candidate)!=NEW_SOURCE:raise ValueError('Wrong menu candidate')
    base=root/BASE/'compact-system';product=root/'out-eng-02/target/product/n139dl/system'
    if (root/BASE/'build.exit').read_text().strip()!='0':raise ValueError('Image40 build incomplete')
    if (base/'build.prop').read_text().splitlines().count('ro.kaidroid.image=40')!=1:raise ValueError('Not image40')
    for name,digest in FRAMEWORK.items():
        if sha(base/name)!=digest or sha(product/name)!=digest:raise ValueError('Framework baseline mismatch: '+name)
    closure=sorted(p.relative_to(base).as_posix() for p in (base/'framework').rglob('*')
        if p.is_file() and not p.is_symlink() and p.suffix in ('.art','.oat','.odex','.vdex'))
    closure+=list(FRAMEWORK)+['framework/ethernet-service.jar','framework/com.android.location.provider.jar']
    if len(closure)!=len(set(closure)) or not all((product/p).is_file() for p in closure):raise ValueError('Invalid closure')
    apex=base/'apex/com.android.art.release'
    apex_files=sorted(p.relative_to(base).as_posix() for p in apex.rglob('*')
        if p.is_file() and not p.is_symlink() and p.suffix in ('.art','.oat','.vdex','.jar'))
    if not apex_files or any(sha(base/p)!=sha(product/p) for p in apex_files):raise ValueError('ART APEX mismatch')
    allocated=int(subprocess.check_output(['du','-sk',str(root/'out-eng-02')]).split()[0])*1024
    if shutil.disk_usage(root).free<2*allocated+20*1024**3:raise ValueError('Insufficient free space for isolated clone/build')
    stage.mkdir();inputs=stage/'inputs';inputs.mkdir();(stage/'ninja').mkdir()
    shutil.copy2(root/SOURCE,inputs/'MenuBar.original.java');shutil.copy2(candidate,inputs/'MenuBar.java')
    graph_sha=sha(root/'out-eng-02/soong/build.ninja')
    (stage/'clone-state.json').write_text(json.dumps(dict(state='copying',allocated_bytes=allocated,shared_graph_sha256=graph_sha))+'\n')
    print('Cloning output into fresh stage; shared source and outputs remain untouched.',flush=True)
    with (stage/'clone.log').open('wb') as log:
        process=subprocess.Popen(['cp','--reflink=auto','-a',str(root/'out-eng-02'),str(stage/'out')],stdout=log,stderr=subprocess.STDOUT)
        (stage/'clone.pid').write_text(str(process.pid)+'\n')
        if process.wait()!=0:raise ValueError('Clone failed; retain stage and inspect clone.log')
    idle()
    if sha(root/'out-eng-02/soong/build.ninja')!=graph_sha or sha(stage/'out/soong/build.ninja')!=graph_sha:
        raise ValueError('Graph changed during clone')
    for name,digest in PINS.items():
        if sha(root/name)!=digest:raise ValueError('Baseline changed during clone: '+name)
    for name,digest in FRAMEWORK.items():
        copied=stage/'out/target/product/n139dl/system'/name
        if sha(copied)!=digest or copied.stat().st_ino==(product/name).stat().st_ino:raise ValueError('Clone not independent')
    for name in ('.ninja_log','.ninja_deps'):
        shutil.copy2(stage/'out'/name,stage/'ninja'/name)
    (inputs/'query.ninja').write_text('pool highmem_pool\n  depth = 1\nsubninja /build/out-eng-02/soong/build.ninja\n'
        'builddir = /build/'+stage.name+'/ninja\n')
    (stage/'targets.txt').write_text(''.join('/build/out-eng-02/target/product/n139dl/system/'+p+'\n' for p in closure))
    script=build_script.read_text().replace('STAGE_NAME',stage.name)
    (stage/'build.sh').write_text(script,newline='\n')
    launcher='''#!/usr/bin/env bash
set -euo pipefail
root=ROOT
stage="$root/STAGE_NAME"
test -f "$stage/staging.json"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
if pgrep -x ninja >/dev/null || pgrep -x soong_build >/dev/null || pgrep -x e2fsdroid >/dev/null; then
  echo 'Another build is active; do not launch.' >&2; exit 1
fi
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
sudo docker run -d --name kaidroid-STAGE_NAME --network none \\
  -v "$root:/build:ro" -v "$root:/baseline:ro" \\
  -v "$stage:/build/STAGE_NAME:rw" -v "$stage/out:/build/out-eng-02:rw" \\
  -v "$stage/inputs/MenuBar.java:/build/aosp/frameworks/base/core/java/android/widget/MenuBar.java:ro" \\
  kaidroid-build:20261023 bash /build/STAGE_NAME/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''.replace('ROOT',str(root)).replace('STAGE_NAME',stage.name)
    (stage/'launch.sh').write_text(launcher)
    manifest=dict(baseline_image=40,reserved_image=41,source=SOURCE,candidate_sha256=NEW_SOURCE,
        baseline_pins=PINS,framework_pins=FRAMEWORK,closure=closure,
        before_closure={p:sha(base/p) for p in closure},art_apex={p:sha(base/p) for p in apex_files},
        shared_graph_sha256=graph_sha,shared_root_read_only=True,independent_output_clone=True,
        export_scope='Framework/preopt closure only; never replace image40 APK tree with shared product output',
        inputs={str(p.relative_to(stage)):sha(p) for p in [inputs/'MenuBar.java',inputs/'MenuBar.original.java',inputs/'query.ninja',stage/'targets.txt',stage/'build.sh',stage/'launch.sh']},
        launched=False,installed=False)
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (stage/'clone-state.json').write_text(json.dumps(dict(state='complete',allocated_bytes=allocated))+'\n')
    print(json.dumps(dict(stage=str(stage),closure_files=len(closure),launched=False)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','candidate','stage','build-script'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();prepare(a.root,a.candidate,a.stage,a.build_script)

"""Prepare isolated image42 framework closure from verified41 output; never launch."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

SOURCE='aosp/frameworks/base/core/java/android/widget/MenuBar.java'
OLD_SOURCE='73f871ffa9bda03951050d91cab118f6a8f6e663e1090fc68ce8767a1389cc26'
NEW_SOURCE='cf53c3f317a2470f46c713f395fd5769ebbe86977928bb07efb6819275343f4b'
BASE='engineering-option-menu-stage-41'
CLONE='option-menu41-build01/out'
PINS={SOURCE:OLD_SOURCE,
 'aosp/frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java':'eae4f86569e8ea885a0a2620c99216b50637de8e0d4424b0747773e142448afc',
 'engineering-option-menu-stage-41/compact-image/system.raw.img':'60d659580278bfe3dcc09ca92b1910d4f9d7af27ca8e62e87a67ff9e0d4ae5fe',
 'engineering-option-menu-stage-41/compact-system/system_ext/priv-app/SystemUI/SystemUI.apk':'f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0',
 'engineering-option-menu-stage-41/compact-system/priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'}
FRAMEWORK={'framework/framework.jar':'fb116ee31688cd20f6c8ab6cbc73d69c7664c05e491e0325fc05dc4daa033d86',
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
    if stage.parent!=root or not re.fullmatch(r'option-menu42-build[0-9]+',stage.name) or stage.exists():
        raise ValueError('Require a fresh named direct child of build root')
    idle()
    if (root/'option-menu41-build01/retry04.exit').read_text().strip()!='0':raise ValueError('Prior framework build incomplete')
    for name,digest in PINS.items():
        if sha(root/name)!=digest:raise ValueError('Baseline identity mismatch: '+name)
    if sha(candidate)!=NEW_SOURCE:raise ValueError('Wrong menu candidate')
    base=root/BASE/'compact-system';product=root/CLONE/'target/product/n139dl/system'
    if (root/BASE/'build.exit').read_text().strip()!='0':raise ValueError('Image41 build incomplete')
    if (base/'build.prop').read_text().splitlines().count('ro.kaidroid.image=41')!=1:raise ValueError('Not image41')
    for name,digest in FRAMEWORK.items():
        if sha(base/name)!=digest or sha(product/name)!=digest:raise ValueError('Framework baseline mismatch: '+name)
    closure=sorted(p.relative_to(base).as_posix() for p in (base/'framework').rglob('*')
        if p.is_file() and not p.is_symlink() and p.suffix in ('.art','.oat','.odex','.vdex'))
    closure+=list(FRAMEWORK)+['framework/ethernet-service.jar','framework/com.android.location.provider.jar']
    if len(closure)!=len(set(closure)) or not all((product/p).is_file() for p in closure):raise ValueError('Invalid closure')
    for name in closure:
        if sha(base/name)!=sha(product/name):raise ValueError('Prior output closure differs from image41: '+name)
    apex=base/'apex/com.android.art.release'
    apex_files=sorted(p.relative_to(base).as_posix() for p in apex.rglob('*')
        if p.is_file() and not p.is_symlink() and p.suffix in ('.art','.oat','.vdex','.jar'))
    if not apex_files or any(sha(base/p)!=sha(product/p) for p in apex_files):raise ValueError('ART APEX mismatch')
    allocated=int(subprocess.check_output(['du','-sk',str(root/CLONE)]).split()[0])*1024
    if shutil.disk_usage(root).free<2*allocated+20*1024**3:raise ValueError('Insufficient free space for isolated clone/build')
    stage.mkdir();inputs=stage/'inputs';inputs.mkdir();(stage/'ninja').mkdir()
    shutil.copy2(root/SOURCE,inputs/'MenuBar.original.java');shutil.copy2(candidate,inputs/'MenuBar.java')
    graph_sha=sha(root/CLONE/'soong/build.ninja')
    graphs={name:sha(root/CLONE/name) for name in ('soong/build.ninja','combined-kaidroid_n139dl.ninja')}
    (stage/'clone-state.json').write_text(json.dumps(dict(state='copying',allocated_bytes=allocated,shared_graph_sha256=graph_sha))+'\n')
    print('Cloning output into fresh stage; shared source and outputs remain untouched.',flush=True)
    with (stage/'clone.log').open('wb') as log:
        process=subprocess.Popen(['cp','--reflink=auto','-a',str(root/CLONE),str(stage/'out')],stdout=log,stderr=subprocess.STDOUT)
        (stage/'clone.pid').write_text(str(process.pid)+'\n')
        if process.wait()!=0:raise ValueError('Clone failed; retain stage and inspect clone.log')
    idle()
    if sha(root/CLONE/'soong/build.ninja')!=graph_sha or sha(stage/'out/soong/build.ninja')!=graph_sha:
        raise ValueError('Graph changed during clone')
    for name,digest in graphs.items():
        if sha(root/CLONE/name)!=digest or sha(stage/'out'/name)!=digest:raise ValueError('Graph clone mismatch: '+name)
    for name,digest in PINS.items():
        if sha(root/name)!=digest:raise ValueError('Baseline changed during clone: '+name)
    for name in closure:
        digest=sha(base/name)
        copied=stage/'out/target/product/n139dl/system'/name
        if sha(copied)!=digest or copied.stat().st_ino==(product/name).stat().st_ino:raise ValueError('Clone not independent')
    for name in ('.ninja_log','.ninja_deps'):
        shutil.copy2(stage/'out'/name,stage/'ninja'/name)
    (inputs/'query.ninja').write_text('subninja /build/out-eng-02/combined-kaidroid_n139dl.ninja\n')
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
    manifest=dict(baseline_image=41,reserved_image=42,clone_source=CLONE,source=SOURCE,candidate_sha256=NEW_SOURCE,
        baseline_pins=PINS,framework_pins=FRAMEWORK,closure=closure,
        before_closure={p:sha(base/p) for p in closure},art_apex={p:sha(base/p) for p in apex_files},
        shared_graph_sha256=graph_sha,graph_pins=graphs,shared_root_read_only=True,independent_output_clone=True,
        export_scope='Framework/preopt closure only; never replace image41 APK tree with shared product output',
        inputs={str(p.relative_to(stage)):sha(p) for p in [inputs/'MenuBar.java',inputs/'MenuBar.original.java',inputs/'query.ninja',stage/'targets.txt',stage/'build.sh',stage/'launch.sh']},
        launched=False,installed=False)
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (stage/'clone-state.json').write_text(json.dumps(dict(state='complete',allocated_bytes=allocated))+'\n')
    print(json.dumps(dict(stage=str(stage),closure_files=len(closure),launched=False)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','candidate','stage','build-script'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();prepare(a.root,a.candidate,a.stage,a.build_script)

"""Stage only the verified SystemUI candidate and revision marker over image39."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

BASE_APK='203f2f316c48a354fc5ee2e0477da35b97b78604e63a2ae5e9ca9778719e5586'
CANDIDATE='f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'
BASE_RAW='c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b'
APK='system_ext/priv-app/SystemUI/SystemUI.apk'


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def inventory(root):
    result={}
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            p=Path(folder)/name
            result[p.relative_to(root).as_posix()]=(
                ['link',os.readlink(p)] if p.is_symlink() else
                ['dir',p.stat().st_mode&0o7777] if p.is_dir() else
                ['file',p.stat().st_mode&0o7777,sha(p)])
    return result


def stage(root,build_script):
    root=root.resolve(strict=True)
    base=root/'engineering-messaging-stage-39-retry02'
    out=root/'engineering-lazy-wifi-stage-40'
    candidate=root/'memory-lazy-wifi-build04/output/SystemUI.apk'
    if out.exists():raise FileExistsError(out)
    if (base/'build.exit').read_text().strip()!='0':raise ValueError('Image39 build not successful')
    if sha(base/'compact-image/system.raw.img')!=BASE_RAW:raise ValueError('Wrong base image39')
    if sha(base/'compact-system'/APK)!=BASE_APK or sha(candidate)!=CANDIDATE:
        raise ValueError('Wrong SystemUI identity')
    before=inventory(base/'compact-system');root_before=inventory(base/'compact-root')
    props=(base/'compact-system/build.prop').read_bytes()
    if props.splitlines().count(b'ro.kaidroid.image=39')!=1:raise ValueError('Wrong image revision')
    out.mkdir()
    for name in ('compact-system','compact-root'):
        shutil.copytree(base/name,out/name,symlinks=True)
    (out/'compact-image').mkdir()
    shutil.copyfile(candidate,out/'compact-system'/APK)
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=39',b'ro.kaidroid.image=40'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    config=(base/'system_image_info.compact.txt').read_text()
    if config.count('/build/'+base.name+'/')!=2:raise ValueError('Unexpected image build config')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
    after=inventory(out/'compact-system')
    changed={n for n in before.keys()|after.keys() if before.get(n)!=after.get(n)}
    if changed!={APK,'build.prop'}:raise ValueError('Unexpected staged file changes')
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=root_before:
        raise ValueError('Original stage mutated')
    if inventory(out/'compact-root')!=root_before:raise ValueError('Root closure changed')
    provider='priv-app/TelephonyProvider/TelephonyProvider.apk'
    if sha(out/'compact-system'/provider)!='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c':
        raise ValueError('Provider68 identity changed')
    report=dict(image=40,baseline_image=39,base_raw_sha256=BASE_RAW,
        baseline_entries=len(before),baseline_stage_unchanged=True,root_unchanged=True,
        changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},
        candidate_apk_sha256=CANDIDATE,provider_schema68_preserved=True,
        apk_size_delta_bytes=candidate.stat().st_size-(base/'compact-system'/APK).stat().st_size,
        system_partition_bytes=834666496,avb_required=True,installed=False,built=False)
    (out/'staging.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'system-inventory.json').write_text(json.dumps(after,indent=2)+'\n')
    (out/'root-inventory.json').write_text(json.dumps(root_before,indent=2)+'\n')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    launcher='''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-lazy-wifi-stage-40"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
if pgrep -x ninja >/dev/null || pgrep -x soong_build >/dev/null || pgrep -x e2fsdroid >/dev/null; then
  echo 'Another build is active; stop before launch.' >&2
  exit 1
fi
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
sudo docker run -d --name kaidroid-memory-lazy-wifi-image40 \\
  -v "$root:/build:ro" \\
  -v "$stage:/build/engineering-lazy-wifi-stage-40:rw" \\
  kaidroid-build:20261023 bash /build/engineering-lazy-wifi-stage-40/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''
    (out/'launch.sh').write_text(launcher)
    print(json.dumps(report))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--build-script',type=Path,required=True)
    a=p.parse_args();stage(a.root,a.build_script)

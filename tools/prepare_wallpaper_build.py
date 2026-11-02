"""Prepare a fresh isolated SystemUI stage only after the hardware owner assigns it.

Render-only mode is local/offline. Neither mode launches Docker or touches AOSP.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from prepare_wallpaper_buffer_candidate import ENGINE, RENDERER, PINS

ROOT='/opt/kaidroid/kaidroid-build-20261023'
RETAINED='memory-lazy-bubbles-build02'
APK='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
GRAPH='931aa0c06b4ccb817efaef6098c52574215608b0952c8eb168c3246b1abb6e4d'
SCRIPTS={'build.sh':'660d26ed94a1567e0d03cb9ca3220a576486d48a208502df84daef157e8a2a90',
         'launch.sh':'2b89ca3d1925dcc69f52bafa9509aecf0d63385f1a3720d453e6bb4ad65168ff',
         'query.ninja':'132026ea47eb634aaa8ae23e807e017ef6a64b7d20b5cd0ece2c34096be64095'}
SOURCES={ENGINE:('ImageWallpaper.java','e2df0e541cf1125a10171c22dde66f3b127253a5cfb3c42e79d7f5288245f267'),
         RENDERER:('ImageWallpaperRenderer.java','c9f2d09818b3763d384435d8196f22e09e9b5dbc7056a93204f3601f1301c859')}


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text,old,new):
    if text.count(old)!=1: raise ValueError('Unexpected script marker: '+old)
    return text.replace(old,new,1)


def render(manifest,scripts,name):
    if not re.fullmatch(r'memory-wallpaper-build\d{2}',name): raise ValueError('Invalid stage name')
    if manifest['stage']!=ROOT+'/'+RETAINED or manifest['ninja_manifest_sha256']!=GRAPH:
        raise ValueError('Retained stage/graph identity mismatch')
    pins={'candidate_source_sha256':'fe9b1542b7013a082db6070927c69b5097eb4a600277b1932d2219dcd28bdea5'}
    if any(manifest[k]!=v for k,v in pins.items()) or manifest['additional_source']['candidate_sha256']!='1dabead7099acf7536275df2a81b7f753cd3f303da95195b9934e904e5acd51c' or manifest['optimizer_policy']['candidate_sha256']!='457e4098fa25ee5bb88b51eb5f7670994fc30efe08473acd36a609439c5c68e5':
        raise ValueError('Retained Wi-Fi/bubble/optimizer inputs changed')
    for key,pin in SCRIPTS.items():
        if hashlib.sha256(scripts[key]).hexdigest()!=pin: raise ValueError('Retained script changed: '+key)
    rendered={key:data.decode().replace(RETAINED,name) for key,data in scripts.items()}
    launch=once(rendered['launch.sh'],'test -f "$stage/bubbles-staging.complete"',
                'test -f "$stage/wallpaper-staging.complete"')
    launch=once(launch,'pgrep -x soong_build >/dev/null; then',
                'pgrep -x soong_build >/dev/null || pgrep -x e2fsdroid >/dev/null; then')
    marker='  kaidroid-build:20261023 bash '
    mounts=''.join('  -v "$stage/inputs/'+filename+':/build/aosp/'+path+':ro" \\\n' for path,(filename,_) in SOURCES.items())
    launch=once(launch,marker,mounts+marker)
    guard="""assert m['wallpaper_prepared'] is True
for item in m['wallpaper_sources']:
 assert hashlib.sha256((Path('/build/aosp')/item['path']).read_bytes()).hexdigest()==item['candidate_sha256'],item['path']
"""
    build=once(rendered['build.sh'],'PY\nprebuilts/build-tools/linux-x86/bin/ninja',guard+'PY\nprebuilts/build-tools/linux-x86/bin/ninja')
    build=once(build,"before=entries(s/'inputs/SystemUI.original.apk');after=entries(p)",
               "before=entries(s/'inputs/SystemUI.comparison.apk');after=entries(p)")
    updated=copy.deepcopy(manifest)
    updated.update(stage=ROOT+'/'+name,retained_stage=ROOT+'/'+RETAINED,
        retained_comparison_apk_sha256=APK,baseline_apk_sha256=APK,
        installed_comparison_apk_sha256=APK,shared_source_baseline_apk_sha256=manifest['baseline_apk_sha256'],
        wallpaper_sources=[dict(path=path,input_name=filename,original_sha256=PINS[path],candidate_sha256=pin)
                           for path,(filename,pin) in SOURCES.items()],
        wallpaper_prepared=False,launched=False,installed=False,
        output_closure='One signed SystemUI APK; subsequent DEX/ABI/cert/image/behavior and physical-memory gates remain.')
    return updated,{'build.sh':build,'launch.sh':launch,'query.ninja':rendered['query.ninja']}


def stage(root,retained,candidate_root,name):
    if os.name!='posix': raise ValueError('Actual stage preparation is Linux only')
    root=root.resolve(strict=True);retained=retained.resolve(strict=True)
    destination=root/name
    if str(root)!=ROOT or retained!=root/RETAINED or destination.exists(): raise ValueError('Require reviewed root/retained stage and new destination')
    manifest=json.loads((retained/'staging.json').read_text())
    scripts={key:(retained/('inputs/query.ninja' if key=='query.ninja' else key)).read_bytes() for key in SCRIPTS}
    updated,rendered=render(manifest,scripts,name)
    if (retained/'build.exit').read_text().strip()!='0' or sha(retained/'output/SystemUI.apk')!=APK:
        raise ValueError('Retained completed APK does not match installed comparison')
    if sha(root/'out-eng-02/soong/build.ninja')!=GRAPH: raise ValueError('Shared graph changed')
    for filename,pin in manifest['inputs'].items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',filename): raise ValueError('Invalid retained input name')
        path=retained/'inputs'/filename
        if path.is_symlink() or sha(path)!=pin: raise ValueError('Retained input changed: '+filename)
    if {p.name for p in (retained/'inputs').iterdir()}!=set(manifest['inputs']):
        raise ValueError('Retained inputs contain unreviewed entries')
    subtrees=['inputs','ninja','intermediates','settingslib-intermediates','dependency-intermediates']
    for subtree in subtrees:
        path=retained/subtree
        if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(retained):
            raise ValueError('Retained cache subtree escapes the reviewed stage')
    for path,(_,pin) in SOURCES.items():
        if sha(root/'aosp'/path)!=PINS[path] or sha(candidate_root/path)!=pin: raise ValueError('Wallpaper source pin changed')
    for process in ['ninja','soong_build','e2fsdroid']:
        if subprocess.run(['pgrep','-x',process],capture_output=True).returncode!=1:
            raise ValueError('Build active or status ambiguous; no stage copied')
    sizes=subprocess.run(['du','-sb','--count-links',*[str(retained/subtree) for subtree in subtrees]],
                         capture_output=True,text=True,check=True)
    copy_bytes=sum(int(line.split('\t',1)[0]) for line in sizes.stdout.splitlines())
    free=shutil.disk_usage(root).free
    if free<copy_bytes+2*1024**3: raise ValueError('Insufficient free space for private copies and2GiB margin')
    updated['copy_space_preflight']=dict(subtree_apparent_bytes=copy_bytes,free_bytes=free,margin_bytes=2*1024**3)
    destination.mkdir()
    # Copy only retained inputs/private output caches, never old launch/status/log/output files.
    for subtree in subtrees:
        subprocess.run(['cp','--reflink=auto','-a',str(retained/subtree),str(destination/subtree)],check=True)
    shutil.copy2(retained/'output/SystemUI.apk',destination/'inputs/SystemUI.comparison.apk')
    for path,(filename,_) in SOURCES.items():
        (destination/'inputs'/filename).write_bytes((candidate_root/path).read_bytes())
        (destination/'inputs'/(filename+'.original')).write_bytes((root/'aosp'/path).read_bytes())
    for filename,text in rendered.items():
        target=destination/('inputs/query.ninja' if filename=='query.ninja' else filename)
        target.write_bytes(text.encode())
    # Do not inherit archive timestamps that let Ninja reuse an unchanged APK.
    cached=[destination/'intermediates/SystemUI-core/android_common/javac/SystemUI-core.jar',
            destination/'intermediates/SystemUI/android_common/SystemUI.apk']
    if any(p.is_symlink() or not p.resolve().is_relative_to(destination) for p in cached):
        raise ValueError('Cached output escapes private stage')
    now=time.time_ns();latest=max(p.stat().st_mtime_ns for p in cached)
    if latest>now+5_000_000_000: raise ValueError('Future cached output timestamp; incomplete stage remains unlaunchable')
    fresh=max(now,latest+2_000_000_000)
    touched=['AccessPointControllerImpl.java','BubbleDataRepository.kt','SystemUI.proguard.flags']+[x[0] for x in SOURCES.values()]
    for filename in touched: os.utime(destination/'inputs'/filename,ns=(fresh,fresh))
    updated['fresh_input_timestamp_ns']=fresh
    updated['wallpaper_prepared']=True
    updated['inputs']={p.name:sha(p) for p in (destination/'inputs').iterdir() if p.is_file()}
    updated['free_bytes_after_preparation']=shutil.disk_usage(root).free
    (destination/'staging.json').write_text(json.dumps(updated,indent=2)+'\n')
    subprocess.run(['bash','-n',str(destination/'build.sh')],check=True)
    subprocess.run(['bash','-n',str(destination/'launch.sh')],check=True)
    (destination/'wallpaper-staging.complete').write_text(sha(destination/'staging.json')+'\n')
    return updated


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',required=True)
    parser.add_argument('--render-only',type=Path)
    parser.add_argument('--retained-snapshot',type=Path)
    parser.add_argument('--retained-scripts',type=Path)
    parser.add_argument('--root',type=Path)
    parser.add_argument('--retained-stage',type=Path)
    parser.add_argument('--candidate-root',type=Path)
    args=parser.parse_args()
    if args.render_only:
        snapshot=json.loads(args.retained_snapshot.read_text())
        if snapshot['build_exit'].strip()!='0' or snapshot['output_sha256']!=APK: raise ValueError('Retained snapshot mismatch')
        manifest,rendered=render(snapshot['manifest'],{key:(args.retained_scripts/key).read_bytes() for key in SCRIPTS},args.name)
        args.render_only.mkdir(parents=True,exist_ok=False)
        for name,text in rendered.items(): (args.render_only/name).write_bytes(text.encode())
        (args.render_only/'proposal.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print('Rendered local held proposal only; no remote stage created.')
    else:
        if not all([args.root,args.retained_stage,args.candidate_root]): parser.error('Actual stage requires root/retained-stage/candidate-root')
        print(json.dumps(stage(args.root,args.retained_stage,args.candidate_root,args.name),indent=2))

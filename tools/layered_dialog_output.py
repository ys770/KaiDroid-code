"""Check private dialog OverlayFS mounts and journal preserved lower/derived upper files."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

ROOT=PurePosixPath('/opt/kaidroid/kaidroid-build-20261023')


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def unescape(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)


def mounts(text):
    rows={}
    for line in text.splitlines():
        left,right=line.split(' - ',1);a=left.split();b=right.split()
        target=unescape(a[4])
        rows.setdefault(target,[]).append(dict(root=unescape(a[3]),options=set(a[5].split(',')),fstype=b[0],
            super_options=dict((v.split('=',1) if '=' in v else (v,'')) for v in unescape(b[2]).split(','))))
    return rows


def verify_mounts(stage,spec,text=None,readonly=None):
    layer=spec['layered_output'];rows=mounts(Path('/proc/self/mountinfo').read_text(encoding='utf-8') if text is None else text)
    host_stage=PurePosixPath(layer['merged']).parent
    expected_paths=dict(lower=str(ROOT/'tcl-dialog-build01/out'),lower_ro=str(host_stage/'lower-ro'),
        upper=str(host_stage/'cache-upper'),work=str(host_stage/'cache-work'),merged=str(host_stage/'out'))
    if host_stage.parent!=ROOT or not re.fullmatch('tcl-dialog-build[0-9]+',host_stage.name) or \
            any(layer.get(k)!=v for k,v in expected_paths.items()):raise ValueError('Layer path scope changed')
    host=stage==host_stage
    if not host and stage!=PurePosixPath('/build')/host_stage.name:raise ValueError('Unknown mount namespace/stage mapping')
    def ro(path):
        return readonly[str(path)] if readonly is not None else bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    lowers=rows.get(str(stage/'lower-ro'),[])
    if not lowers or host and len(lowers)!=1 or not ro(stage/'lower-ro'):
        raise ValueError('Missing or writable effective lower bind')
    for lower in lowers:
        if lower['root']!=layer['lower'] or lower['fstype']!='ext4' or 'ro' not in lower['options']:
            raise ValueError('Original lower must be exact read-only ext4 bind in every exposed mount')
    expected={'lowerdir':layer['lower_ro'],'upperdir':layer['upper'],'workdir':layer['work']}
    outputs=[stage/'out'] if host else [stage/'out',PurePosixPath('/build/out-eng-02')]
    for target in outputs:
        merged=rows.get(str(target),[])
        if not merged or host and len(merged)!=1 or ro(target):raise ValueError('Missing/wrong effective writable OverlayFS output')
        for entry in merged:
            if entry['fstype']!='overlay' or entry['root']!='/' or not entry['options'] & {'rw','ro'} or \
                    any(entry['super_options'].get(k)!=v for k,v in expected.items()):
                raise ValueError('OverlayFS lower/upper/work/root identity changed')
            if 'volatile' in entry['super_options'] or any(entry['super_options'].get(k,'off')!='off' for k in ('index','redirect_dir','metacopy')):
                raise ValueError('Unreviewed OverlayFS copy-up behavior')
    return True


def inventory(root,identity=True):
    rows={}
    def item(path):
        relative=path.relative_to(root).as_posix();s=path.lstat();kind=stat.S_IFMT(s.st_mode)
        attrs={n:os.getxattr(path,n,follow_symlinks=False).hex() for n in os.listxattr(path,follow_symlinks=False)}
        row=dict(mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,xattrs=attrs)
        if identity:row.update(device=s.st_dev,inode=s.st_ino,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
        if kind==stat.S_IFREG:row['sha256']=sha(path)
        elif kind==stat.S_IFLNK:row['target']=os.readlink(path)
        elif kind==stat.S_IFIFO:row['fifo']=True  # Metadata only: never open a Ninja notification stream.
        elif kind==stat.S_IFSOCK:row['socket']=True  # Metadata only: never open/connect to the path-interposer socket.
        elif kind==stat.S_IFCHR and s.st_rdev==0:row['whiteout']=True
        elif kind!=stat.S_IFDIR:raise ValueError('Unexpected cache file type: '+str(path))
        rows[relative]=row
    item(root)
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:item(Path(folder)/name)
    return rows


def write_new(path,value):
    with path.open('x',encoding='utf-8') as stream:stream.write(json.dumps(value,sort_keys=True,indent=2)+'\n')


def semantic(rows):
    omit={'device','inode','mtime_ns','ctime_ns'}
    return {n:{k:v for k,v in row.items() if k not in omit} for n,row in rows.items()}


def owned_stage(path):
    stage=path.resolve(strict=True)
    if stage.parent!=ROOT or not re.fullmatch('tcl-dialog-build[0-9]+',stage.name):
        raise ValueError('Not a dedicated named dialog stage')
    return stage


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('snapshot','verify','finish'));p.add_argument('--stage',type=Path,required=True)
    a=p.parse_args();stage=owned_stage(a.stage)
    if a.mode=='snapshot':
        if os.geteuid()!=0:raise ValueError('Full lower xattr snapshot requires host root')
        lower=Path(ROOT)/'tcl-dialog-build01/out'
        rows=inventory(lower);write_new(stage/'cache-lower-before.json',rows)
        print(json.dumps(dict(lower_entries=len(rows),sha256=sha(stage/'cache-lower-before.json'))));return
    spec=json.loads((stage/'staging.json').read_text(encoding='utf-8'))
    if (stage/'preparation.complete').read_text(encoding='utf-8').strip()!=sha(stage/'staging.json'):raise ValueError('Stage completion hash changed')
    controls=json.loads((stage/'control-inputs.json').read_text(encoding='utf-8'))
    if set(controls)!={'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}:
        raise ValueError('Unexpected stage controls')
    for name,pin in controls.items():
        if sha(stage/name)!=pin:raise ValueError('Stage control changed: '+name)
    verify_mounts(stage,spec)
    if a.mode=='verify':return
    if os.geteuid()!=0:raise ValueError('Final full-cache preservation proof requires host root')
    cid=(stage/'container-id').read_text(encoding='utf-8').strip()
    if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('Require exact container ID')
    info=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0];state=info['State']
    if (info.get('Config',{}).get('Labels') or {}).get('kaidroid.dialog.staging')!=sha(stage/'staging.json'):
        raise ValueError('Terminal container is bound to different stage metadata')
    if info.get('Id')!=cid or info.get('Name')!='/kaidroid-'+stage.name or \
            info['Config'].get('Cmd')!=['bash','/build/'+stage.name+'/build.sh'] or \
            state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('Pid')!=0:
        raise ValueError('Observe same container until authoritative terminal before cache proof')
    if sha(stage/'cache-lower-before.json')!=spec['layered_output']['before_inventory_sha256']:
        raise ValueError('Original lower snapshot changed')
    before=json.loads((stage/'cache-lower-before.json').read_text(encoding='utf-8'))
    lower=inventory(Path(spec['layered_output']['lower']))
    if before!=lower:raise ValueError('Existing lower cache file/content/metadata changed')
    upper=inventory(Path(spec['layered_output']['upper']))
    view=inventory(stage/'out',identity=False);old=semantic(before)
    changes={n:dict(before=old.get(n),after=view.get(n)) for n in old.keys()|view.keys() if old.get(n)!=view.get(n)}
    write_new(stage/'cache-upper-after.json',upper)
    write_new(stage/'cache-view-delta.json',changes)
    write_new(stage/'cache-preservation.json',dict(container_id=cid,terminal_state=state,
        original_lower_all_files_content_metadata_unchanged=True,lower_entries=len(before),upper_entries=len(upper),
        projected_changed_entries=len(changes),projected_removed_entries=sorted(old.keys()-view.keys()),
        shadowed_existing_paths=sorted((upper.keys()&before.keys())-set(['.'])),
        before_inventory_sha256=sha(stage/'cache-lower-before.json'),upper_inventory_sha256=sha(stage/'cache-upper-after.json'),
        view_delta_sha256=sha(stage/'cache-view-delta.json'),
        scope='Original lower files preserved; compiler overwrites/removals exist only as new upper files/whiteouts'))
    print(json.dumps(dict(original_lower_unchanged=True,projected_changes=len(changes))))


if __name__=='__main__':main()

"""Native09 storage policy; read-only validation, never create or mount anything."""
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

STORAGE_ROOT = '/opt/kaidroid/kaidroid-build-20261023'
STORAGE_STAGE = 'tcl-dialog-build09'
STORAGE_VOLUME = '/mnt/ext1'
STORAGE_BACKING = STORAGE_VOLUME+'/kaidroid-tcl-dialog-build09'
STORAGE_GIB = 1024**3


def storage_mounts(text):
    def decode(s):
        return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),s)
    rows = {}
    for line in text.splitlines():
        left,right=line.split(' - ',1);a=left.split();b=right.split()
        rows.setdefault(decode(a[4]),[]).append(dict(device=a[2],root=decode(a[3]),
            options=set(a[5].split(',')),fstype=b[0],source=decode(b[1]),
            super_options=set(b[2].split(','))))
    return rows


def storage_layout(stage, rows, stats, host):
    """Validate exact namespace, device, mount roots and directory identities."""
    stage=PurePosixPath(stage)
    root=PurePosixPath(STORAGE_ROOT if host else '/build')
    if stage!=root/STORAGE_STAGE:
        raise ValueError('Unreviewed external stage path')
    expected_root='/kaidroid-tcl-dialog-build09'
    entries=rows.get(str(stage),[])
    if not entries or host and len(entries)!=1:
        raise ValueError('Missing or ambiguous stage bind mount')
    for row in entries:
        if row['device']!='8:0' or row['root']!=expected_root or row['fstype']!='ext4' or row['source']!='/dev/sda':
            raise ValueError('Wrong external stage mount identity')
    if 'rw' not in entries[-1]['options'] or 'rw' not in entries[-1]['super_options']:
        raise ValueError('External stage must be writable')
    for name in (str(root),str(stage)):
        s=stats[name]
        if not stat.S_ISDIR(s.st_mode) or (s.st_uid,s.st_gid)!=(1000,1000):
            raise ValueError('Storage directory type/owner changed')
    s=stats[str(stage)]
    if s.st_dev!=2048 or stat.S_IMODE(s.st_mode)!=0o700 or stats[str(root)].st_dev!=66306:
        raise ValueError('Storage device or private stage mode changed')
    if host:
        volume=rows.get(STORAGE_VOLUME,[])
        if len(volume)!=1 or any(volume[0][k]!=v for k,v in dict(device='8:0',root='/',fstype='ext4',source='/dev/sda').items()) or \
                'rw' not in volume[0]['options'] or 'rw' not in volume[0]['super_options']:
            raise ValueError('External volume mount changed')
        for name in (STORAGE_VOLUME,STORAGE_BACKING):
            other=stats[name]
            if not stat.S_ISDIR(other.st_mode) or (other.st_uid,other.st_gid,other.st_dev)!=(1000,1000,2048) or stat.S_IMODE(other.st_mode)!=0o700:
                raise ValueError('Private backing/volume identity changed')
        if stats[STORAGE_BACKING].st_ino!=s.st_ino:
            raise ValueError('Stage bind does not identify exact backing inode')
    return True


def verify_external_storage(stage, fresh=False):
    stage=Path(stage)
    host=str(stage.parent)==STORAGE_ROOT
    root=Path(STORAGE_ROOT if host else '/build')
    paths=[root,stage]+([Path(STORAGE_VOLUME),Path(STORAGE_BACKING)] if host else [])
    for path in paths:
        if path.resolve(strict=True)!=path:
            raise ValueError('Symlinked external storage path')
    stats={str(p):p.lstat() for p in paths}
    storage_layout(str(stage),storage_mounts(Path('/proc/self/mountinfo').read_text()),stats,host)
    if fresh and (not host or any(stage.iterdir()) or any(Path(STORAGE_BACKING).iterdir())):
        raise ValueError('External preparation requires fresh empty bind/backing')
    for name in ('cache-upper','cache-work'):
        path=stage/name
        if path.exists():
            s=path.lstat()
            if path.resolve(strict=True)!=path or not stat.S_ISDIR(s.st_mode) or (s.st_dev,s.st_uid,s.st_gid)!=(2048,1000,1000):
                raise ValueError('Overlay upper/work left reviewed external device')
    return True


def external_capacity(plan, external_free, root_free, initial=False):
    for value in (external_free,root_free):
        if type(value) is not int or value<0:
            raise ValueError('Invalid volume free-space observation')
    if any(type(plan.get(k)) is not int for k in ('incremental_budget_bytes','emergency_floor_bytes','free_after_clone_bytes')) or \
            plan.get('incremental_budget_bytes')!=14*STORAGE_GIB or plan.get('emergency_floor_bytes')!=20*STORAGE_GIB or \
            type(plan.get('free_after_clone_bytes')) is not int or plan['free_after_clone_bytes']<34*STORAGE_GIB:
        raise ValueError('Unreviewed external volume budget')
    growth=max(0,plan['free_after_clone_bytes']-external_free)
    breach=('root_emergency_floor' if root_free<=20*STORAGE_GIB else
            'external_emergency_floor' if external_free<=20*STORAGE_GIB else
            'external_incremental_budget' if growth>=14*STORAGE_GIB else
            'external_budget_plus_floor_before_frontend' if initial and external_free<34*STORAGE_GIB else None)
    return dict(free_bytes=external_free,root_free_bytes=root_free,observed_growth_bytes=growth,breach=breach,
                writable_volume=STORAGE_BACKING,root_volume=STORAGE_ROOT)


def external_sample(root,stage,plan,initial=False,free=None):
    free=free or (lambda path:shutil.disk_usage(path).free)
    return external_capacity(plan,free(stage),free(root),initial)

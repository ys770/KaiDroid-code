"""Prepare/apply one reviewed reservation amendment to the already prepared stage.

Default plan mode is offline. Apply is hardware-owned Linux1000:1000 only;
backs up originals before changes, invalidates readiness until all checks pass,
and never re-prepares, snapshots, launches, removes or resets a build/cache.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
from prepare_scrollbar_reservation_amendment import amend_source

ROOT = Path('/opt/kaidroid/kaidroid-build-20261023')
STAGE = ROOT/'tcl-scrollbar-build01'
OLD_STAGE = 'af097d2f00a7686a13fd5fb56b340d96387cedd9cf95d5e9243ff6d639826e27'
OLD_PREPARER = '92a7e0e59c8aa037bbd32e59520e797e8077b42bd7077a40ae283189d9cc3fc1'
OLD_CONTROLS = 'ade98fabe53c20555f03212878cf50ab158eed9b0162f53366da15f1bb5e21a1'
HELPER_SHA = '77d83c00538034d1597e4ad708f913bd403620009af561e1c91ef8ac12924cda'
BACKUP = 'reservation-amendment-backup01'
PREPARER = 'inputs/tools/prepare_tcl_scrollbar_stage.py'
HELPER = 'inputs/tools/scrollbar_host_reservation.py'
CHANGED = (PREPARER, 'staging.json', 'control-inputs.json', 'preparation.complete')
JOB_MARKERS = ('container-id', 'build.log', 'build.exit', 'start.log')
INVALID = b'RESERVATION_AMENDMENT_INCOMPLETE\n'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def plan(staging, controls, complete, preparer, helper):
    require(sha(staging) == OLD_STAGE, 'Exact original prepared staging required')
    require(sha(preparer) == OLD_PREPARER, 'Exact original staged preparer required')
    require(sha(controls) == OLD_CONTROLS, 'Exact original control manifest required')
    require(sha(helper) == HELPER_SHA, 'Exact independently reviewed reservation helper required')
    require(complete == (OLD_STAGE+'\n').encode(), 'Original completion identity differs')
    before = json.loads(staging)
    control = json.loads(controls)
    require(control.get('staging.json') == OLD_STAGE and len(control) == 7, 'Original seven-control manifest differs')
    require(before['source_controls'] == {k:v for k,v in control.items() if k!='staging.json'}, 'Original control hashes disagree')
    require(before['inputs']['tools/prepare_tcl_scrollbar_stage.py'] == OLD_PREPARER and
            'tools/scrollbar_host_reservation.py' not in before['inputs'], 'Original helper/input set differs')
    changed = amend_source(preparer)
    after = copy.deepcopy(before)
    after['inputs']['tools/prepare_tcl_scrollbar_stage.py'] = sha(changed)
    after['inputs']['tools/scrollbar_host_reservation.py'] = HELPER_SHA
    after['reservation_amendment'] = dict(original_staging_sha256=OLD_STAGE, backup_directory=BACKUP,
        original_preparer_sha256=OLD_PREPARER, amended_preparer_sha256=sha(changed), helper_sha256=HELPER_SHA,
        scope='Only fresh host reservation at original idle gates; no resource/cache/build/launch changes',
        original_packet_retained=True, original_source_controls_unchanged=True)
    new_staging = encoded(after)
    new_control = copy.deepcopy(control)
    new_control['staging.json'] = sha(new_staging)
    payload = {PREPARER:changed, HELPER:helper, 'staging.json':new_staging,
               'control-inputs.json':encoded(new_control), 'preparation.complete':(sha(new_staging)+'\n').encode()}
    # Every other field is independently projected back to the actual original.
    restored = copy.deepcopy(after)
    del restored['reservation_amendment']
    del restored['inputs']['tools/scrollbar_host_reservation.py']
    restored['inputs']['tools/prepare_tcl_scrollbar_stage.py'] = OLD_PREPARER
    require(restored == before, 'Unrelated staging/resource/cache/source field changed')
    return payload


def regular(stage, name):
    path = stage/name
    require(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'Symlink/nonregular original: '+name)
    return path


def check_preparations(root):
    for record in list(root.glob('*/prepare.pid')) + list(root.glob('*/preparation.pid')):
        pid = int(record.read_text().strip())
        if pid == os.getpid():
            continue
        try:
            command = (Path('/proc')/str(pid)/'cmdline').read_bytes()
        except FileNotFoundError:
            continue
        require(b'prepare_' not in command and b'stage_' not in command, 'Other preparation is live; observe it')


def guarded_inputs(stage, helper):
    require(not any((stage/n).exists() or (stage/n).is_symlink() for n in JOB_MARKERS), 'Existing/ambiguous job; observe its handle')
    require(not (stage/BACKUP).exists() and not (stage/BACKUP).is_symlink(), 'Existing amendment backup; inspect/reconcile, do not repeat')
    require(not (stage/HELPER).exists() and not (stage/HELPER).is_symlink(), 'Existing helper must not be overwritten')
    originals = {name:regular(stage,name).read_bytes() for name in CHANGED}
    return originals, plan(originals['staging.json'], originals['control-inputs.json'], originals['preparation.complete'],
                           originals[PREPARER], helper)


def replace_owned(path, data, info=None):
    temporary = path.parent/('.reservation-new-'+uuid.uuid4().hex)
    fd = os.open(str(temporary), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.chmod(temporary, stat.S_IMODE(info.st_mode) if info else 0o644)
    if info and hasattr(os, 'listxattr'):
        for name in os.listxattr(path, follow_symlinks=False):
            os.setxattr(temporary, name, os.getxattr(path,name,follow_symlinks=False), follow_symlinks=False)
    os.replace(temporary,path)


def commit_files(stage, originals, payload, verify, after_replace=None):
    """Caller has verified live host/stage. Failed commit leaves readiness invalid."""
    backup = stage/BACKUP
    backup.mkdir(mode=0o700)
    metadata = {}
    for name in CHANGED:
        source = regular(stage,name)
        require(source.read_bytes() == originals[name], 'Original changed before backup: '+name)
        info = source.stat()
        target = backup/name; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target,follow_symlinks=False)
        require(target.read_bytes() == originals[name], 'Backup bytes differ')
        metadata[name] = dict(sha256=sha(originals[name]),mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,
                              mtime_ns=info.st_mtime_ns,size=info.st_size,
                              xattrs={n:os.getxattr(source,n,follow_symlinks=False).hex() for n in os.listxattr(source,follow_symlinks=False)} if hasattr(os,'listxattr') else {})
        copied = target.stat()
        require((copied.st_mode,copied.st_uid,copied.st_gid,copied.st_mtime_ns) ==
                (info.st_mode,info.st_uid,info.st_gid,info.st_mtime_ns), 'Backup metadata differs')
        if hasattr(os,'listxattr'):
            require({n:os.getxattr(target,n,follow_symlinks=False).hex() for n in os.listxattr(target,follow_symlinks=False)} ==
                    metadata[name]['xattrs'], 'Backup extended attributes differ')
    proof = dict(original_staging_sha256=OLD_STAGE, originals=metadata,
                 new_files_sha256={n:sha(b) for n,b in payload.items()}, new_helper_previously_absent=True,
                 job_started=False, mutation_scope=list(payload), completed=False)
    with (backup/'plan.json').open('xb') as stream:
        stream.write(encoded(proof));stream.flush();os.fsync(stream.fileno())
    original_marker = regular(stage,'preparation.complete')
    replace_owned(original_marker,INVALID,original_marker.stat())
    committed = False
    try:
        for index,name in enumerate((PREPARER,HELPER,'staging.json','control-inputs.json')):
            path = stage/name
            replace_owned(path,payload[name],path.stat() if path.exists() else None)
            if after_replace: after_replace(index,name)
        # Enabling readiness is the last content mutation before contract/host
        # verification; any verification failure invalidates it again.
        replace_owned(stage/'preparation.complete',payload['preparation.complete'],(stage/'preparation.complete').stat())
        verify()
        require(all((stage/name).read_bytes() == data for name,data in payload.items()), 'Committed control bytes changed')
        result = dict(original_staging_sha256=OLD_STAGE,new_staging_sha256=sha(payload['staging.json']),
                      backup=str(backup),changed=list(payload),resource_cache_build_launch_unchanged=True,
                      compiler_launched=False,verified=True)
        with (backup/'result.json').open('xb') as stream:
            stream.write(encoded(result));stream.flush();os.fsync(stream.fileno())
        committed = True
        return result
    finally:
        if not committed:
            replace_owned(stage/'preparation.complete',INVALID,(stage/'preparation.complete').stat())


def apply(stage, helper):
    require(os.name == 'posix' and (os.geteuid(),os.getegid()) == (1000,1000), 'Hardware Linux1000:1000 only')
    require(stage == STAGE and stage.resolve(strict=True) == stage, 'Exact prepared stage required')
    helper_bytes = helper.read_bytes()
    originals,payload = guarded_inputs(stage,helper_bytes)
    sys.path.insert(0,str(stage/'inputs/tools'))
    import tcl_scrollbar_build_contract as contract
    require(sha(Path(contract.__file__).read_bytes()) == json.loads(originals['control-inputs.json'])['tcl_scrollbar_build_contract.py'],
            'Loaded contract differs from original stage')
    def run(argv):
        return subprocess.run(list(map(str,argv)),capture_output=True,text=True,check=True,timeout=30)
    # Load the reviewed helper without copying it into stage before validation.
    require(sha(helper_bytes) == HELPER_SHA and helper.resolve(strict=True) == helper, 'Helper identity/link changed')
    spec = importlib.util.spec_from_file_location('reservation_apply_helper',str(helper))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    check_preparations(ROOT)
    module.verify(ROOT,run)
    before = contract.load_stage(ROOT,stage); contract.verify_inputs(stage,before)
    require(not any((stage/name).exists() for name in JOB_MARKERS), 'Job appeared during validation')
    for name in CHANGED:
        info = regular(stage,name).stat()
        require((info.st_uid,info.st_gid) == (1000,1000), 'Original control owner differs')
    def verify():
        after = contract.load_stage(ROOT,stage); contract.verify_inputs(stage,after)
        check_preparations(ROOT)
        module.verify(ROOT,run)
        require(not any((stage/name).exists() for name in JOB_MARKERS), 'Job appeared during amendment')
    return commit_files(stage,originals,payload,verify)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',required=True,type=Path)
    parser.add_argument('--helper',required=True,type=Path)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    if args.apply:
        result = apply(args.stage,args.helper)
    else:
        original,payload = guarded_inputs(args.stage,args.helper.read_bytes())
        result = dict(offline_plan=True,new_files_sha256={n:sha(b) for n,b in payload.items()},
                      original_staging_sha256=OLD_STAGE,compiler_launched=False,host_modified=False)
    print(json.dumps(result))


if __name__ == '__main__':
    main()

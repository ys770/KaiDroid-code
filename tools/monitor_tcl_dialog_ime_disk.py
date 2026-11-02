"""Guard one identified dialog container and bind Ninja review to the actual plan.

Never deletes files, creates/restarts containers, or stops by name/pattern.
Host monitor mode runs as root after Docker create and before Docker start.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

GIB = 1024**3


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def journal(stage, filename, event):
    row = dict(event, utc=datetime.now(timezone.utc).isoformat())
    with (stage/filename).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, sort_keys=True)+'\n')
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value, exclusive=False):
    if exclusive and path.exists():
        raise FileExistsError(path)
    temp = path.with_name(path.name+'.new.'+str(os.getpid()))
    with temp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(str(temp), str(path))


def load_stage(root, stage):
    root = root.resolve(strict=True);stage = stage.resolve(strict=True)
    if stage.parent != root or not re.fullmatch(r'tcl-dialog-build[0-9]+',stage.name):
        raise ValueError('Not an owned direct-child dialog stage')
    try:control = json.loads((stage/'control-inputs.json').read_text())
    except json.JSONDecodeError as error:raise ValueError('Invalid stage control JSON') from error
    expected = {'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}
    if set(control) != expected:
        raise ValueError('Unexpected stage control set')
    for name, digest in control.items():
        if (stage/name).is_symlink() or sha(stage/name) != digest:
            raise ValueError('Stage control changed: '+name)
    spec = json.loads((stage/'staging.json').read_text())
    builder=spec.get('builder_identity')
    if builder:
        owner=stage.stat()
        if (owner.st_uid,owner.st_gid)!=(builder['uid'],builder['gid']) or owner.st_mode & 0o700 != 0o700:
            raise ValueError('Stage ownership does not match attested builder')
    plan = spec.get('disk_plan')
    if plan and (plan.get('incremental_budget_bytes') != 20*GIB or
                 plan.get('emergency_floor_bytes') != 20*GIB or
                 type(plan.get('free_after_clone_bytes')) is not int or
                 plan['free_after_clone_bytes'] < 40*GIB):
        raise ValueError('Unreviewed disk budget')
    from layered_dialog_output import verify_mounts
    verify_mounts(stage,spec)
    return spec


def assess(plan, free):
    growth = max(0,plan['free_after_clone_bytes']-free)
    reason = ('emergency_floor' if free <= plan['emergency_floor_bytes'] else
              'incremental_budget' if growth >= plan['incremental_budget_bytes'] else None)
    return dict(free_bytes=free,observed_growth_bytes=growth,breach=reason)


def verify_inputs(stage,spec):
    for name,digest in spec.get('inputs',{}).items():
        path=Path(name)
        if path.is_absolute() or '..' in path.parts or (stage/'inputs'/path).is_symlink() or \
                sha(stage/'inputs'/path)!=digest:
            raise ValueError('Bound source input changed: '+name)


def check_phase(root, stage, phase, free=None):
    spec = load_stage(root,stage)
    if phase in ('pre-frontend','pre-ninja','pre-export'):verify_inputs(stage,spec)
    if not spec.get('disk_plan'):
        return dict(phase=phase,status='original_strict_reservation')
    row = dict(assess(spec['disk_plan'],shutil.disk_usage(root).free if free is None else free),phase=phase)
    if phase in ('pre-start','pre-frontend') and row['free_bytes'] < 40*GIB:
        row['breach'] = 'budget_plus_floor_before_frontend'
    if phase != 'pre-start':
        state=json.loads((stage/'disk-monitor-state.json').read_text())
        cid=(stage/'container-id').read_text().strip()
        if state.get('status')!='monitoring' or state.get('container_id')!=cid or \
                time.time()-state.get('heartbeat_epoch',0)>20:
            row['breach']='monitor_heartbeat_missing_or_stale'
    journal(stage,'disk-host-phases.jsonl' if phase=='pre-start' else 'disk-phases.jsonl',row)
    if row['breach']:
        raise ValueError('Disk budget phase check failed: '+str(row))
    return row


def validate_container(info, root, stage, cid):
    if not re.fullmatch('[0-9a-f]{64}',cid) or info.get('Id') != cid:
        raise ValueError('Require exact full owned container ID')
    if info.get('Name') != '/kaidroid-'+stage.name or info.get('Config',{}).get('Image') != 'kaidroid-build:20261023':
        raise ValueError('Container name/image mismatch')
    labels = info.get('Config',{}).get('Labels') or {}
    if labels.get('kaidroid.dialog.stage') != stage.name or labels.get('kaidroid.dialog.staging') != sha(stage/'staging.json'):
        raise ValueError('Container stage labels mismatch')
    if info.get('HostConfig',{}).get('NetworkMode') != 'none':
        raise ValueError('Unexpected container network')
    oom=info.get('HostConfig',{}).get('OomKillDisable')
    if oom is not None and oom is not False:
        raise ValueError('Unexpected OOM killer disable policy')
    spec=json.loads((stage/'staging.json').read_text())
    builder=spec.get('builder_identity')
    if builder and (info.get('Image')!=builder['image_id'] or info['Config'].get('User')!=builder['image_user']):
        raise ValueError('Container image/user differs from attested builder')
    output_source=Path(spec.get('output_source',str(stage/'out')))
    if output_source.name!='out' or output_source.parent.parent!=root or \
            not re.fullmatch(r'tcl-dialog-build[0-9]+',output_source.parent.name):
        raise ValueError('Output source is outside a named owned dialog stage')
    expected = {'/build':(str(root),False),'/baseline':(str(root),False),
        '/build/'+stage.name:(str(stage),True),'/build/out-eng-02':(str(output_source),True),
        '/build/aosp/frameworks/base/core/java/com/android/internal/app':(str(stage/'inputs/app'),False)}
    for filename,directory in [('MenuBar.java','widget'),('TctDialog.java','app'),
                               ('TctDialogMessage.java','widget'),('KeypadImeController.java','widget')]:
        expected['/build/aosp/frameworks/base/core/java/android/'+directory+'/'+filename] = (str(stage/'inputs'/filename),False)
    expected['/build/'+stage.name+'/lower-ro']=(str(stage/'lower-ro'),False)
    expected['/build/'+stage.name+'/out']=(str(stage/'out'),True)
    actual = {}
    for mount in info.get('Mounts',[]):
        if mount.get('Type') != 'bind' or mount.get('Destination') in actual:
            raise ValueError('Unexpected/duplicate container mount')
        actual[mount['Destination']] = (mount.get('Source'),mount.get('RW'))
    if actual != expected:
        raise ValueError('Container mount identities or writable scope mismatch')


def inspect_container(cid):
    result = subprocess.run(['docker','inspect',cid],capture_output=True,text=True,check=True,timeout=15)
    rows = json.loads(result.stdout)
    if len(rows) != 1:raise ValueError('Ambiguous container inspect')
    return rows[0]


def stop_container(cid):
    return subprocess.run(['docker','stop','--time','10',cid],capture_output=True,text=True,check=True,timeout=25)


def identity_signature(info):
    host=dict(info.get('HostConfig') or {})
    # The retained no-build Docker probe changed only this default on start.
    # Keep all other HostConfig data and list ordering significant.
    if 'OomKillDisable' in host and host['OomKillDisable'] is None:
        host['OomKillDisable']=False
    return json.dumps(dict(Id=info.get('Id'),Image=info.get('Image'),Name=info.get('Name'),Config=info.get('Config'),
        HostConfig=host,Mounts=sorted(info.get('Mounts',[]),key=lambda m:m.get('Destination',''))),sort_keys=True)


def monitor_loop(root, stage, cid, ready=None, inspect=inspect_container, stop=stop_container,
                 free=lambda p: shutil.disk_usage(p).free, sleep=time.sleep):
    spec = load_stage(root,stage)
    if not spec.get('disk_plan'):raise ValueError('Monitor requires reviewed budget option')
    info = inspect(cid);validate_container(info,root,stage,cid)
    attested=identity_signature(info)
    if not info['State'].get('Running') and info['State'].get('Status') != 'created':
        raise ValueError('Container already terminal; inspect instead of restarting')
    check_phase(root,stage,'pre-start',free(root))
    pid = os.getpid()
    save(stage/'disk-monitor-ready.json',dict(pid=pid,container_id=cid,staging_sha256=sha(stage/'staging.json')),True)
    (stage/'disk-monitor.pid').write_text(str(pid)+'\n')
    state = dict(status='monitoring',container_id=cid,pid=pid,heartbeat_epoch=time.time())
    save(stage/'disk-monitor-state.json',state)
    journal(stage,'disk-monitor.jsonl',dict(event='ready',**state))
    if ready:ready()
    attempted = False
    validation_error = None
    minimum = free(root)
    while True:
        if not attempted and validation_error is None:
            try:load_stage(root,stage)
            except (ValueError,OSError) as error:
                validation_error=str(error)
                state.update(status='validation_failed',reason='validation_failure',validation_error=validation_error)
                save(stage/'disk-monitor-state.json',state)
                journal(stage,'disk-monitor.jsonl',dict(event='validation_failed',error=validation_error,container_id=cid))
        try:
            info = inspect(cid)
        except (subprocess.SubprocessError,OSError,json.JSONDecodeError) as error:
            journal(stage,'disk-monitor.jsonl',dict(event='inspect_error',error=str(error),container_id=cid))
            sleep(2);continue  # Observation failure is not termination or permission to restart.
        # Once controls fail or stop is requested, do not reload those invalid
        # controls. Continue using the original immutable container attestation.
        if identity_signature(info)!=attested:
            raise ValueError('Attested container identity changed; no stop permitted')
        running = info['State'].get('Running')
        status = info['State'].get('Status')
        if not running and (status != 'created' or attempted or validation_error is not None):
            state.update(status='terminal',docker_state=info['State'],minimum_free_bytes=minimum,stop_attempted=attempted)
            save(stage/'disk-monitor-state.json',state)
            journal(stage,'disk-monitor.jsonl',dict(event='terminal',**state))
            return state
        row = assess(spec['disk_plan'],free(root));minimum=min(minimum,row['free_bytes'])
        state.update(heartbeat_epoch=time.time(),minimum_free_bytes=minimum)
        save(stage/'disk-monitor-state.json',state)
        journal(stage,'disk-monitor.jsonl',dict(event='sample',container_id=cid,**row))
        reason='validation_failure' if validation_error is not None else row['breach']
        if reason and not attempted:
            # Full identity was verified immediately above. Stop exactly once,
            # then keep observing this same ID even if the client times out.
            attempted=True
            state.update(status='stop_requested',reason=reason,minimum_free_bytes=minimum)
            save(stage/'disk-monitor-state.json',state)
            journal(stage,'disk-monitor.jsonl',dict(event='stop_requested',reason=reason,container_id=cid,**row))
            try:stop(cid)
            except (subprocess.SubprocessError,OSError) as error:
                journal(stage,'disk-monitor.jsonl',dict(event='stop_client_error',error=str(error),container_id=cid))
        sleep(2)


def ready_check(root,stage,cid):
    load_stage(root,stage)
    ready=json.loads((stage/'disk-monitor-ready.json').read_text())
    state=json.loads((stage/'disk-monitor-state.json').read_text())
    if ready['container_id']!=cid or state.get('status')!='monitoring' or ready['staging_sha256']!=sha(stage/'staging.json'):
        raise ValueError('Disk monitor not ready for this container/stage')
    os.kill(ready['pid'],0)
    command=(Path('/proc')/str(ready['pid'])/'cmdline').read_bytes().split(b'\0')
    if os.fsencode(str(stage/'disk-monitor.py')) not in command or os.fsencode(str(stage)) not in command:
        raise ValueError('Ready PID no longer identifies this stage monitor')
    info=inspect_container(cid);validate_container(info,root,stage,cid)
    if info['State'].get('Status')!='created':raise ValueError('Require unstarted owned container')
    check_phase(root,stage,'pre-start')


def plan_ready(stage):
    save(stage/'plan-ready.json',dict(plan_sha256=sha(stage/'dependency-plan.log'),
        staging_sha256=sha(stage/'staging.json'),source_graph_sha256=sha(stage/'source-graph.json'),
        state='waiting_for_hardware_review'),True)


def review_plan(stage, digest, note):
    verify_inputs(stage,load_stage(stage.parent,stage))
    expected=json.loads((stage/'plan-ready.json').read_text())
    if digest!=sha(stage/'dependency-plan.log') or expected['plan_sha256']!=digest or \
            expected['staging_sha256']!=sha(stage/'staging.json') or \
            expected['source_graph_sha256']!=sha(stage/'source-graph.json') or len(note.strip())<20:
        raise ValueError('Plan/source identity mismatch or missing substantive review note')
    save(stage/'plan-review.json',dict(expected,review_note=note,reviewed=True),True)


def await_plan(root,stage,sleep=time.sleep):
    load_stage(root,stage)
    plan_ready(stage)
    while not (stage/'plan-review.json').exists():
        check_phase(root,stage,'waiting_for_plan_review');sleep(2)
    review=json.loads((stage/'plan-review.json').read_text())
    if review.get('reviewed') is not True or review.get('plan_sha256')!=sha(stage/'dependency-plan.log') or \
            review.get('staging_sha256')!=sha(stage/'staging.json') or \
            review.get('source_graph_sha256')!=sha(stage/'source-graph.json'):
        raise ValueError('Plan review is stale or does not cover this source graph')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('check','monitor','ready','await-plan','review-plan'))
    p.add_argument('--stage',type=Path,required=True)
    p.add_argument('--root',type=Path)
    p.add_argument('--container-id-file',type=Path)
    p.add_argument('--phase',default='phase')
    p.add_argument('--daemonize',action='store_true')
    p.add_argument('--plan-sha256')
    p.add_argument('--note')
    a=p.parse_args();stage=a.stage.resolve(strict=True);root=(a.root or stage.parent).resolve(strict=True)
    if a.mode=='check':print(json.dumps(check_phase(root,stage,a.phase)));return
    if a.mode=='await-plan':await_plan(root,stage);return
    if a.mode=='review-plan':review_plan(stage,a.plan_sha256 or '',a.note or '');return
    cid=a.container_id_file.read_text().strip()
    if a.mode=='ready':ready_check(root,stage,cid);return
    if os.geteuid()!=0:raise ValueError('Host disk monitor must run as root for Docker access')
    if not a.daemonize:monitor_loop(root,stage,cid);return
    # Parent returns only after the daemon verified identity, disk and readiness.
    read_fd,write_fd=os.pipe();pid=os.fork()
    if pid:
        os.close(write_fd);answer=os.read(read_fd,4096);os.close(read_fd)
        if answer!=b'READY':raise ValueError('Disk monitor failed before readiness: '+answer.decode(errors='replace'))
        print(json.dumps(dict(monitor_pid=pid,container_id=cid)));return
    os.close(read_fd);os.setsid()
    with (stage/'disk-monitor.log').open('x') as log:
        os.dup2(log.fileno(),1);os.dup2(log.fileno(),2)
        try:
            def ready():os.write(write_fd,b'READY');os.close(write_fd)
            monitor_loop(root,stage,cid,ready=ready)
        except BaseException as error:
            save(stage/'disk-monitor-state.json',dict(status='failed',error=str(error),container_id=cid))
            journal(stage,'disk-monitor.jsonl',dict(event='monitor_failed',error=str(error),container_id=cid))
            try:os.write(write_fd,str(error).encode()[:2000]);os.close(write_fd)
            except OSError:pass
            os._exit(1)
    os._exit(0)


if __name__=='__main__':main()

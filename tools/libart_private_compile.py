"""One assigned image55 private ARM32 libart compile; no package/install mode."""
import argparse,hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
import libart_private_dryrun as d
CANDIDATE='f35f5abc6310b349fb57aed5091ea5a677bb07ac523aeb86d17522195de1c09f'
PATCH='960dbe6ba8f448d273aa6ce8872c05017580928e3b29c0b94bd090af8fa836f0'
MANIFEST='66ae4aaa80b16c0ab22fe61120f59e4c66feab11f50515f677b7365822a08bb1'
CONTROL='49bbad922d10782f4191497ba768246059161920e447d22011c910c23b93c208'
STAGE='memory-services-art-build03'
GROWTH=4*1024**3;FLOOR=2*1024**3;DEADLINE=1800

def dump(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def total(root):return sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
def checked(stage):
    if stage.name!=STAGE or stage.parent!=d.ROOT or stage.resolve()!=stage:raise ValueError('Exact fresh03 stage only')
    return d.controls(stage)
def receipts(stage):
    result={}
    for catalog in ('header-receipts.json','remaining-input-receipts03.json'):
        raw=json.loads((stage/'compile-inputs'/catalog).read_text())
        for row in raw['files']:
            p=Path(row['resolved'])
            if not p.is_relative_to(d.ROOT) or p.resolve()!=p or d.sha(p)!=row['sha256']:raise ValueError('Input drift '+str(p))
            result[str(p)]=row['sha256']
    for row in json.loads((stage/'inputs/toolchain.json').read_text())['files']:
        p=Path(row['path'])
        if not p.is_relative_to(d.ROOT) or str(p.resolve())!=row['resolved'] or d.sha(p)!=row['sha256']:raise ValueError('Tool drift '+str(p))
        result[str(p)]=row['sha256']
    if d.sha(d.ROOT/d.SRC)!=d.SOURCE or d.sha(d.ROOT/'out-eng-02/soong/build.ninja')!=d.GRAPH:raise ValueError('Source/graph drift')
    return result

def freeze(stage):
    checked(stage);d.idle()
    r=json.loads((stage/'dryrun.result.json').read_text())
    if not r['complete'] or not r['plan_matches_reviewed_three_commands'] or r['plan_action_count']!=3 or (stage/'dryrun.exit').read_text().strip()!='0':raise ValueError('Fresh dryrun incomplete')
    pins={'candidate.cc':CANDIDATE,'candidate.patch':PATCH,'candidate.json':MANIFEST}
    for n,pin in pins.items():
        if d.sha(stage/'inputs'/n)!=pin:raise ValueError('Not exact55 '+n)
    if d.sha(stage/'compile-inputs/controls.json')!=CONTROL:raise ValueError('Wrong host-body controls')
    if d.inventory(d.ROOT/d.REL)[0]!=json.loads((stage/'inputs/cache-before.json').read_text()):raise ValueError('Shared cache drift')
    cpus=sorted(os.sched_getaffinity(0))[:2]
    if len(cpus)!=2 or shutil.disk_usage(stage).free<FLOOR+GROWTH:raise ValueError('Insufficient bounded resources')
    read=receipts(stage);before,size=d.inventory(stage/'libart-copy')
    dump(stage/'compile-before.json',before)
    inputs={p.name:d.sha(p) for p in (stage/'compile-inputs').iterdir() if p.is_file()}
    record=dict(stage=STAGE,assignment='hardware lane bounded exclusive host compile assignment',candidate=CANDIDATE,patch=PATCH,candidate_manifest=MANIFEST,raw='c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88',host_controls=CONTROL,
        dryrun_result_sha256=d.sha(stage/'dryrun.result.json'),dryrun_manifest_sha256=d.sha(stage/'inputs/manifest.json'),compile_inputs_sha256=inputs,read_inputs=read,private_bytes=size,
        builder=d.IMAGE,cpus=cpus,memory=8589934592,memory_swap=8589934592,pids=512,deadline_seconds=DEADLINE,growth_bytes=GROWTH,free_floor_bytes=FLOOR,package_authorized=False,install_authorized=False)
    dump(stage/'compile-record.json',record)
    (stage/'compile-record.sha256').write_text(d.sha(stage/'compile-record.json')+'\n')
    print(json.dumps(dict(frozen=True,record_sha256=d.sha(stage/'compile-record.json'),cpus=cpus)),flush=True)
def record(stage):
    r=json.loads((stage/'compile-record.json').read_text())
    if (stage/'compile-record.sha256').read_text().strip()!=d.sha(stage/'compile-record.json'):raise ValueError('Compile record changed')
    for n,pin in r['compile_inputs_sha256'].items():
        if Path(n).name!=n or d.sha(stage/'compile-inputs'/n)!=pin:raise ValueError('Frozen compile input changed')
    return r

def launch(stage):
    checked(stage);r=record(stage);d.idle()
    if (stage/'compile.launch.started.json').exists():raise ValueError('Already launched; monitor same handle')
    if receipts(stage)!=r['read_inputs'] or d.inventory(stage/'libart-copy')[0]!=json.loads((stage/'compile-before.json').read_text()):raise ValueError('Prelaunch input/cache drift')
    for n in ('inputs','compile-inputs','ninja','tmp','libart-copy'):
        if (stage/n).is_symlink() or (stage/n).resolve()!=stage/n:raise ValueError('Symlink boundary')
    cp='/build/'+STAGE
    mounts=[(d.ROOT,'/build','ro'),(d.ROOT,'/baseline','ro'),(stage,cp,'rw'),(stage/'inputs',cp+'/inputs','ro'),(stage/'compile-inputs',cp+'/compile-inputs','ro'),(stage/'libart-copy','/build/'+str(d.REL),'rw'),(stage/'inputs/candidate.cc','/build/'+str(d.SRC),'ro'),(stage/'tmp','/tmp','rw')]
    argv=['sudo','-n','docker','run','-d','--pull','never','--name','kaidroid-'+STAGE+'-compile','--read-only','--network','none','--user','1000:1000','--cpuset-cpus',','.join(map(str,r['cpus'])),'--cpus','2','--memory','8g','--memory-swap','8g','--pids-limit','512']
    for src,target,mode in mounts:argv+=['-v',str(src)+':'+target+':'+mode]
    argv+=['-e','TMPDIR='+cp+'/tmp','-e','PYTHONDONTWRITEBYTECODE=1',d.IMAGE,'timeout','--signal=TERM','--kill-after=10s','1800','python3',cp+'/compile-inputs/libart_private_compile.py','inside','--stage',cp]
    dump(stage/'compile.launch.started.json',dict(argv=argv,record_sha256=d.sha(stage/'compile-record.json'),mounts=[list(map(str,x)) for x in mounts],initial_stage_bytes=total(stage),time_unix=time.time()))
    proc=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    (stage/'compile.launch.stdout').write_text(proc.stdout);(stage/'compile.launch.stderr').write_text(proc.stderr);proc.check_returncode()
    cid=proc.stdout.strip()
    if len(cid)!=64 or any(c not in '0123456789abcdef' for c in cid):raise ValueError('Ambiguous launch; inspect exact name; no retry')
    (stage/'compile.container-id').write_text(cid+'\n')
    with (stage/'compile.watchdog.log').open('xb') as log:
        watcher=subprocess.Popen(['sudo','-n',sys.executable,str(Path(__file__).resolve()),'watch','--stage',str(stage)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
    (stage/'compile.watchdog.pid').write_text(str(watcher.pid)+'\n')
    for attempt in range(50):
        if (stage/'compile.watchdog.ready.json').exists():break
        if watcher.poll() is not None:raise ValueError('Watchdog failed; container cannot pass compile barrier')
        time.sleep(.1)
    else:
        subprocess.run(['sudo','-n','docker','kill',cid],check=True,capture_output=True,timeout=15)
        raise ValueError('Watchdog readiness timeout; no retry')
    print(json.dumps(dict(container=cid,watchdog_pid=watcher.pid)),flush=True)

def watch(stage):
    if os.geteuid()!=0:raise ValueError('Watchdog requires already authorized root child')
    try:os.setsid()
    except PermissionError:pass
    (stage/'compile.watchdog.actual-pid').write_text(str(os.getpid())+'\n')
    r=record(stage);cid=(stage/'compile.container-id').read_text().strip();launch=json.loads((stage/'compile.launch.started.json').read_text());reason=None;samples=[]
    docker=['docker']
    dump(stage/'compile.watchdog.ready.json',dict(pid=os.getpid(),uid=os.geteuid(),record_sha256=d.sha(stage/'compile-record.json')))
    while True:
        state=json.loads(subprocess.check_output(docker+['inspect',cid],timeout=15))[0]
        elapsed=time.time()-launch['time_unix'];growth=total(stage)-launch['initial_stage_bytes'];free=shutil.disk_usage(stage).free
        samples.append(dict(elapsed=elapsed,growth=growth,free=free,running=state['State']['Running']))
        if not state['State']['Running']:break
        if elapsed>DEADLINE or growth>GROWTH or free<FLOOR:
            reason='deadline' if elapsed>DEADLINE else ('stage_growth' if growth>GROWTH else 'free_floor')
            subprocess.run(docker+['kill',cid],check=True,capture_output=True,timeout=15)
        time.sleep(2)
    dump(stage/'compile.container.inspect.json',state);dump(stage/'compile.watchdog.result.json',dict(terminal=True,stop_reason=reason,samples=samples))
    logs=subprocess.run(docker+['logs',cid],capture_output=True,timeout=30)
    (stage/'compile.docker.stdout').write_bytes(logs.stdout);(stage/'compile.docker.stderr').write_bytes(logs.stderr)
    current=d.inventory(d.ROOT/d.REL)[0];dump(stage/'compile.shared-after.json',current)
    shared_ok=current==json.loads((stage/'inputs/cache-before.json').read_text())
    post=receipts(stage);dump(stage/'compile.read-inputs-after.json',post)
    copied,_=d.inventory(stage/'libart-copy');dump(stage/'compile.private-after.json',copied)
    before=json.loads((stage/'compile-before.json').read_text());changed={n:dict(before=before.get(n),after=copied.get(n)) for n in before.keys()|copied.keys() if before.get(n)!=copied.get(n)}
    dump(stage/'compile.changed.json',changed)
    outputs={}
    for name,target in [('manager',d.STATIC),('unstripped',d.LINK),('stripped',d.TARGET)]:
        p=stage/'libart-copy'/target[len('/build/'+str(d.REL)) + 1:]
        outputs[name]=dict(path=str(p),sha256=d.sha(p),size=p.stat().st_size)
    dump(stage/'compile.host.result.json',dict(terminal=True,container=cid,exit_code=state['State']['ExitCode'],oom_killed=state['State']['OOMKilled'],stop_reason=reason,shared_unchanged=shared_ok,read_inputs_unchanged=post==r['read_inputs'],outputs=outputs,changed_paths=list(changed),installed=False,ready_for_image=False))
    if not shared_ok or post!=r['read_inputs']:raise ValueError('Shared/read input drift')
    print(json.dumps(dict(terminal=True,exit_code=state['State']['ExitCode'],oom=state['State']['OOMKilled'],stop_reason=reason)),flush=True)

def inside(stage):
    if stage!=Path('/build')/STAGE or os.getuid()!=1000:raise ValueError('Wrong stage/user')
    r=record(stage);d.controls(stage)
    for attempt in range(100):
        if (stage/'compile.watchdog.ready.json').exists():break
        time.sleep(.1)
    else:raise ValueError('No live watchdog readiness; compiler blocked')
    ready=json.loads((stage/'compile.watchdog.ready.json').read_text())
    if ready['uid']!=0 or ready['record_sha256']!=d.sha(stage/'compile-record.json'):raise ValueError('Watchdog barrier differs')
    if (stage/'compile.started.json').exists():raise ValueError('Never replay compile')
    for path,mode in [('/','ro'),('/build','ro'),('/baseline','ro'),(str(stage),'rw'),(str(stage/'inputs'),'ro'),(str(stage/'compile-inputs'),'ro'),('/build/'+str(d.REL),'rw'),('/build/'+str(d.SRC),'ro'),('/tmp','rw')]:
        if d.mount_mode(path)!=mode:raise ValueError('Mount boundary '+path)
    if sorted(os.sched_getaffinity(0))!=r['cpus']:raise ValueError('CPU affinity differs')
    for name,expected in [('memory.max','8589934592'),('memory.swap.max','0'),('pids.max','512')]:
        if (Path('/sys/fs/cgroup')/name).read_text().strip()!=expected:raise ValueError('Resource cap differs '+name)
    if d.sha(Path('/baseline')/d.SRC)!=d.SOURCE or d.sha(Path('/build')/d.SRC)!=CANDIDATE or d.sha(Path('/build/out-eng-02/soong/build.ninja'))!=d.GRAPH:raise ValueError('Source/graph drift')
    for row in json.loads((stage/'compile-inputs/runtime-container02.json').read_text())['files']:
        p=Path(row['path'])
        if str(p.resolve())!=row['resolved'] or d.sha(p)!=row['sha256']:raise ValueError('Builder runtime drift '+str(p))
    ninja=Path('/build/aosp/prebuilts/build-tools/linux-x86/bin/ninja')
    if d.sha(ninja)!=d.NINJA:raise ValueError('Ninja drift')
    commands=subprocess.check_output([str(ninja),'-f',str(stage/'inputs/query.ninja'),'-t','commands','-s',d.STATIC,d.LINK,d.TARGET],cwd='/build/aosp',timeout=60)
    if hashlib.sha256(commands).hexdigest()!=d.RECEIPTS['commands.stdout']:raise ValueError('Three command drift')
    argv=[str(ninja),'-f',str(stage/'inputs/query.ninja'),'-j1','-v',d.TARGET]
    dump(stage/'compile.started.json',dict(argv=argv,record_sha256=d.sha(stage/'compile-record.json'),time_unix=time.time(),runtime_rehashed=True,mounts_checked=True,resource_caps_checked=True))
    with (stage/'compile.stdout').open('xb') as out,(stage/'compile.stderr').open('xb') as err:
        result=subprocess.run(argv,cwd='/build/aosp',stdout=out,stderr=err)
    (stage/'compile.exit').write_text(str(result.returncode)+'\n')
    print(json.dumps(dict(compile_exit=result.returncode)),flush=True)
    raise SystemExit(result.returncode)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('freeze','launch','watch','inside'));p.add_argument('--stage',type=Path,required=True);a=p.parse_args()
    globals()[a.mode](a.stage)

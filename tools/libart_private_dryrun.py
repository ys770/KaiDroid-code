"""Stage/launch a bounded private Ninja inspection ONLY. This tool has no compilation mode."""
import argparse,hashlib,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
REL=Path('out-eng-02/soong/.intermediates/art/runtime/libart')
SRC=Path('aosp/art/runtime/oat_file_manager.cc')
STATIC='/build/'+str(REL)+'/android_arm_armv7-a-neon_static_com.android.art.release/obj/art/runtime/oat_file_manager.o'
LINK='/build/'+str(REL)+'/android_arm_armv7-a-neon_shared_com.android.art.release/unstripped/libart.so'
TARGET='/build/'+str(REL)+'/android_arm_armv7-a-neon_shared_com.android.art.release/libart.so'
SOURCE='9b2d2869e0138fc00810a276a63c653c423d3173f5d3a8ac521dd62ceb15e521'
BASE='cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62'
GRAPH='931aa0c06b4ccb817efaef6098c52574215608b0952c8eb168c3246b1abb6e4d'
IMAGE='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
NINJA='438850edf03d48cd75509a595ee1b283802facefaf09200d3761ee9169136a47'
RECEIPTS={'query.stdout':'c33a7cfb4ed60a134c620a03f859a4271bd90dc0f66e34ecb35386202f5a5d3f','commands.stdout':'73a492f7b5cfe7b3b57048e09cbeff2fe607f1d5fd89206cbe960e4cead5ac2a','strip.sh':'4ee69021598b68bb07ae4a14c07e1f369fec747d1af686c5557db4b48a2f5ff9','libart.so.rsp':'644f74f0ddf43142a52b440e4c2a282048248b5d8ddf96c7b573aca1000d18bf','rules.json':'fc3fb18c03133a34fa66bec595a39308a2463d2fe3e3f2d79452c8b4599e081b','toolchain.json':'db6ae131551701400ae59e98bb1c3ea42e3d3a2b85d9ab998f4dff28a0f0335b'}
MAX_BYTES=2*1024**3;MAX_FILES=10000

def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def name_ok(name):
    if not re.fullmatch('memory-services-art-build[0-9]{2}',name):raise ValueError('Use a fresh reviewed direct-child stage name')
    return name
def idle():
    for name in ('ninja','soong_build','e2fsdroid'):
        r=subprocess.run(['pgrep','-x',name],capture_output=True,timeout=5)
        if r.returncode not in (0,1) or r.returncode==0:raise ValueError('Host build/pack job active or process check failed: '+name)
def inventory(root):
    rows={};total=0
    for path in sorted(root.rglob('*')):
        st=path.lstat()
        if stat.S_ISLNK(st.st_mode):raise ValueError('Cache symlink needs explicit review: '+str(path))
        if path.is_dir():continue
        if not stat.S_ISREG(st.st_mode):raise ValueError('Nonregular cache entry')
        total+=st.st_size
        if len(rows)>=MAX_FILES or total>MAX_BYTES:raise ValueError('Copy/hash inventory exceeds2GiB/10000file bound')
        rows[path.relative_to(root).as_posix()]=dict(sha256=sha(path),size=st.st_size,mode=stat.S_IMODE(st.st_mode),mtime_ns=st.st_mtime_ns,uid=st.st_uid,gid=st.st_gid)
    if not rows:raise ValueError('Empty cache inventory')
    return rows,total
def controls(stage):
    m=json.loads((stage/'inputs/manifest.json').read_text())
    if (stage/'preparation.complete').read_text().strip()!=sha(stage/'inputs/manifest.json'):raise ValueError('Incomplete/tampered stage')
    for rel,pin in m['input_sha256'].items():
        if Path(rel).name!=rel or sha(stage/'inputs'/rel)!=pin:raise ValueError('Control input differs: '+rel)
    if m['dryrun_only'] is not True or m['compile_authorized'] is not False:raise ValueError('Not a dryrun-only stage')
    return m

def stage_job(a):
    if os.name!='posix' or a.root.resolve()!=ROOT or os.getuid()!=1000:raise ValueError('Preparation requires assigned Linux host, exact root and UID1000')
    idle();dest=ROOT/name_ok(a.name)
    if dest.exists():raise ValueError('Never reuse a partial/existing stage')
    candidate=json.loads((a.candidate_dir/'candidate.json').read_text())
    if candidate['original_sha256']!=SOURCE or sha(a.candidate_dir/'original.cc')!=SOURCE or sha(a.candidate_dir/'candidate.cc')!=candidate['candidate_sha256'] or sha(a.candidate_dir/'candidate.patch')!=candidate['patch_sha256']:raise ValueError('Candidate source/patch binding differs')
    if candidate.get('baseline_libart_sha256',candidate.get('expected_baseline_libart_sha256'))!=BASE:raise ValueError('Candidate baseline library differs')
    if sha(ROOT/SRC)!=SOURCE or sha(ROOT/'out-eng-02/soong/build.ninja')!=GRAPH or sha(ROOT/Path(TARGET[len('/build/'):]))!=BASE:raise ValueError('Shared source/graph/libart differs')
    for rel,pin in RECEIPTS.items():
        if sha(a.receipts/rel)!=pin:raise ValueError('Reviewed receipt differs: '+rel)
    for row in json.loads((a.receipts/'toolchain.json').read_text())['files']:
        p=Path(row['path'])
        if not p.is_relative_to(ROOT) or str(p.resolve())!=row['resolved'] or sha(p)!=row['sha256']:raise ValueError('Actual direct tool differs: '+str(p))
    before,size=inventory(ROOT/REL)
    logs=[ROOT/'out-eng-02'/n for n in ('.ninja_log','.ninja_deps')]
    if not all(p.is_file() for p in logs):raise ValueError('Original Ninja bookkeeping missing; inspect before copying')
    log_bytes=sum(p.stat().st_size for p in logs)
    if log_bytes>512*1024**2 or shutil.disk_usage(ROOT).free<size+log_bytes+2*1024**3:raise ValueError('Bookkeeping exceeds512MiB or insufficient copy/evidence headroom')
    dest.mkdir();(dest/'inputs').mkdir();(dest/'ninja').mkdir();(dest/'tmp').mkdir()
    dump(dest/'preparation.started.json',dict(dryrun_only=True,source=SOURCE,graph=GRAPH,copy_bytes=size))
    with (dest/'copy.stdout').open('wb') as out,(dest/'copy.stderr').open('wb') as err:
        subprocess.run(['cp','--reflink=auto','-a',str(ROOT/REL),str(dest/'libart-copy')],check=True,timeout=180,stdout=out,stderr=err)
    copied,_=inventory(dest/'libart-copy')
    if copied!=before or inventory(ROOT/REL)[0]!=before:raise ValueError('Copy differs or shared cache changed')
    idle()
    if sha(ROOT/SRC)!=SOURCE or sha(ROOT/'out-eng-02/soong/build.ninja')!=GRAPH:raise ValueError('Source/graph drifted during copy')
    for p in logs:shutil.copy2(p,dest/'ninja'/p.name)
    for rel in RECEIPTS:shutil.copy2(a.receipts/rel,dest/'inputs'/rel)
    for rel in ('original.cc','candidate.cc','candidate.patch','candidate.json'):shutil.copy2(a.candidate_dir/rel,dest/'inputs'/rel)
    # A fresh candidate mtime makes the private changed source dirty; no object is deleted.
    os.utime(dest/'inputs/candidate.cc',None)
    shutil.copy2(Path(__file__),dest/'inputs/runner.py')
    query='pool highmem_pool\n  depth = 1\nsubninja /build/out-eng-02/soong/build.ninja\nbuilddir = /build/'+dest.name+'/ninja\n'
    (dest/'inputs/query.ninja').write_text(query)
    dump(dest/'inputs/cache-before.json',before)
    pins={p.name:sha(p) for p in (dest/'inputs').iterdir() if p.is_file()}
    m=dict(stage=dest.name,dryrun_only=True,compile_authorized=False,candidate_sha256=candidate['candidate_sha256'],candidate_manifest_sha256=sha(a.candidate_dir/'candidate.json'),source_sha256=SOURCE,graph_sha256=GRAPH,baseline_libart_sha256=BASE,builder=IMAGE,cache_bytes=size,cache_files=len(before),input_sha256=pins,host_headers_and_real_compiler_closure_pending=True)
    dump(dest/'inputs/manifest.json',m);(dest/'preparation.complete').write_text(sha(dest/'inputs/manifest.json')+'\n');print(json.dumps(m))

def launch(a):
    stage=a.stage.resolve()
    if stage.parent!=ROOT:name_ok('invalid')
    name_ok(stage.name);m=controls(stage);idle()
    for name in ('inputs','ninja','tmp','libart-copy'):
        p=stage/name
        if p.is_symlink() or p.resolve()!=p:raise ValueError('Private directory resolves outside stage: '+name)
    for p in (stage/'ninja').iterdir():
        if p.is_symlink():raise ValueError('Bookkeeping symlink needs review')
    if inventory(stage/'libart-copy')[0]!=json.loads((stage/'inputs/cache-before.json').read_text()):raise ValueError('Private cache changed after preparation')
    if sha(ROOT/SRC)!=SOURCE or sha(ROOT/'out-eng-02/soong/build.ninja')!=GRAPH or sha(ROOT/Path(TARGET[len('/build/'):]))!=BASE:raise ValueError('Host baseline drift before launch')
    for name in ('launch.started.json','container-id','dryrun.log','dryrun.exit'):
        if (stage/name).exists():raise ValueError('Launch already started; follow existing container, never retry')
    r=subprocess.run(['sudo','-n','docker','image','inspect','kaidroid-build:20261023','--format','{{.Id}}'],check=True,capture_output=True,text=True,timeout=15)
    if r.stdout.strip()!=IMAGE:raise ValueError('Builder image differs')
    with (stage/'launch.started.json').open('x') as f:json.dump(dict(dryrun_only=True,compile_authorized=False,stage=stage.name),f)
    cp='/build/'+stage.name;mounts=[(ROOT,'/build','ro'),(ROOT,'/baseline','ro'),(stage,cp,'rw'),(stage/'inputs',cp+'/inputs','ro'),(stage/'libart-copy','/build/'+str(REL),'rw'),(stage/'inputs/candidate.cc','/build/'+str(SRC),'ro'),(stage/'tmp','/tmp','rw')]
    cmd=['sudo','-n','docker','run','-d','--pull','never','--name','kaidroid-'+stage.name+'-dryrun','--read-only','--network','none','--user','1000:1000']
    for src,target,mode in mounts:cmd+=['-v',str(src)+':'+target+':'+mode]
    cmd+=['-e','TMPDIR='+cp+'/tmp','-e','PYTHONDONTWRITEBYTECODE=1',IMAGE,'python3',cp+'/inputs/runner.py','inside','--stage',cp]
    dump(stage/'launch.argv.json',cmd)
    try:r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
    except subprocess.TimeoutExpired as error:
        (stage/'launch.partial.stdout').write_bytes(error.stdout or b'');(stage/'launch.partial.stderr').write_bytes(error.stderr or b'');raise
    (stage/'launch.stdout').write_text(r.stdout);(stage/'launch.stderr').write_text(r.stderr);r.check_returncode()
    if not re.fullmatch('[a-f0-9]{64}\n?',r.stdout):raise ValueError('Ambiguous Docker response; inspect recorded container name, do not retry')
    (stage/'container-id').write_text(r.stdout);print(r.stdout,end='')

def mount_mode(path):
    rows=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    found=[r[5].split(',') for r in rows if r[4]==str(path)]
    if len(found)!=1:raise ValueError('Missing/ambiguous mount '+str(path))
    return 'ro' if 'ro' in found[0] else 'rw'

def inside(a):
    stage=a.stage;name_ok(stage.name)
    if stage.parent!=Path('/build') or os.getuid()!=1000:raise ValueError('Wrong container stage/user')
    if (stage/'dryrun.result.json').exists() or (stage/'query-manager.started.json').exists():raise ValueError('Inspection already started; follow existing result, never replay')
    return _inside_job(stage)

def _inside_job(stage):
    started=time.monotonic();report=dict(complete=False,dryrun_only=True,compiler_executed=False,ready_for_compile=False,commands=[],python_version=sys.version.split()[0],phase='control-validation');code=1
    try:
        m=controls(stage);before=json.loads((stage/'inputs/cache-before.json').read_text());report['phase']='mount-validation'
        for path,mode in [('/', 'ro'),('/build','ro'),('/baseline','ro'),(str(stage),'rw'),(str(stage/'inputs'),'ro'),('/build/'+str(REL),'rw'),('/build/'+str(SRC),'ro'),('/tmp','rw')]:
            if mount_mode(path)!=mode:raise ValueError('Unexpected writable/read-only boundary '+path)
        if sha(Path('/baseline')/SRC)!=SOURCE or sha(Path('/build')/SRC)!=m['candidate_sha256'] or sha(Path('/build/out-eng-02/soong/build.ninja'))!=GRAPH:raise ValueError('Container source/graph differs')
        ninja=Path('/build/aosp/prebuilts/build-tools/linux-x86/bin/ninja')
        if sha(ninja)!=NINJA:raise ValueError('Ninja binary differs')
        report['phase']='readonly-ninja-inspection'
        def run(label,tail):
            if not ('-t' in tail or '-n' in tail):raise ValueError('No compiler/build mode exists in this runner')
            argv=[str(ninja),'-f',str(stage/'inputs/query.ninja'),*tail];out=stage/(label+'.stdout');err=stage/(label+'.stderr');start=time.monotonic()
            dump(stage/(label+'.started.json'),dict(argv=argv,dryrun_only=True,compiler_executed=False))
            with out.open('wb') as o,err.open('wb') as e:
                proc=subprocess.Popen(argv,cwd='/build/aosp',stdout=o,stderr=e)
                try:
                    while proc.poll() is None:
                        if time.monotonic()-start>60 or out.stat().st_size+err.stat().st_size>32*1024**2:raise TimeoutError('Bounded Ninja inspection exceeded60s/32MiB')
                        time.sleep(.1)
                except BaseException:
                    proc.terminate()
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
                    raise
            report['commands'].append(dict(name=label,argv=argv,exit=proc.returncode,seconds=time.monotonic()-start,stdout_sha256=sha(out),stderr_sha256=sha(err)))
            if proc.returncode:raise ValueError('Ninja inspection failed '+label)
        for label,target in [('query-manager',STATIC),('query-link',LINK),('query-strip',TARGET)]:run(label,['-t','query',target])
        run('commands',['-t','commands','-s',STATIC,LINK,TARGET])
        if sha(stage/'commands.stdout')!=RECEIPTS['commands.stdout']:raise ValueError('Actual command bytes drifted; review before dry-run')
        run('baseline-header-deps',['-t','deps',STATIC])
        run('dry-run',['-n','-d','explain','-v','-j1',TARGET])
        shared,_=inventory(Path('/baseline')/REL);copied,_=inventory(stage/'libart-copy')
        if shared!=before or sha(Path('/baseline')/SRC)!=SOURCE or sha(Path('/baseline/out-eng-02/soong/build.ninja'))!=GRAPH:raise ValueError('Shared libart cache/source/graph changed during inspection')
        changed=[n for n in before.keys()|copied.keys() if before.get(n)!=copied.get(n)]
        metadata={p[len('/build/'+str(REL)) + 1:] for p in (STATIC+'.d',LINK+'.rsp',TARGET+'.d')}
        if any(n not in metadata for n in changed):raise ValueError('Dryrun changed private object/library or unexpected file; inspect existing stage')
        lines=(stage/'dry-run.stdout').read_text().splitlines();actions=[re.sub(r'^\[[0-9]+/[0-9]+\] ','',line) for line in lines if re.match(r'^\[[0-9]+/[0-9]+\] ',line)]
        reviewed=(stage/'inputs/commands.stdout').read_text().splitlines()
        report.update(complete=True,phase='complete',shared_cache_unchanged=True,private_object_libraries_unchanged=True,private_ninja_metadata_changes=changed,plan_action_count=len(actions),plan_matches_reviewed_three_commands=actions==reviewed,baseline_header_deps_available='#deps' in (stage/'baseline-header-deps.stdout').read_text(),manual_writeclosure_review_pending=True);code=0
    except BaseException as e:report['error']=repr(e);raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started
        dump(stage/'dryrun.result.json',report);(stage/'dryrun.exit').write_text(str(code)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
    s=sub.add_parser('stage');s.add_argument('--root',type=Path,required=True);s.add_argument('--name',required=True);s.add_argument('--candidate-dir',type=Path,required=True);s.add_argument('--receipts',type=Path,required=True)
    for n in ('launch','inside'):sub.add_parser(n).add_argument('--stage',type=Path,required=True)
    a=p.parse_args();{'stage':stage_job,'launch':launch,'inside':inside}[a.mode](a)

"""Fixed fresh56 stage/pack launcher; device operations and deletion are absent."""
import argparse,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
import image56_contract as c

def inventory(root):
 rows={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for n in dirs+files:
   p=Path(folder)/n;st=p.lstat();rel=p.relative_to(root).as_posix()
   rows[rel]=(['link',os.readlink(p)] if p.is_symlink() else ['dir',stat.S_IMODE(st.st_mode)] if p.is_dir() else ['file',stat.S_IMODE(st.st_mode),c.sha(p)])
 return rows
def host_attrs(root):
 rows={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=Path(folder)/name;st=p.lstat();rows[p.relative_to(root).as_posix()]=dict(uid=st.st_uid,gid=st.st_gid,xattrs={n:os.getxattr(p,n,follow_symlinks=False).hex() for n in os.listxattr(p,follow_symlinks=False)})
 return rows
def safe_stage(stage,inside=False):
 root=Path('/build') if inside else c.ROOT
 if stage!=root/c.NAME or stage.resolve()!=stage or stage.is_symlink():raise ValueError('Exact direct fresh56 stage required')
 return root
def idle():
 for name in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',name],capture_output=True,timeout=5).returncode!=1:raise ValueError('Host job active/unknown '+name)
 if subprocess.check_output(['sudo','-n','docker','ps','-q'],text=True,timeout=15).strip():raise ValueError('Container active; no interruption')
def packet_check(packet,pin):
 if packet.is_symlink() or packet.resolve()!=packet or c.sha(packet/'packet.json')!=pin:raise ValueError('Packet identity differs')
 m=json.loads((packet/'packet.json').read_text());expected={'tools/'+n for n in c.TOOLS}|{'proposal.json','baseline-raw-inventory.json','baseline-xattrs.json','payload/'+c.LIB,'payload/build.prop','config/file_contexts.txt','config/system_image_info.compact55.txt','config/system_image_info.compact56.txt'}
 if m.get('image')!=56 or m.get('proposal_sha256')!=c.PROPOSAL or set(m.get('files',{}))!=expected:raise ValueError('Packet file set differs')
 actual={p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_file()}
 if any(p.is_symlink() for p in packet.rglob('*')) or actual!=expected|{'packet.json'}:raise ValueError('Packet paths/link/extra files differ')
 for name,value in m['files'].items():
  if Path(name).is_absolute() or '..' in Path(name).parts or c.sha(packet/name)!=value:raise ValueError('Packet content changed '+name)
 r=c.proposal(packet/'proposal.json')
 if c.sha(packet/'config/file_contexts.txt')!=r['pack']['baseline_file_contexts_sha256'] or c.sha(packet/'config/system_image_info.compact55.txt')!=r['pack']['baseline_pack_config_sha256']:raise ValueError('Frozen config/labels differ')
 if (packet/'config/system_image_info.compact56.txt').read_bytes()!=c.config56((packet/'config/system_image_info.compact55.txt').read_bytes().decode()).encode():raise ValueError('Frozen56 config transform differs')
 for name,key in [('baseline-raw-inventory.json','baseline_inventory_sha256'),('baseline-xattrs.json','baseline_xattrs_sha256')]:
  if c.sha(packet/name)!=r[key]:raise ValueError('Raw55 receipt differs')
 for n in c.CHANGES:
  if c.sha(packet/'payload'/n)!=r['changed'][n]['after']['sha256']:raise ValueError('Payload differs '+n)
 return r

def baseline(root):
 b=root/c.BASE_NAME
 if b.is_symlink() or b.resolve()!=b:raise ValueError('Baseline path differs')
 for name,pin in [('staging.json',c.BASE_MANIFEST),('outputs.json',c.BASE_OUTPUTS),('compact-image/system.raw.img',c.BASE)]:
  if c.sha(b/name)!=pin:raise ValueError('Immutable55 differs '+name)
 if (b/'compact-image/system.raw.img').stat().st_size!=c.PARTITION or (b/'build.exit').read_text().strip()!='0':raise ValueError('Baseline55 not terminal valid size')
 m=json.loads((b/'staging.json').read_text());out=json.loads((b/'outputs.json').read_text())
 if m['image']!=55 or out['raw_sha256']!=c.BASE or not out['avb_verified'] or not out['signed_hashtree_verified'] or out['optional_fec'] is not False:raise ValueError('Baseline55 AVB disposition differs')
 for n,pin in m['metadata_files_sha256'].items():
  if Path(n).name!=n or (b/n).is_symlink() or c.sha(b/n)!=pin:raise ValueError('Baseline control differs '+n)
 system=inventory(b/'compact-system');roots=inventory(b/'compact-root')
 if system!=json.loads((b/'system-inventory.json').read_text()) or roots!=json.loads((b/'root-inventory.json').read_text()):raise ValueError('Source55 tree differs')
 return b,m,system,roots

def compare_trees(before,after,r):
 if before.keys()!=after.keys():raise ValueError('Staged path set changed')
 changed={n for n in before if before[n]!=after[n]}
 if changed!=c.CHANGES:raise ValueError('Not exact two-file stage delta')
 for n in changed:
  if before[n][:2]!=after[n][:2] or before[n][0]!='file' or before[n][2]!=r['changed'][n]['before']['sha256'] or after[n][2]!=r['changed'][n]['after']['sha256']:raise ValueError('Type/mode/content change differs '+n)
 return changed

def source_raw_content(system,roots,raw):
 for prefix,rows in [('/system/',system),('/',roots)]:
  for n,row in rows.items():
   name=prefix+n
   if name not in raw:raise ValueError('Source path absent from raw55 '+name)
   value=raw[name]
   if row[0]=='file' and value.get('sha256')!=row[2]:raise ValueError('Source bytes differ from raw55 '+name)
   if row[0]=='link' and value.get('target')!=row[1]:raise ValueError('Source symlink differs from raw55 '+name)

def stage(a):
 if os.name!='posix' or os.getuid()!=1000 or os.getgid()!=1000 or a.root!=c.ROOT:raise ValueError('Assigned Linux builder1000/exact root required')
 out=c.ROOT/c.NAME
 if out.exists():raise FileExistsError('Preserve existing stage; never reuse/delete')
 r=packet_check(a.packet,a.packet_sha256);idle();b,bm,before,roots=baseline(c.ROOT)
 source_raw_content(before,roots,json.loads((a.packet/'baseline-raw-inventory.json').read_text()))
 copies=sum(p.stat().st_size for tree in ('compact-system','compact-root') for p in (b/tree).rglob('*') if p.is_file() and not p.is_symlink())
 if shutil.disk_usage(c.ROOT).free<copies+2*c.PARTITION+c.FLOOR:raise ValueError('Insufficient root capacity; preserve floor, no deletion or guessed external path')
 attr0=host_attrs(b/'compact-system');rootattr=host_attrs(b/'compact-root')
 out.mkdir();c.dump(out/'staging.started.json',dict(copy_bytes=copies,base_raw_sha256=c.BASE))
 for tree in ('compact-system','compact-root'):shutil.copytree(b/tree,out/tree,symlinks=True)
 if inventory(out/'compact-system')!=before or inventory(out/'compact-root')!=roots or host_attrs(out/'compact-system')!=attr0 or host_attrs(out/'compact-root')!=rootattr:raise ValueError('Initial copy metadata/content differs')
 shutil.copytree(a.packet,out/'inputs',symlinks=False);(out/'records').mkdir();(out/'compact-image').mkdir();(out/'tmp').mkdir()
 for n in c.CHANGES:shutil.copyfile(out/'inputs/payload'/n,out/'compact-system'/n)
 after=inventory(out/'compact-system');changed=compare_trees(before,after,r)
 if host_attrs(out/'compact-system')!=attr0 or host_attrs(out/'compact-root')!=rootattr:raise ValueError('Copied host ownership/xattrs changed')
 if (out/'compact-system/build.prop').read_bytes()!=c.props56((b/'compact-system/build.prop').read_bytes()):raise ValueError('Property edit differs')
 shutil.copyfile(out/'inputs/config/file_contexts.txt',out/'records/file_contexts.txt')
 shutil.copyfile(out/'inputs/config/system_image_info.compact56.txt',out/'records/system_image_info.compact.txt')
 records={'baseline-system-inventory.json':before,'baseline-root-inventory.json':roots,'system-inventory.json':after,'root-inventory.json':roots,'baseline-system-host-attrs.json':attr0,'baseline-root-host-attrs.json':rootattr}
 for n,v in records.items():c.dump(out/'records'/n,v)
 if baseline(c.ROOT)[2:]!=(before,roots):raise ValueError('Baseline changed during staging')
 cpus=sorted(os.sched_getaffinity(0))[:2]
 if len(cpus)!=2:raise ValueError('Two CPUs unavailable')
 m=dict(image=56,baseline_image=55,base_raw_sha256=c.BASE,base_manifest_sha256=c.BASE_MANIFEST,base_outputs_sha256=c.BASE_OUTPUTS,proposal_sha256=c.PROPOSAL,packet_sha256=a.packet_sha256,raw_changes=r['changed'],changed=sorted(changed),copy_bytes=copies,cpus=cpus,controls={p.name:c.sha(p) for p in (out/'records').iterdir()},baseline_stage_unchanged=True,root_unchanged=True,system_partition_bytes=c.PARTITION,optional_fec=False,signed_hashtree_required=True,staged=True,built=False,installed=False)
 c.dump(out/'staging.json',m);(out/'staging.complete').write_text(c.sha(out/'staging.json')+'\n');check(out);print(json.dumps(dict(staged=True,stage=str(out),manifest_sha256=c.sha(out/'staging.json'))))

def check(stage,inside=False):
 root=safe_stage(stage,inside);m=json.loads((stage/'staging.json').read_text())
 if (stage/'staging.complete').read_text().strip()!=c.sha(stage/'staging.json') or m['image']!=56 or m['baseline_image']!=55 or m['base_raw_sha256']!=c.BASE or set(m['changed'])!=c.CHANGES or m['optional_fec'] is not False or m['signed_hashtree_required'] is not True:raise ValueError('Incomplete/changed56 manifest')
 r=packet_check(stage/'inputs',m['packet_sha256'])
 if m['raw_changes']!=r['changed']:raise ValueError('Raw contract differs')
 for n,pin in m['controls'].items():
  if Path(n).name!=n or (stage/'records'/n).is_symlink() or c.sha(stage/'records'/n)!=pin:raise ValueError('Stage control changed')
 b,bm,before,roots=baseline(root);after=inventory(stage/'compact-system');compare_trees(before,after,r)
 if before!=json.loads((stage/'records/baseline-system-inventory.json').read_text()) or after!=json.loads((stage/'records/system-inventory.json').read_text()) or roots!=inventory(stage/'compact-root') or roots!=json.loads((stage/'records/root-inventory.json').read_text()):raise ValueError('Tree/root record differs')
 for tree,key in [('compact-system','baseline-system-host-attrs.json'),('compact-root','baseline-root-host-attrs.json')]:
  recorded=json.loads((stage/'records'/key).read_text())
  if host_attrs(stage/tree)!=recorded or host_attrs(b/tree)!=recorded:raise ValueError('Host ownership/xattrs differ')
 if (stage/'compact-system/build.prop').read_bytes()!=c.props56((b/'compact-system/build.prop').read_bytes()):raise ValueError('Property content differs')
 if (stage/'records/system_image_info.compact.txt').read_text()!=c.config56((b/'system_image_info.compact.txt').read_text()) or c.sha(stage/'records/file_contexts.txt')!=bm['metadata_files_sha256']['file_contexts.txt']:raise ValueError('Pack config/labels differ')
 if shutil.disk_usage(stage).free<c.FLOOR:raise ValueError('20GiB floor crossed')
 return m

def mount_mode(path):
 found=[line.split()[5].split(',') for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==str(path)]
 if len(found)!=1:raise ValueError('Ambiguous mount '+str(path))
 return 'ro' if 'ro' in found[0] else 'rw'
def inside(stage,headroom=True):
 safe_stage(stage,True)
 if os.getuid()!=1000:raise ValueError('Wrong container UID')
 for attempt in range(100):
  if (stage/'watchdog.ready.json').exists():break
  time.sleep(.1)
 else:raise ValueError('Watchdog absent; no pack')
 ready=json.loads((stage/'watchdog.ready.json').read_text())
 if ready['uid']!=0 or ready['staging_sha256']!=c.sha(stage/'staging.json'):raise ValueError('Watchdog barrier differs')
 for path,mode in [('/','ro'),('/build','ro'),(str(stage),'rw'),(str(stage/'inputs'),'ro'),(str(stage/'records'),'ro'),(str(stage/'staging.json'),'ro'),(str(stage/'staging.complete'),'ro'),('/tmp','rw')]:
  if mount_mode(path)!=mode:raise ValueError('Mount boundary differs '+path)
 for name,value in [('memory.max','8589934592'),('memory.swap.max','0'),('pids.max','512')]:
  if (Path('/sys/fs/cgroup')/name).read_text().strip()!=value:raise ValueError('Resource cap differs')
 m=check(stage,True)
 if sorted(os.sched_getaffinity(0))!=m['cpus']:raise ValueError('CPU affinity differs')
 if headroom and shutil.disk_usage(stage).free<2*c.PARTITION+c.FLOOR:raise ValueError('Pack headroom unavailable')
 c.dump(stage/('pack.inside-checked.json' if headroom else 'pack.inside-postchecked.json'),dict(staging_sha256=c.sha(stage/'staging.json'),mounts_checked=True,resource_caps_checked=True,watchdog_checked=True))

def launch(stage):
 safe_stage(stage);m=check(stage);idle()
 if any((stage/n).exists() for n in ['launch.started.json','container-id','build.log','build.exit']):raise ValueError('Already launched; follow same handle')
 if shutil.disk_usage(stage).free<2*c.PARTITION+c.FLOOR:raise ValueError('Pack headroom unavailable')
 if subprocess.check_output(['sudo','-n','docker','image','inspect',c.BUILDER,'--format','{{.Id}}'],text=True,timeout=15).strip()!=c.BUILDER:raise ValueError('Builder differs')
 cp='/build/'+c.NAME;mounts=[(c.ROOT,'/build','ro'),(stage,cp,'rw'),(stage/'inputs',cp+'/inputs','ro'),(stage/'records',cp+'/records','ro'),(stage/'staging.json',cp+'/staging.json','ro'),(stage/'staging.complete',cp+'/staging.complete','ro'),(stage/'tmp','/tmp','rw')]
 argv=['sudo','-n','docker','run','-d','--pull','never','--name','kaidroid-services-appimage-image56','--read-only','--network','none','--user','1000:1000','--cpuset-cpus',','.join(map(str,m['cpus'])),'--cpus','2','--memory','8g','--memory-swap','8g','--pids-limit','512']
 for src,target,mode in mounts:argv+=['-v',str(src)+':'+target+':'+mode]
 argv+=['-e','TMPDIR='+cp+'/tmp','-e','PYTHONDONTWRITEBYTECODE=1',c.BUILDER,'timeout','--signal=TERM','--kill-after=10s','1800','bash',cp+'/inputs/tools/build_services_image56.sh']
 c.dump(stage/'launch.started.json',dict(argv=argv,time_unix=time.time(),staging_sha256=c.sha(stage/'staging.json'),initial_stage_bytes=tree_bytes(stage)))
 result=subprocess.run(argv,capture_output=True,text=True,timeout=30);(stage/'launch.stdout').write_text(result.stdout);(stage/'launch.stderr').write_text(result.stderr);result.check_returncode();cid=result.stdout.strip()
 if not re.fullmatch('[a-f0-9]{64}',cid):raise ValueError('Ambiguous Docker response; inspect name, no retry')
 (stage/'container-id').write_text(cid+'\n')
 with (stage/'watchdog.log').open('xb') as log:watcher=subprocess.Popen(['sudo','-n',sys.executable,str(stage/'inputs/tools/stage_services_image56.py'),'watch','--stage',str(stage)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
 (stage/'watchdog.launch-pid').write_text(str(watcher.pid)+'\n')
 for attempt in range(50):
  if (stage/'watchdog.ready.json').exists():break
  if watcher.poll() is not None:raise ValueError('Watchdog failed; pack barrier blocks')
  time.sleep(.1)
 else:
  subprocess.run(['sudo','-n','docker','kill',cid],check=True,capture_output=True,timeout=15);raise ValueError('No watchdog readiness; no retry')
 print(json.dumps(dict(container=cid,watchdog_launch_pid=watcher.pid)))
def tree_bytes(root):return sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())
def watch(stage):
 if os.geteuid()!=0:raise ValueError('Root watchdog child required')
 safe_stage(stage)
 try:os.setsid()
 except PermissionError:pass
 cid=(stage/'container-id').read_text().strip();start=json.loads((stage/'launch.started.json').read_text());samples=[];reason=None
 c.dump(stage/'watchdog.ready.json',dict(pid=os.getpid(),uid=0,staging_sha256=c.sha(stage/'staging.json')))
 while True:
  state=json.loads(subprocess.check_output(['docker','inspect',cid],timeout=15))[0];elapsed=time.time()-start['time_unix'];free=shutil.disk_usage(stage).free;growth=tree_bytes(stage)-start['initial_stage_bytes'];samples.append(dict(seconds=elapsed,free_bytes=free,growth_bytes=growth,running=state['State']['Running']))
  if not state['State']['Running']:break
  if elapsed>1800 or free<c.FLOOR or growth>4*1024**3:
   reason='deadline' if elapsed>1800 else 'free_floor' if free<c.FLOOR else 'stage_growth';subprocess.run(['docker','kill',cid],capture_output=True,check=True,timeout=15)
  time.sleep(2)
 c.dump(stage/'container.inspect.json',state);c.dump(stage/'watchdog.result.json',dict(terminal=True,stop_reason=reason,samples=samples))
 logs=subprocess.run(['docker','logs',cid],capture_output=True,timeout=30);(stage/'docker.stdout').write_bytes(logs.stdout);(stage/'docker.stderr').write_bytes(logs.stderr)
 error=None
 try:check(stage)
 except BaseException as exc:error=repr(exc)
 c.dump(stage/'terminal.result.json',dict(container=cid,exit_code=state['State']['ExitCode'],oom_killed=state['State']['OOMKilled'],stop_reason=reason,source_and_stage_checks_pass=error is None,postcheck_error=error,installed=False,raw_closure_verified=False))
 print(json.dumps(dict(terminal=True,exit_code=state['State']['ExitCode'],postcheck_error=error)))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 s=sub.add_parser('stage');s.add_argument('--root',type=Path,required=True);s.add_argument('--packet',type=Path,required=True);s.add_argument('--packet-sha256',required=True)
 for n in ('check','launch','inside','inside-check','watch'):sub.add_parser(n).add_argument('--stage',type=Path,required=True)
 a=p.parse_args()
 if a.mode=='stage':stage(a)
 elif a.mode=='check':print(json.dumps(dict(stage_checked=True,image=check(a.stage)['image'])))
 elif a.mode=='inside-check':inside(a.stage,False)
 else:globals()[a.mode](a.stage)

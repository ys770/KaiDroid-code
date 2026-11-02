"""Stage/pack the audited footer and Messaging over immutable56 on external disk."""
import argparse,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
import ime_footer_image57_retry01_contract as c
import ime_footer_image57_retry01_storage as storage


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
  for n in dirs+files:
   p=Path(folder)/n;st=p.lstat()
   rows[p.relative_to(root).as_posix()]=dict(uid=st.st_uid,gid=st.st_gid,xattrs={k:os.getxattr(p,k,follow_symlinks=False).hex() for k in os.listxattr(p,follow_symlinks=False)})
 return rows


def safe_stage(stage,inside=False):
 root=Path('/build') if inside else c.ROOT
 if stage!=root/c.NAME or stage.resolve(strict=True)!=stage or stage.is_symlink():raise ValueError('Exact external57 stage required')
 storage.verify(stage)
 return root


def capacity(stage,plan,initial=False):
 root=stage.parent
 sample=storage.sample(root,stage,plan,initial)
 if sample['breach']:raise ValueError('Two-volume capacity gate: '+sample['breach'])
 return sample


def idle():
 for n in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',n],capture_output=True,timeout=5).returncode!=1:raise ValueError('Active/unknown host job: '+n)
 if subprocess.check_output(['sudo','-n','docker','ps','-q'],text=True,timeout=15).strip():raise ValueError('Container active; observe existing job')


def packet_check(packet,pin):
 if packet.resolve(strict=True)!=packet or packet.is_symlink() or c.sha(packet/'packet.json')!=pin:raise ValueError('Packet identity differs')
 m=json.loads((packet/'packet.json').read_text())
 expected={'tools/'+n for n in c.TOOLS}|{'proposal.json','baseline-raw-inventory.json','baseline-xattrs.json','payload/'+c.MMS,'payload/build.prop','config/file_contexts.txt','config/system_image_info.compact56.txt','config/system_image_info.compact57.txt'}|{'proofs/'+n for n in ['native-staging.json','native-outputs.json','native-cache.json','native-review.json']}
 actual={p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_file()}
 if m.get('image')!=57 or m.get('proposal_sha256')!=c.PROPOSAL or set(m.get('files',{}))!=expected or actual!=expected|{'packet.json'} or any(p.is_symlink() for p in packet.rglob('*')):
  raise ValueError('Packet files/link/coverage differs')
 for n,pin in m['files'].items():
  if Path(n).is_absolute() or '..' in Path(n).parts or c.sha(packet/n)!=pin:raise ValueError('Packet payload differs: '+n)
  if n.startswith('tools/') and n.endswith(('.sh','.py')) and b'\r' in (packet/n).read_bytes():raise ValueError('Executable packet text must be canonical LF: '+n)
 if m.get('shell_preamble_execution',{}).get('preamble_executed') is not True or m.get('shell_preamble_execution',{}).get('whole_shell_syntax_passed') is not True or m.get('watchdog_unit')!=c.UNIT:raise ValueError('Actual packet shell/service evidence absent')
 r=c.proposal(packet/'proposal.json')
 for n,key in [('baseline-raw-inventory.json','baseline_inventory_sha256'),('baseline-xattrs.json','baseline_xattrs_sha256')]:
  if c.sha(packet/n)!=r[key]:raise ValueError('Baseline raw receipt differs')
 for n,key in [('file_contexts.txt','baseline_file_contexts_sha256'),('system_image_info.compact56.txt','baseline_pack_config_sha256')]:
  if c.sha(packet/'config'/n)!=r['pack'][key]:raise ValueError('Pack config/labels differ')
 if (packet/'config/system_image_info.compact57.txt').read_bytes()!=c.config57((packet/'config/system_image_info.compact56.txt').read_bytes()):raise ValueError('Pack config transform differs')
 for n in (c.MMS,'build.prop'):
  if c.sha(packet/'payload'/n)!=r['changed'][n]['after']['sha256']:raise ValueError('Private payload differs: '+n)
 for n,key in [('native-staging.json','compiled_stage_sha256'),('native-outputs.json','compiled_outputs_sha256'),('native-cache.json','compiled_cache_sha256'),('native-review.json','compiled_review_sha256')]:
  if c.sha(packet/'proofs'/n)!=r[key]:raise ValueError('Native receipt differs: '+n)
 values=[json.loads((packet/'proofs'/n).read_text()) for n in ['native-staging.json','native-outputs.json','native-cache.json','native-review.json']]
 c.validate_native_proofs(*values,r)
 return r


def native(root,packet,r,live):
 build=root/c.NATIVE
 if build.resolve(strict=True)!=build:raise ValueError('Symlinked native source')
 for n,key in [('staging.json','compiled_stage_sha256'),('outputs.json','compiled_outputs_sha256'),('cache-preservation.json','compiled_cache_sha256')]:
  if (build/n).resolve(strict=True)!=build/n or c.sha(build/n)!=r[key]:raise ValueError('Original native proof drift: '+n)
 if (build/'build.exit').read_text().strip()!='0' or (build/'container-id').read_text().strip()!=c.CID or (build/'preparation.complete').read_text().strip()!=r['compiled_stage_sha256']:
  raise ValueError('Native11 terminal identity differs')
 if live:
  info=json.loads(subprocess.check_output(['sudo','-n','docker','inspect',c.CID],text=True,timeout=15))[0];s=info['State']
  if info['Id']!=c.CID or info['Name']!='/kaidroid-tcl-dialog-build11' or info['Image']!=c.BUILDER or info['Config']['User']!='builder' or info['Config']['Cmd']!=['bash','/build/tcl-dialog-build11/build.sh'] or s['Status']!='exited' or s['Running'] or s['Restarting'] or s['OOMKilled'] or s['Pid']!=0 or s['ExitCode']!=0:raise ValueError('Original native container changed/live')
 meta=json.loads((build/'staging.json').read_text())
 for n,pin in meta['inputs'].items():
  path=build/'inputs'/n
  if Path(n).is_absolute() or '..' in Path(n).parts or path.resolve(strict=True)!=path or c.sha(path)!=pin:raise ValueError('Native input drift: '+n)
 if c.sha(build/'hiddenapi-flags.csv')!='bb6da7de3b49099e28eb3aa102bd5e0d06cf02ab4316a49adc677e9491a3a979':raise ValueError('Native complete CSV drift')
 for n,pin in r['exported_files'].items():
  path=build/'output'/n
  if path.resolve(strict=True)!=path or c.sha(path)!=pin:raise ValueError('Native30 export drift: '+n)
 return build


def baseline(root):
 b=root/c.BASE_NAME
 if b.resolve(strict=True)!=b:raise ValueError('Symlinked baseline56')
 for n,pin in [('staging.json',c.BASE_MANIFEST),('outputs.json',c.BASE_OUTPUTS),('compact-image/system.raw.img',c.BASE)]:
  if c.sha(b/n)!=pin:raise ValueError('Immutable56 differs: '+n)
 if (b/'compact-image/system.raw.img').stat().st_size!=c.PARTITION or (b/'build.exit').read_text().strip()!='0' or (b/'staging.complete').read_text().strip()!=c.BASE_MANIFEST:raise ValueError('Baseline56 terminal/completion differs')
 m=json.loads((b/'staging.json').read_text());out=json.loads((b/'outputs.json').read_text())
 if m['image']!=56 or out['image']!=56 or out['raw_sha256']!=c.BASE or out['staging_sha256']!=c.BASE_MANIFEST or out['avb_verified'] is not True or out['signed_hashtree_verified'] is not True or out['optional_fec'] is not False:raise ValueError('Baseline56 disposition differs')
 for n,pin in m['controls'].items():
  if Path(n).name!=n or (b/'records'/n).is_symlink() or c.sha(b/'records'/n)!=pin:raise ValueError('Baseline56 control drift: '+n)
 before=inventory(b/'compact-system');roots=inventory(b/'compact-root')
 if before!=json.loads((b/'records/system-inventory.json').read_text()) or roots!=json.loads((b/'records/root-inventory.json').read_text()):raise ValueError('Baseline56 tree differs')
 return b,before,roots


def stage(a):
 if os.name!='posix' or (os.geteuid(),os.getegid())!=(1000,1000) or a.root!=c.ROOT:raise ValueError('Attested builder/root required')
 out=a.root/c.NAME;storage.verify(out,fresh=True);idle()
 r=packet_check(a.packet,a.packet_sha256);build=native(a.root,a.packet,r,True);b,before,roots=baseline(a.root)
 for n,pin in {**r['protected56'],**{n:v['before']['sha256'] for n,v in r['changed'].items()}}.items():
  if before[n][0]!='file' or before[n][2]!=pin:raise ValueError('Baseline proposal payload differs: '+n)
 plan=dict(free_after_clone_bytes=shutil.disk_usage(out).free,incremental_budget_bytes=14*1024**3,emergency_floor_bytes=c.FLOOR)
 capacity(out,plan,True)
 (out/'preparation.pid').write_text(str(os.getpid())+'\n')
 attrs=host_attrs(b/'compact-system');rootattrs=host_attrs(b/'compact-root')
 shutil.copytree(b/'compact-system',out/'compact-system',symlinks=True);shutil.copytree(b/'compact-root',out/'compact-root',symlinks=True)
 shutil.copytree(a.packet,out/'inputs',symlinks=False)
 for n in ('records','compact-image','tmp'):(out/n).mkdir()
 for n in r['exported_files']:shutil.copyfile(build/'output'/n,out/'compact-system'/n)
 for n in (c.MMS,'build.prop'):shutil.copyfile(out/'inputs/payload'/n,out/'compact-system'/n)
 after=inventory(out/'compact-system');changed=c.compare_trees(before,after,r)
 if host_attrs(out/'compact-system')!=attrs or host_attrs(out/'compact-root')!=rootattrs:raise ValueError('Copied host ownership/xattrs differ')
 if (out/'compact-system/build.prop').read_bytes()!=c.props57((b/'compact-system/build.prop').read_bytes()):raise ValueError('Property edit differs')
 shutil.copyfile(out/'inputs/config/file_contexts.txt',out/'records/file_contexts.txt')
 shutil.copyfile(out/'inputs/config/system_image_info.compact57.txt',out/'records/system_image_info.compact.txt')
 for n,value in {'baseline-system-inventory.json':before,'system-inventory.json':after,'root-inventory.json':roots,'baseline-system-host-attrs.json':attrs,'baseline-root-host-attrs.json':rootattrs}.items():c.dump(out/'records'/n,value)
 if baseline(a.root)[1:]!=(before,roots):raise ValueError('Baseline changed during preparation')
 cpus=sorted(os.sched_getaffinity(0))[:2]
 if len(cpus)!=2:raise ValueError('Two CPUs unavailable')
 m=dict(image=57,baseline_image=56,base_raw_sha256=c.BASE,proposal_sha256=c.PROPOSAL,packet_sha256=a.packet_sha256,raw_changes=r['changed'],changed=sorted(changed),exported_files=r['exported_files'],cpus=cpus,disk_plan=plan,controls={p.name:c.sha(p) for p in (out/'records').iterdir()},system_partition_bytes=c.PARTITION,optional_fec=False,signed_hashtree_required=True,staged=True,built=False,installed=False)
 c.dump(out/'staging.json',m);(out/'staging.complete').write_text(c.sha(out/'staging.json')+'\n')
 check(out);print(json.dumps(dict(staged=True,stage=str(out),manifest_sha256=c.sha(out/'staging.json'))))


def check(stage,inside=False):
 root=safe_stage(stage,inside);m=json.loads((stage/'staging.json').read_text())
 if (stage/'staging.complete').read_text().strip()!=c.sha(stage/'staging.json') or m.get('image')!=57 or m.get('baseline_image')!=56 or m.get('base_raw_sha256')!=c.BASE or m.get('proposal_sha256')!=c.PROPOSAL or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True:raise ValueError('Incomplete/changed57 manifest')
 r=packet_check(stage/'inputs',m['packet_sha256']);native(root,stage/'inputs',r,not inside)
 if m['raw_changes']!=r['changed'] or set(m['changed'])!=set(r['changed']) or m['exported_files']!=r['exported_files']:raise ValueError('Stage prediction differs')
 for n,pin in m['controls'].items():
  if Path(n).name!=n or (stage/'records'/n).is_symlink() or c.sha(stage/'records'/n)!=pin:raise ValueError('Stage control changed')
 b,before,roots=baseline(root);after=inventory(stage/'compact-system');c.compare_trees(before,after,r)
 if before!=json.loads((stage/'records/baseline-system-inventory.json').read_text()) or after!=json.loads((stage/'records/system-inventory.json').read_text()) or roots!=inventory(stage/'compact-root') or roots!=json.loads((stage/'records/root-inventory.json').read_text()):raise ValueError('Tree/root record differs')
 for tree,key in [('compact-system','baseline-system-host-attrs.json'),('compact-root','baseline-root-host-attrs.json')]:
  expected=json.loads((stage/'records'/key).read_text())
  if host_attrs(stage/tree)!=expected or host_attrs(b/tree)!=expected:raise ValueError('Host ownership/xattrs drift')
 if (stage/'compact-system/build.prop').read_bytes()!=c.props57((b/'compact-system/build.prop').read_bytes()):raise ValueError('Property drift')
 if c.sha(stage/'records/file_contexts.txt')!=r['pack']['baseline_file_contexts_sha256'] or (stage/'records/system_image_info.compact.txt').read_bytes()!=c.config57((b/'records/system_image_info.compact.txt').read_bytes()):raise ValueError('Pack labels/config drift')
 capacity(stage,m['disk_plan'])
 return m


def validate_pack_container(info,stage,cid):
 m=json.loads((stage/'staging.json').read_text());config=info.get('Config',{});host=info.get('HostConfig',{})
 if info.get('Id')!=cid or info.get('Name')!='/kaidroid-tcl-ime-footer-image57-retry01' or info.get('Image')!=c.BUILDER or config.get('User')!='1000:1000' or host.get('NetworkMode')!='none' or host.get('ReadonlyRootfs') is not True:
  raise ValueError('Pack container identity changed; no stop allowed')
 cp='/build/'+c.NAME
 if config.get('Cmd')!=['timeout','--signal=TERM','--kill-after=10s','1800','bash',cp+'/inputs/tools/build_tcl_ime_footer_image57_retry01.sh']:raise ValueError('Pack command differs')
 expected={str(c.ROOT):('/build',False),str(stage):(cp,True),str(stage/'inputs'):(cp+'/inputs',False),str(stage/'records'):(cp+'/records',False),str(stage/'staging.json'):(cp+'/staging.json',False),str(stage/'staging.complete'):(cp+'/staging.complete',False),str(stage/'tmp'):('/tmp',True)}
 actual={v['Source']:(v['Destination'],v['RW']) for v in info.get('Mounts',[]) if v.get('Type')=='bind'}
 if len(info.get('Mounts',[]))!=7 or actual!=expected:raise ValueError('Pack container mounts differ')
 if config.get('Labels',{}).get('kaidroid.image57.staging')!=c.sha(stage/'staging.json'):raise ValueError('Container manifest label differs')
 if host.get('Memory')!=8*1024**3 or host.get('MemorySwap')!=8*1024**3 or host.get('PidsLimit')!=512 or host.get('CpusetCpus')!=','.join(map(str,m['cpus'])) or host.get('NanoCpus')!=2000000000:raise ValueError('Pack resource limits differ')


def mount_mode(path):
 found=[line.split()[5].split(',') for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==str(path)]
 if len(found)!=1:raise ValueError('Ambiguous mount '+str(path))
 return 'ro' if 'ro' in found[0] else 'rw'
def inside(stage,headroom=True):
 safe_stage(stage,True)
 if os.getuid()!=1000:raise ValueError('Wrong container UID')
 for attempt in range(1800):
  if (stage/'watchdog.ready.json').exists():break
  time.sleep(.1)
 else:raise ValueError('Watchdog absent; no pack')
 ready=json.loads((stage/'watchdog.ready.json').read_text())
 if ready['uid']!=0 or ready['staging_sha256']!=c.sha(stage/'staging.json') or ready.get('unit')!=c.UNIT or not re.fullmatch('[0-9a-f]{32}',ready.get('invocation_id','')):raise ValueError('Watchdog barrier differs')
 for path,mode in [('/','ro'),('/build','ro'),(str(stage),'rw'),(str(stage/'inputs'),'ro'),(str(stage/'records'),'ro'),(str(stage/'staging.json'),'ro'),(str(stage/'staging.complete'),'ro'),('/tmp','rw')]:
  if mount_mode(path)!=mode:raise ValueError('Mount boundary differs '+path)
 for name,value in [('memory.max','8589934592'),('memory.swap.max','0'),('pids.max','512')]:
  if (Path('/sys/fs/cgroup')/name).read_text().strip()!=value:raise ValueError('Resource cap differs')
 m=check(stage,True)
 if sorted(os.sched_getaffinity(0))!=m['cpus']:raise ValueError('CPU affinity differs')
 if headroom and shutil.disk_usage(stage).free<2*c.PARTITION+c.FLOOR:raise ValueError('Pack headroom unavailable')
 c.dump(stage/('pack.inside-checked.json' if headroom else 'pack.inside-postchecked.json'),dict(staging_sha256=c.sha(stage/'staging.json'),mounts_checked=True,resource_caps_checked=True,watchdog_checked=True))

def unit_argv(stage):
 return ['sudo','-n','systemd-run','--unit='+c.UNIT,
  '--property=Type=exec','--property=Restart=no','--property=RemainAfterExit=yes',
  '--property=User=root','--property=Group=root','--property=StandardInput=null',
  '--property=StandardOutput=append:'+str(stage/'watchdog.log'),
  '--property=StandardError=append:'+str(stage/'watchdog.log'),
  '--property=WorkingDirectory='+str(stage),'--property=RuntimeMaxSec=1900',
  '--property=MemoryMax=512M','--property=TasksMax=32','--',sys.executable,
  str(stage/'inputs/tools/stage_tcl_ime_footer_image57_retry01.py'),'watch','--stage',str(stage)]


def unit_state():
 result=subprocess.run(['systemctl','show',c.UNIT,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,Result,ExecMainStatus'],capture_output=True,text=True,timeout=15)
 return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)


def launch(stage):
 safe_stage(stage);m=check(stage);idle()
 if any((stage/n).exists() for n in ['launch.started.json','container-id','build.log','build.exit']):raise ValueError('Already launched; follow same handle')
 if shutil.disk_usage(stage).free<2*c.PARTITION+c.FLOOR:raise ValueError('Pack headroom unavailable')
 if subprocess.check_output(['sudo','-n','docker','image','inspect',c.BUILDER,'--format','{{.Id}}'],text=True,timeout=15).strip()!=c.BUILDER:raise ValueError('Builder differs')
 cp='/build/'+c.NAME;mounts=[(c.ROOT,'/build','ro'),(stage,cp,'rw'),(stage/'inputs',cp+'/inputs','ro'),(stage/'records',cp+'/records','ro'),(stage/'staging.json',cp+'/staging.json','ro'),(stage/'staging.complete',cp+'/staging.complete','ro'),(stage/'tmp','/tmp','rw')]
 argv=['sudo','-n','docker','run','-d','--label','kaidroid.image57.staging='+c.sha(stage/'staging.json'),'--pull','never','--name','kaidroid-tcl-ime-footer-image57-retry01','--read-only','--network','none','--user','1000:1000','--cpuset-cpus',','.join(map(str,m['cpus'])),'--cpus','2','--memory','8g','--memory-swap','8g','--pids-limit','512']
 for src,target,mode in mounts:argv+=['-v',str(src)+':'+target+':'+mode]
 argv+=['-e','TMPDIR='+cp+'/tmp','-e','PYTHONDONTWRITEBYTECODE=1',c.BUILDER,'timeout','--signal=TERM','--kill-after=10s','1800','bash',cp+'/inputs/tools/build_tcl_ime_footer_image57_retry01.sh']
 c.dump(stage/'launch.started.json',dict(argv=argv,time_unix=time.time(),staging_sha256=c.sha(stage/'staging.json'),initial_stage_bytes=tree_bytes(stage)))
 result=subprocess.run(argv,capture_output=True,text=True,timeout=30);(stage/'launch.stdout').write_text(result.stdout);(stage/'launch.stderr').write_text(result.stderr);result.check_returncode();cid=result.stdout.strip()
 if not re.fullmatch('[a-f0-9]{64}',cid):raise ValueError('Ambiguous Docker response; inspect name, no retry')
 (stage/'container-id').write_text(cid+'\n')
 service=unit_argv(stage)
 c.dump(stage/'watchdog.unit-request.json',dict(unit=c.UNIT,argv=service,container_id=cid,staging_sha256=c.sha(stage/'staging.json')))
 # PID1 supervises this root service independently of the launching SSH/PTY.
 # An observation error retains the same container/unit for reconciliation.
 result=subprocess.run(service,capture_output=True,timeout=30)
 (stage/'watchdog.unit-start.stdout').write_bytes(result.stdout);(stage/'watchdog.unit-start.stderr').write_bytes(result.stderr);result.check_returncode()
 deadline=time.monotonic()+120
 while time.monotonic()<deadline:
  if (stage/'watchdog.ready.json').exists():
   ready=json.loads((stage/'watchdog.ready.json').read_text())
   if ready.get('unit')!=c.UNIT or ready.get('uid')!=0 or ready.get('staging_sha256')!=c.sha(stage/'staging.json'):raise ValueError('Unexpected service barrier')
   print(json.dumps(dict(container=cid,watchdog_unit=c.UNIT,watchdog_pid=ready['pid'])));return
  time.sleep(1)
 c.dump(stage/'watchdog.readiness-unresolved.json',dict(container_id=cid,unit=c.UNIT,state=unit_state(),relaunch_allowed=False))
 raise ValueError('Existing container/unit readiness unresolved; reconcile read-only, never relaunch')
def tree_bytes(root):return sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())
def watch(stage):
 if os.geteuid()!=0:raise ValueError('Root watchdog child required')
 safe_stage(stage)
 invocation=os.environ.get('INVOCATION_ID','')
 if not re.fullmatch('[0-9a-f]{32}',invocation) or unit_state().get('MainPID')!=str(os.getpid()):raise ValueError('Watcher must be the root PID1-supervised service')
 cid=(stage/'container-id').read_text().strip();start=json.loads((stage/'launch.started.json').read_text());samples=[];reason=None
 validate_pack_container(json.loads(subprocess.check_output(['docker','inspect',cid],timeout=15))[0],stage,cid)
 c.dump(stage/'watchdog.ready.json',dict(pid=os.getpid(),uid=0,unit=c.UNIT,invocation_id=invocation,staging_sha256=c.sha(stage/'staging.json')))
 while True:
  state=json.loads(subprocess.check_output(['docker','inspect',cid],timeout=15))[0];validate_pack_container(state,stage,cid);elapsed=time.time()-start['time_unix'];free=shutil.disk_usage(stage).free;growth=tree_bytes(stage)-start['initial_stage_bytes'];rootfree=shutil.disk_usage(c.ROOT).free;samples.append(dict(seconds=elapsed,free_bytes=free,growth_bytes=growth,running=state['State']['Running']))
  if not state['State']['Running']:break
  if elapsed>1800 or free<=c.FLOOR or rootfree<=c.FLOOR or growth>4*1024**3:
   reason='deadline' if elapsed>1800 else 'free_floor' if free<=c.FLOOR or rootfree<=c.FLOOR else 'stage_growth';subprocess.run(['docker','kill',cid],capture_output=True,check=True,timeout=15)
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
 elif a.mode=='watch':
  try:watch(a.stage)
  except BaseException as error:
   failure=a.stage/'watchdog.failure.json'
   if not failure.exists():c.dump(failure,dict(unit=c.UNIT,error=repr(error),pid=os.getpid(),time_unix=time.time(),replacement_pack_started=False))
   raise
 else:globals()[a.mode](a.stage)

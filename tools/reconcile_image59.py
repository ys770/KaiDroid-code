"""Read an identified image59 job's actual state; never launch/restart/stop anything."""
import argparse,json,re,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
import ime_handover_image59_contract as c

NAMES={
 'engineering-tcl-ime-handover-stage-59':('kaidroid-tcl-ime-handover-image59','build_tcl_ime_handover_image59.sh',c.UNIT),
}


def validate(info,stage,manifest_pin,cid):
 if stage.parent!=c.ROOT or stage.name not in NAMES:raise ValueError('Only the identified image59 stage may be observed')
 name,script,_=NAMES[stage.name];config=info.get('Config',{});host=info.get('HostConfig',{});cp='/build/'+stage.name
 if info.get('Id')!=cid or info.get('Name')!='/'+name or info.get('Image')!=c.BUILDER or config.get('User')!='1000:1000' or config.get('Labels',{}).get('kaidroid.image59.staging')!=manifest_pin:
  raise ValueError('Container identity/manifest differs')
 if config.get('Cmd')!=['timeout','--signal=TERM','--kill-after=10s','1800','bash',cp+'/inputs/tools/'+script] or host.get('NetworkMode')!='none' or host.get('ReadonlyRootfs') is not True:raise ValueError('Container command/boundary differs')
 expected={str(c.ROOT):('/build',False),str(stage):(cp,True),str(stage/'inputs'):(cp+'/inputs',False),str(stage/'records'):(cp+'/records',False),str(stage/'staging.json'):(cp+'/staging.json',False),str(stage/'staging.complete'):(cp+'/staging.complete',False),str(stage/'tmp'):('/tmp',True)}
 actual={v['Source']:(v['Destination'],v['RW']) for v in info.get('Mounts',[]) if v.get('Type')=='bind'}
 if len(info.get('Mounts',[]))!=7 or actual!=expected:raise ValueError('Container mounts differ')


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--stage',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--manifest-sha256',required=True);p.add_argument('--container-id',required=True)
 p.add_argument('--observation-delay-seconds',type=int,choices=range(16),default=0,help='Optional bounded read-only detached-service probe delay')
 a=p.parse_args();s=a.stage
 if s.parent!=c.ROOT or s.name not in NAMES or s.resolve(strict=True)!=s:raise ValueError('Exact original/retry stage required')
 if any(not re.fullmatch('[0-9a-f]{64}',v) for v in [a.manifest_sha256,a.container_id]):raise ValueError('Exact canonical identities required')
 if c.sha(s/'staging.json')!=a.manifest_sha256 or (s/'staging.complete').read_text().strip()!=a.manifest_sha256 or (s/'container-id').read_text().strip()!=a.container_id:raise ValueError('Stage identity changed')
 manifest=json.loads((s/'staging.json').read_text())
 if manifest.get('image')!=59 or manifest.get('baseline_image')!=58:raise ValueError('Stage generation differs')
 if a.observation_delay_seconds:time.sleep(a.observation_delay_seconds)
 def docker(*args):
  result=subprocess.run(['sudo','-n','docker',*args],capture_output=True,timeout=30);result.check_returncode();return result
 result=docker('inspect',a.container_id);info=json.loads(result.stdout)[0];validate(info,s,a.manifest_sha256,a.container_id)
 packet=s/'inputs';packet_pin=manifest['packet_sha256']
 if c.sha(packet/'packet.json')!=packet_pin:raise ValueError('Original packet manifest differs')
 for n,pin in json.loads((packet/'packet.json').read_text())['files'].items():
  path=packet/n
  if Path(n).is_absolute() or '..' in Path(n).parts or path.resolve(strict=True)!=path or c.sha(path)!=pin:raise ValueError('Original packet payload changed: '+n)
 state=info['State'];terminal=state.get('Status')=='exited' and state.get('Running') is False and state.get('Pid')==0
 build_exit=(s/'build.exit').read_text().strip() if (s/'build.exit').exists() else None
 receipt=json.loads((s/'terminal.result.json').read_text()) if (s/'terminal.result.json').exists() else None
 if receipt and (receipt.get('container')!=a.container_id or terminal and receipt.get('exit_code')!=state.get('ExitCode')):raise ValueError('Existing terminal receipt contradicts actual container')
 ready=json.loads((s/'watchdog.ready.json').read_text()) if (s/'watchdog.ready.json').exists() else None
 observer={}
 if ready:
  path=Path('/proc')/str(int(ready['pid']))/'cmdline'
  try:cmd=path.read_bytes()
  except FileNotFoundError:cmd=None
  observer=dict(recorded_pid=ready['pid'],pid_present=cmd is not None,matches_expected_watch_command=bool(cmd and str(s/'inputs/tools').encode() in cmd and b'watch' in cmd))
 if NAMES[s.name][2]:
  unit=subprocess.run(['systemctl','show',NAMES[s.name][2],'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,Result,ExecMainStatus'],capture_output=True,text=True,timeout=15)
  observer['unit']=dict(line.split('=',1) for line in unit.stdout.splitlines() if '=' in line)
 logs=docker('logs',a.container_id)
 report=dict(scope='Read-only terminal/state reconciliation; original files preserved',stage=str(s),manifest_sha256=a.manifest_sha256,container_id=a.container_id,
  terminal=terminal,observed_container_state=state,actual_build_exit_file=build_exit,build_log_exists=(s/'build.log').exists(),raw_image_exists=(s/'compact-image/system.raw.img').exists(),existing_terminal_receipt=receipt,observer=observer,
  docker_stdout_tail=logs.stdout[-4096:].decode(errors='replace'),docker_stderr_tail=logs.stderr[-4096:].decode(errors='replace'),
  observation_delay_seconds=a.observation_delay_seconds,replacement_pack_started=False,watcher_started_or_restarted=False,container_stopped=False,original_files_changed=False,raw_closure_verified=False,installed=False)
 c.dump(a.output,report);print(json.dumps(dict(terminal=terminal,exit_code=state.get('ExitCode'),build_exit_file=build_exit,replacement_pack_started=False)))


if __name__=='__main__':main()

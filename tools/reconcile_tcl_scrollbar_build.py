"""Observe the exact resource job after a timeout; never start, stop or restart it."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode=True
import tcl_scrollbar_build_contract as c


def observation(stage,pin,cid,info):
 config=info.get('Config',{})
 if info.get('Id')!=cid or info.get('Name')!='/kaidroid-'+c.NAME or info.get('Image')!=c.IMAGE or config.get('Labels',{}).get('kaidroid.dialog.staging')!=pin or config.get('Cmd')!=['bash','/build/'+c.NAME+'/build.sh']:
  raise ValueError('Not the caller-identified resource job')
 error=None
 try:
  if c.sha(stage/'staging.json')!=pin:raise ValueError('Original staging manifest changed')
  c.validate_container(info,c.ROOT,stage,cid)
  spec=c.load_stage(c.ROOT,stage);c.verify_inputs(stage,spec)
 except (ValueError,OSError) as exc:error=str(exc)
 state=info['State']
 terminal=state.get('Status')=='exited' and state.get('Running') is False and state.get('Pid')==0
 build_exit=(stage/'build.exit').read_text().strip() if (stage/'build.exit').exists() else None
 monitor=None;monitor_error=None
 try:
  if (stage/'disk-monitor-state.json').exists():monitor=json.loads((stage/'disk-monitor-state.json').read_text())
 except (ValueError,OSError) as exc:monitor_error=str(exc)
 live_monitor=None
 if monitor and type(monitor.get('pid')) is int:
  try:cmd=(Path('/proc')/str(monitor['pid'])/'cmdline').read_bytes()
  except FileNotFoundError:cmd=None
  live_monitor=dict(recorded_pid=monitor['pid'],present=cmd is not None,
   command_matches=bool(cmd and str(stage/'disk-monitor.py').encode() in cmd and str(stage/'container-id').encode() in cmd))
 return dict(scope='Read-only existing resource job reconciliation',container_id=cid,expected_staging_sha256=pin,
  observed_container_state=state,terminal=terminal,build_exit_file=build_exit,
  exit_file_matches_docker=terminal and build_exit==str(state.get('ExitCode')),
  source_and_container_checks_passed=error is None,source_or_control_error=error,
  existing_monitor_state=monitor,monitor_read_error=monitor_error,monitor_process_observation=live_monitor,
  outputs_manifest_exists=(stage/'outputs.json').exists(),cache_proof_exists=(stage/'cache-preservation.json').exists(),
  compiler_launched=False,job_stopped_or_restarted=False,compiled_resource_gate_verified=False,installed=False)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('stage','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in ('manifest-sha256','container-id'):p.add_argument('--'+name,required=True)
 a=p.parse_args()
 if a.stage!=c.ROOT/c.NAME or a.stage.resolve(strict=True)!=a.stage or any(not re.fullmatch('[0-9a-f]{64}',v) for v in (a.manifest_sha256,a.container_id)):
  raise ValueError('Require exact resource stage, manifest and complete CID')
 result=subprocess.run(['sudo','-n','docker','inspect',a.container_id],capture_output=True,check=True,timeout=30)
 rows=json.loads(result.stdout)
 if len(rows)!=1:raise ValueError('Ambiguous Docker observation; retain same job')
 report=observation(a.stage,a.manifest_sha256,a.container_id,rows[0])
 c.dump(a.output,report);print(json.dumps(report))


if __name__=='__main__':main()

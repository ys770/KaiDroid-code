"""Prepare one isolated resource-only stage; hardware owns every invocation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
sys.dont_write_bytecode=True
import tcl_scrollbar_build_contract as c

PRIOR=c.ROOT/'tcl-dialog-build12'
RECOVERY=PRIOR/'export-recovery01'
PRIOR_PINS={
 'tcl-dialog-build12/staging.json':'794416e1fdc169b1374010c0550f1ea51d45eedc65f3c669bb64de06045a3600',
 'tcl-dialog-build12/control-inputs.json':'9a4bea5999ebdfbff17baf554d0937739e6a4a90ab161dfe24be1e1e2b3decd4',
 'tcl-dialog-build12/cache-preservation.json':'04b1802f3503e808c8218f18b3bc6b908b2377bcb7b360d1a91b2e2bee445907',
 'tcl-dialog-build12/export-recovery01/outputs.json':'16d578f19e384fd4e922b1f913f7f1e1637b2318ad54169fdb756b6ebe4ffed1',
 'tcl-dialog-build12/export-recovery01/compiled-audit.json':'a780e970acc7ad915576e95583294d6b1ccbf8ddeeda49eb409da11b4fc291f4',
 'tcl-dialog-build12/export-recovery01/recovery.json':'1def8a52b57e955a28ce1f9097130a230083bfab2b2f4ad5ca2d90b750f26c12',
}


def run(argv):return subprocess.run(list(map(str,argv)),capture_output=True,text=True,check=True,timeout=30)


def idle():
 for record in list(c.ROOT.glob('*/prepare.pid'))+list(c.ROOT.glob('*/preparation.pid')):
  pid=int(record.read_text().strip())
  if pid==os.getpid():continue
  try:cmd=(Path('/proc')/str(pid)/'cmdline').read_bytes()
  except FileNotFoundError:continue
  if b'prepare_' in cmd or b'stage_' in cmd:raise ValueError('Existing preparation process is live; observe it')
 for name in ('ninja','soong_build','soong_ui','e2fsdroid'):
  probe=subprocess.run(['pgrep','-x',name],capture_output=True,timeout=15)
  if probe.returncode!=1:raise ValueError('Active/unknown shared build process: '+name)
 if run(['sudo','-n','docker','ps','-q']).stdout.strip():raise ValueError('Container already active; do not duplicate')


def packet_check(packet,pin):
 if packet.resolve(strict=True)!=packet or c.sha(packet/'packet.json')!=pin:raise ValueError('Execution packet identity differs')
 meta=json.loads((packet/'packet.json').read_text())
 if meta.get('kind')!='tcl-scrollbar-execution01' or meta.get('stage')!=c.NAME or meta.get('backing')!=c.BACKING:
  raise ValueError('Wrong execution packet kind/storage')
 files={p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_file()}
 if files!=set(meta['files'])|{'packet.json'} or any(p.is_symlink() for p in packet.rglob('*')):
  raise ValueError('Execution packet coverage/link differs')
 for name,pin in meta['files'].items():
  p=packet/c.safe_relative(name)
  if c.sha(p)!=pin:raise ValueError('Execution packet bytes changed: '+name)
 return meta


def retained():
 c.verify_pins(c.ROOT,PRIOR_PINS)
 exports=json.loads((RECOVERY/'outputs.json').read_text())
 review=json.loads((RECOVERY/'compiled-audit.json').read_text())
 recovered=json.loads((RECOVERY/'recovery.json').read_text())
 cache=json.loads((PRIOR/'cache-preservation.json').read_text())
 if exports.get('files',{}).get('framework/framework-res.apk')!=c.BASE or exports.get('files',{}).get('framework/framework.jar')!=c.FRAMEWORK or len(exports['files'])!=30 or review.get('full_acceptance') is not True or recovered.get('passed') is not True or recovered.get('compiler_restarted') is not False or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('lower_entries')!=565530 or cache.get('projected_removed_entries')!=[]:
  raise ValueError('Retained native12 context differs')
 pins=dict(PRIOR_PINS)
 for name,pin in exports['files'].items():pins['tcl-dialog-build12/export-recovery01/output/'+name]=pin
 c.verify_pins(c.ROOT,pins)
 return pins,json.loads((PRIOR/'staging.json').read_text())


def launcher(stage,cpus):
 mounts=c.bind_map(c.ROOT,stage)
 argv=['sudo','-n','docker','create','--name','kaidroid-'+c.NAME,'--network','none','--user','builder',
  '--cpuset-cpus',','.join(map(str,cpus)),'--cpus','2','--memory','8g','--memory-swap','8g','--pids-limit','512',
  '--label','kaidroid.dialog.stage='+c.NAME,'--label','kaidroid.dialog.staging=STAGING_DIGEST']
 for dest,(source,rw) in mounts.items():argv+=['-v',source+':'+dest+(':'+('rw' if rw else 'ro'))]
 argv+=['kaidroid-build:20261023','bash','/build/'+c.NAME+'/build.sh']
 import shlex
 return '''#!/usr/bin/env bash
set -euo pipefail
stage='''+shlex.quote(stage.as_posix())+'''
manifest=$(sha256sum "$stage/staging.json")
manifest=${manifest%% *}
test "$(cat "$stage/preparation.complete")" = "$manifest"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
python3 -B "$stage/inputs/tools/prepare_tcl_scrollbar_stage.py" prelaunch --stage "$stage"
'''+shlex.join(argv).replace('kaidroid.dialog.staging=STAGING_DIGEST','"kaidroid.dialog.staging=$manifest"')+''' > "$stage/container-id"
sudo -n python3 -B "$stage/disk-monitor.py" monitor --root '''+shlex.quote(c.ROOT.as_posix())+''' --stage "$stage" --container-id-file "$stage/container-id" --daemonize
sudo -n python3 -B "$stage/disk-monitor.py" ready --root '''+shlex.quote(c.ROOT.as_posix())+''' --stage "$stage" --container-id-file "$stage/container-id"
sudo -n docker start "$(cat "$stage/container-id")" > "$stage/start.log" 2>&1
cat "$stage/container-id"
'''


def prepare(packet,pin):
 if os.name!='posix' or (os.geteuid(),os.getegid())!=(1000,1000):raise ValueError('Use attested Linux1000:1000 builder')
 import layered_dialog_output as layer
 stage=c.ROOT/c.NAME
 idle();layer.verify_external_storage(stage,fresh=True)
 meta=packet_check(packet,pin);pins,prior=retained()
 acquisition=json.loads((packet/'proofs/resource-source.json').read_text())
 expected=acquisition['resource_tree']
 original=c.inventory(c.ROOT/c.RESOURCE)
 if original!=expected or original['values/styles.xml'].get('sha256')!=c.STYLES:
  raise ValueError('Current full resource source differs from frozen acquisition')
 pins.update(acquisition['build_metadata'])
 pins[c.RESOURCE+'/values/styles.xml']=c.STYLES
 c.verify_pins(c.ROOT,pins)
 plan=dict(free_after_clone_bytes=shutil.disk_usage(stage).free,incremental_budget_bytes=14*c.GIB,emergency_floor_bytes=20*c.GIB)
 if layer.external_sample(c.ROOT,stage,plan,initial=True)['breach']:raise ValueError('Require external34GiB/root20GiB before preparation')
 c.dump(stage/'prepare.started.json',dict(pid=os.getpid(),packet_sha256=pin))
 with (stage/'prepare.pid').open('x') as stream:stream.write(str(os.getpid())+'\n')
 inputs=stage/'inputs';inputs.mkdir()
 shutil.copytree(c.ROOT/c.RESOURCE,inputs/'res',symlinks=True)
 if c.inventory(inputs/'res')!=original:raise ValueError('Owned resource copy differs before overlay')
 for name,digest in c.OVERLAY.items():
  source=packet/'proposal/overlay'/name;target=inputs/'res'/name
  if c.sha(source)!=digest or (name!='values/styles.xml' and target.exists()):raise ValueError('Resource overlay identity/new path differs')
  shutil.copyfile(source,target)
  if name!='values/styles.xml':target.chmod(0o644)
  os.utime(target,None)  # Only owned changed inputs; deterministic archives have epoch mtimes.
 candidate=c.inventory(inputs/'res');delta=c.compare_source(original,candidate)
 c.dump(inputs/'resource-before.json',original);c.dump(inputs/'resource-after.json',candidate)
 shutil.copytree(packet/'proposal',inputs/'proposal')
 shutil.copytree(packet/'tools',inputs/'tools')
 shutil.copyfile(packet/'proofs/resource-source.json',inputs/'resource-source.json')
 for source,dest in [('build_tcl_scrollbar.sh','build.sh'),('resource-monitor.py','disk-monitor.py'),('layered_dialog_output.py','layered_dialog_output.py'),('tcl_scrollbar_build_contract.py','tcl_scrollbar_build_contract.py')]:
  shutil.copyfile(packet/'tools'/source,stage/dest)
 for name in ('lower-ro','cache-upper','cache-work','out'):(stage/name).mkdir(mode=0o755)
 # Full snapshot and mount commands operate only on the owned new stage.
 subprocess.run(['sudo','-n','python3','-B',str(stage/'layered_dialog_output.py'),'snapshot','--stage',str(stage)],check=True)
 lower=c.ROOT/'tcl-dialog-build01/out'
 subprocess.run(['sudo','-n','mount','--bind',str(lower),str(stage/'lower-ro')],check=True)
 subprocess.run(['sudo','-n','mount','-o','remount,bind,ro',str(stage/'lower-ro')],check=True)
 options='lowerdir='+str(stage/'lower-ro')+',upperdir='+str(stage/'cache-upper')+',workdir='+str(stage/'cache-work')+',index=off,redirect_dir=off,metacopy=off'
 subprocess.run(['sudo','-n','mount','-t','overlay','overlay','-o',options,str(stage/'out')],check=True)
 layered=dict(lower=str(lower),lower_ro=str(stage/'lower-ro'),upper=str(stage/'cache-upper'),work=str(stage/'cache-work'),merged=str(stage/'out'),before_inventory_sha256=c.sha(stage/'cache-lower-before.json'),original_lower_read_only=True)
 layer.verify_mounts(stage,dict(layered_output=layered))
 before=json.loads((stage/'cache-lower-before.json').read_text())
 if len(before)!=565530 or layer.semantic(before)!=layer.inventory(stage/'out',identity=False):raise ValueError('Initial private cache projection differs')
 product=stage/'out/target/product/n139dl/system'
 if c.sha(product/'framework/framework-res.apk')!=c.BASE:raise ValueError('Initial cached resource APK differs')
 preserved={name:c.sha(product/name) for name in set(prior['closure'])|set(prior['art_apex']) if name!='framework/framework-res.apk'}
 cpus=sorted(os.sched_getaffinity(0))[:2]
 if len(cpus)!=2:raise ValueError('Two CPUs unavailable')
 nonres={p.relative_to(inputs).as_posix():c.sha(p) for p in inputs.rglob('*') if p.is_file() and not c.within(p,inputs/'res')}
 spec=dict(kind='tcl-scrollbar-resource-only01',target=c.TARGET,baseline_framework_res_sha256=c.BASE,
  baseline_pins=pins,retained_product=preserved,resource_source_entries=len(original),source_delta=delta,
  inputs=nonres,layered_output=layered,output_source=str(stage/'out'),cpus=cpus,runtime_limit_seconds=1800,
  packet_sha256=pin,builder_identity=dict(image_id=c.IMAGE,image_user='builder',uid=1000,gid=1000),
  external_storage=dict(volume='/mnt/ext1',backing=c.BACKING,device='8:0',root_floor_bytes=20*c.GIB,root_initial_free_bytes=shutil.disk_usage(c.ROOT).free),disk_plan=plan)
 (stage/'targets.txt').write_text(c.TARGET+'\n')
 (stage/'launch.sh').write_text(launcher(stage,cpus))
 spec['source_controls']={n:c.sha(stage/n) for n in c.CONTROLS}
 c.dump(stage/'staging.json',spec)
 c.dump(stage/'control-inputs.json',{n:c.sha(stage/n) for n in c.CONTROLS|{'staging.json'}})
 (stage/'preparation.complete').write_text(c.sha(stage/'staging.json')+'\n')
 spec=c.load_stage(c.ROOT,stage);c.verify_inputs(stage,spec);idle()
 print(json.dumps(dict(stage=str(stage),staging_sha256=c.sha(stage/'staging.json'),source_entries=len(original),prepared=True,launched=False)))


def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 ready=sub.add_parser('prepare');ready.add_argument('--packet',type=Path,required=True);ready.add_argument('--packet-sha256',required=True)
 pre=sub.add_parser('prelaunch');pre.add_argument('--stage',type=Path,required=True)
 a=p.parse_args()
 if a.mode=='prepare':prepare(a.packet,a.packet_sha256)
 else:
  if os.name!='posix' or (os.geteuid(),os.getegid())!=(1000,1000):raise ValueError('Use Linux1000:1000 builder')
  idle();spec=c.load_stage(c.ROOT,a.stage);c.verify_inputs(a.stage,spec)
  if any((a.stage/name).exists() for name in ('container-id','build.log','build.exit')):raise ValueError('Existing job; observe its exact ID')
  if run(['sudo','-n','docker','image','inspect','kaidroid-build:20261023','--format','{{.Id}}']).stdout.strip()!=c.IMAGE:raise ValueError('Builder image changed')
  print(json.dumps(dict(prelaunch_verified=True,launched=False)))


if __name__=='__main__':main()

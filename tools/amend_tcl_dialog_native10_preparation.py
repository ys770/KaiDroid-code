"""Amend ONLY the exact terminal, never-launched native10 preparation; preserve originals."""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT='/opt/kaidroid/kaidroid-build-20261023'
STAGE='tcl-dialog-build10'
BACKING='/mnt/ext1/kaidroid-tcl-dialog-build10'
OLD_FILES={
 'staging.json':'23f95f50e1e210e30db02efaeddc0296f64c4a00a92686c50290945a2d1f1273',
 'launch.sh':'89719f816d35dea5d6a061c191a32c870e0600a425025ba2e479da551f5f386e',
 'disk-monitor.py':'d06fc91cb98bf4b53e96db62a1eace0b61e3f490115f176a7083e81f3f9b072b',
 'control-inputs.json':'0ab42a60bfeae7539a70ef5dbfbb0687544871ce7b0637708f8378919d86c74f',
 'preparation.complete':'0b0185c7e3001ea601038de3833be6e715d8fa737f33a92654b3d400241cb590',
}
NEW_MONITOR='27e2752748f52df044233b738e3bf84055a53e5ac8b5cde633093e3bd55db350'
CONTROLS={'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}
ORDER=['staging.json','disk-monitor.py','launch.sh','control-inputs.json','preparation.complete']


def digest(data):return hashlib.sha256(data).hexdigest()


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()


def plan(files,monitor):
 for name,pin in OLD_FILES.items():
  if digest(files[name])!=pin:raise ValueError('Exact original controller changed: '+name)
 if digest(monitor)!=NEW_MONITOR:raise ValueError('Unreviewed replacement monitor')
 oldsha=OLD_FILES['staging.json'];spec=json.loads(files['staging.json'])
 controls=json.loads(files['control-inputs.json'])
 if set(controls)!=CONTROLS:raise ValueError('Original six-control set changed')
 for name,pin in controls.items():
  if digest(files[name])!=pin:raise ValueError('Original control mismatch: '+name)
 if files['preparation.complete'].decode().strip()!=oldsha:raise ValueError('Original preparation not complete')
 storage=spec.get('external_storage',{})
 if storage.get('backing')!='/mnt/ext1/kaidroid-tcl-dialog-build09' or storage.get('volume')!='/mnt/ext1' or storage.get('device')!='8:0' or storage.get('root_floor_bytes')!=20*1024**3:
  raise ValueError('Not the exact known descriptive-backing error')
 updated=deepcopy(spec);updated['external_storage']['backing']=BACKING
 manifest=(json.dumps(updated,indent=2)+'\n').encode()
 newsha=digest(manifest)
 launch=files['launch.sh'].decode()
 marker='test -f "$stage/preparation.complete"'
 if launch.count(oldsha)!=1 or launch.count(marker)!=1:raise ValueError('Original launcher shape changed')
 launch=launch.replace(oldsha,newsha).replace(marker,marker+'\ntest "$(cat "$stage/preparation.complete")" = "'+newsha+'"')
 newfiles={'staging.json':manifest,'launch.sh':launch.encode(),'disk-monitor.py':monitor,'preparation.complete':(newsha+'\n').encode()}
 changed=deepcopy(controls)
 for name in ('staging.json','launch.sh','disk-monitor.py'):changed[name]=digest(newfiles[name])
 newfiles['control-inputs.json']=(json.dumps(changed,indent=2)+'\n').encode()
 return newfiles,dict(original_manifest_sha256=oldsha,amended_manifest_sha256=newsha,
  changed_manifest_fields=['external_storage.backing'],new_monitor_sha256=NEW_MONITOR,
  files={n:dict(before=digest(files[n]),after=digest(newfiles[n])) for n in ORDER},
  unchanged_controls={n:controls[n] for n in ('build.sh','targets.txt','layered_dialog_output.py')},
  java_inputs_unchanged=True,generator_input_unchanged=True,original_lower_unchanged=True,
  compiler_launched=False,stage_reprepared=False,originals_preserved=True)


def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def no_launch(stage):
 for name in ('container-id','build.log','build.exit','frontend.log','disk-monitor.pid','disk-monitor-ready.json','disk-monitor-state.json','start.log','dependency-plan.log','plan-ready.json','plan-review.json'):
  if (stage/name).exists():raise ValueError('Build/monitor/plan already exists; never amend: '+name)


def read_controls(stage):
 result={}
 for name in CONTROLS|{'control-inputs.json','preparation.complete'}:
  path=stage/name
  if path.resolve(strict=True)!=path or (path.stat().st_uid,path.stat().st_gid)!=(1000,1000):
   raise ValueError('Symlinked/unowned stage controller: '+name)
  result[name]=path.read_bytes()
 return result


def idle(stage):
 pid=int((stage/'prepare.pid').read_text().strip())
 if (Path('/proc')/str(pid)).exists():raise ValueError('Original preparation PID still exists; observe, never repeat')
 for name in ('ninja','soong_build','e2fsdroid'):
  if subprocess.run(['pgrep','-x',name],capture_output=True,timeout=15).returncode!=1:raise ValueError('Build active or observation failed')
 if subprocess.check_output(['sudo','docker','ps','-q'],text=True,timeout=20).strip():raise ValueError('A container is active')


def verify_inputs(stage,spec):
 if len(spec['inputs'])!=96:raise ValueError('Expected original96 inputs')
 for name,pin in spec['inputs'].items():
  relative=Path(name);path=stage/'inputs'/relative
  if relative.is_absolute() or '..' in relative.parts or path.resolve(strict=True)!=path or sha(path)!=pin:
   raise ValueError('Original input changed: '+name)
 generator=stage/'inputs/generate_hiddenapi_lists.py'
 if generator.stat().st_mode & 0o777!=0o755:raise ValueError('Original private generator no longer0755')
 snapshot=stage/'cache-lower-before.json'
 if sha(snapshot)!=spec['layered_output']['before_inventory_sha256']:raise ValueError('Original lower snapshot changed')


def apply(stage,newfiles,report,verify):
 backup=stage/'preparation-amendment01';backup.mkdir(mode=0o700)
 for name in ORDER:
  path=stage/name;data=path.read_bytes()
  if digest(data)!=OLD_FILES[name]:raise ValueError('Controller changed before backup: '+name)
  with (backup/name).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  (backup/name).chmod(path.stat().st_mode & 0o7777)
 with (backup/'plan.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
 # Staging first invalidates original controls. New launcher/monitor require
 # matching completion contents; writing the completion marker last commits.
 try:
  for name in ORDER:
   with (stage/name).open('r+b') as f:f.write(newfiles[name]);f.truncate();f.flush();os.fsync(f.fileno())
   with (backup/'applied.jsonl').open('a',encoding='utf-8') as f:
    f.write(json.dumps(dict(file=name,sha256=sha(stage/name)))+'\n');f.flush();os.fsync(f.fileno())
  verify()
  result=dict(report,terminal=True,passed=True,backup=str(backup))
  with (backup/'result.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
  return result
 except BaseException as error:
  with (backup/'failure.json').open('x',encoding='utf-8') as f:
   json.dump(dict(error=str(error),no_automatic_retry=True,originals_preserved=True),f,indent=2);f.write('\n')
  raise


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--packet',type=Path,required=True);a=p.parse_args()
 if os.name!='posix' or (os.geteuid(),os.getegid())!=(1000,1000):raise ValueError('Attested Linux builder1000 required')
 root=a.root.absolute();stage=root/STAGE
 if str(root)!=ROOT or root.resolve(strict=True)!=root or stage.resolve(strict=True)!=stage:raise ValueError('Wrong/symlinked exact stage')
 if (stage/'preparation-amendment01').exists():raise ValueError('Amendment exists; inspect same journal, never repeat')
 no_launch(stage);idle(stage)
 files=read_controls(stage)
 monitor=(a.packet/'tools/monitor_tcl_dialog_ime_disk.py').read_bytes();newfiles,report=plan(files,monitor)
 old=json.loads(files['staging.json'])
 sys.path.insert(0,str(stage));layer=module(stage/'layered_dialog_output.py','amendment_layer')
 layer.verify_external_storage(stage);layer.verify_mounts(stage,old);verify_inputs(stage,old)
 no_launch(stage);idle(stage)
 def verify():
  value=module(stage/'disk-monitor.py','amendment_monitor')
  current=value.load_stage(root,stage);verify_inputs(stage,current)
 result=apply(stage,newfiles,report,verify);print(json.dumps(result))


if __name__=='__main__':main()

"""Freeze resource-only stage controls; never runs host commands or touches phones."""
import argparse
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tcl_scrollbar_build_contract as c
from check_pack_shell_text import smoke

LAYER='034cb1e572c384f32387bb57b87d56a6a6615c97717396b3eb470ddb9f358433'
MONITOR='7c10278d646208509e9f5c44bc512ea47d26a75230d579a723228368cc4cb5e6'
SOURCE='a3e16e71bc75c0f6f286c12ce6b2f74b125efa1f44b4f7bb6a85ad2a90299f84'
PROPOSAL='228448c388086facc1edb2747915977223ad4e1f77e78e2271b589dd3afde679'


def sha(data):return hashlib.sha256(data).hexdigest()


def once(text,old,new):
 if text.count(old)!=1:raise ValueError('Retained infrastructure anchor changed: '+old[:90])
 return text.replace(old,new)


def function(text,name,replacement):
 matches=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name]
 if len(matches)!=1:raise ValueError('Retained function changed: '+name)
 node=matches[0];lines=text.splitlines(True)
 return ''.join(lines[:node.lineno-1])+replacement.rstrip()+'\n'+''.join(lines[node.end_lineno:])


def infrastructure(layer,monitor):
 if sha(layer)!=LAYER or sha(monitor)!=MONITOR:raise ValueError('Wrong frozen native12 lifecycle inputs')
 original_layer=layer.decode().replace('\r\n','\n');original_monitor=monitor.decode().replace('\r\n','\n')
 layer=original_layer
 if layer.count("'tcl-dialog-build[0-9]+'")==2:
  layer=layer.replace("'tcl-dialog-build[0-9]+'",repr(c.NAME))
 else:raise ValueError('Layer stage namespace anchors differ')
 layer=layer.replace('tcl-dialog-build12',c.NAME)
 layer=once(layer,"{'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py'}",
                  "{'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py','tcl_scrollbar_build_contract.py'}")
 monitor=original_monitor
 for name,args in [('load_stage','root,stage'),('verify_inputs','stage,spec'),('validate_container','info,root,stage,cid')]:
  monitor=function(monitor,name,'def '+name+'('+args+'):\n    from tcl_scrollbar_build_contract import '+name+' as resource_check\n    return resource_check('+args+')')
 monitor=once(monitor,'    attempted = False\n','    deadline = time.time()+spec[\'runtime_limit_seconds\']\n    attempted = False\n')
 anchor="        reason='validation_failure' if validation_error is not None else row['breach']"
 monitor=once(monitor,anchor,anchor+"\n        if reason is None and time.time()>deadline:reason='build_deadline'")
 def functions(text):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 def changed(a,b):
  a,b=functions(a),functions(b)
  if a.keys()!=b.keys():raise ValueError('Infrastructure function coverage changed')
  return sorted(n for n in a if a[n]!=b[n])
 delta=dict(layer_functions_changed=changed(original_layer,layer),monitor_functions_changed=changed(original_monitor,monitor),
  original_layer_sha256=LAYER,original_monitor_sha256=MONITOR,
  layer_scope='Only exact resource namespace/storage identity and seven-control set',
  monitor_scope='Three resource-contract hooks and1800sec exact-CID deadline; original observation/stop lifecycle retained')
 if delta['layer_functions_changed']!=['main','owned_stage','storage_layout','verify_mounts'] or delta['monitor_functions_changed']!=['load_stage','monitor_loop','validate_container','verify_inputs']:
  raise ValueError('Unexpected infrastructure function delta')
 return layer.encode(),monitor.encode(),delta


def packet_files(root,proposal,source,native12):
 if sha((proposal/'packet.json').read_bytes())!=PROPOSAL or sha(source.read_bytes())!=SOURCE:
  raise ValueError('Wrong frozen resource proposal/current source acquisition')
 manifest=json.loads((proposal/'packet.json').read_text())
 files={}
 actual={p.relative_to(proposal).as_posix() for p in proposal.rglob('*') if p.is_file()}
 if actual!=set(manifest['files'])|{'packet.json'} or any(p.is_symlink() for p in proposal.rglob('*')):
  raise ValueError('Resource proposal coverage/link drift')
 for name in actual:
  data=(proposal/name).read_bytes()
  if name!='packet.json' and sha(data)!=manifest['files'][name]:raise ValueError('Resource proposal payload drift')
  files['proposal/'+name]=data
 layer,monitor,delta=infrastructure((native12/'layered_dialog_output.py').read_bytes(),(native12/'monitor_tcl_dialog_ime_disk.py').read_bytes())
 files.update({'tools/layered_dialog_output.py':layer,'tools/resource-monitor.py':monitor,
  'proofs/original-layer.py':(native12/'layered_dialog_output.py').read_bytes(),
  'proofs/original-monitor.py':(native12/'monitor_tcl_dialog_ime_disk.py').read_bytes(),
  'proofs/infrastructure-delta.json':(json.dumps(delta,indent=2)+'\n').encode(),
  'proofs/resource-source.json':source.read_bytes()})
 for name in ('tcl_scrollbar_build_contract.py','prepare_tcl_scrollbar_stage.py','build_tcl_scrollbar.sh','reconcile_tcl_scrollbar_build.py'):
  data=(root/'tools'/name).read_bytes().replace(b'\r\n',b'\n')
  if b'\r' in data:raise ValueError('Noncanonical execution text')
  files['tools/'+name]=data
 return files,delta


def main():
 root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--proposal',type=Path,default=root/'work/tcl-scrollbar-build-proposal02')
 p.add_argument('--source',type=Path,default=root/'work/tcl-scrollbar-current-source01/resource-inventory01.json')
 p.add_argument('--native12-tools',type=Path,default=root/'work/tcl-app-widgets-build-packet12-03/tools')
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 files,delta=packet_files(root,a.proposal,a.source,a.native12_tools)
 from prepare_tcl_scrollbar_stage import launcher
 bash=Path('bash') if os.name=='nt' else Path('/bin/bash')
 launch=launcher(c.ROOT/c.NAME,[0,1]).encode()
 files['proofs/launch-template.sh']=launch
 files['proofs/shell-smoke.json']=(json.dumps(dict(build=smoke(files['tools/build_tcl_scrollbar.sh'],bash),launch_template=smoke(launch,bash)),indent=2)+'\n').encode()
 files['packet.json']=(json.dumps(dict(kind='tcl-scrollbar-execution01',stage=c.NAME,backing=c.BACKING,
  source_resource_inventory_sha256=SOURCE,resource_proposal_sha256=PROPOSAL,
  baseline_framework_res_sha256=c.BASE,resource_export=['framework/framework-res.apk'],
  files={n:sha(b) for n,b in sorted(files.items())},host_execution_owner='hardware chat',
  host_staged=False,compiler_launched=False,installed=False,full_parity=False),indent=2)+'\n').encode()
 a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 from prepare_tcl_scrollbar_stage import packet_check
 packet_check(a.output.resolve(),sha(files['packet.json']))
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as raw:
  with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as zipped:
   with tarfile.open(fileobj=zipped,mode='w') as tar:
    for name,data in sorted(files.items()):
     member=tarfile.TarInfo(name);member.mode=0o644;member.size=len(data);tar.addfile(member,io.BytesIO(data))
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  if len(members)!=len(files) or {m.name for m in members}!=files.keys():raise ValueError('Execution archive coverage differs')
  for m in members:
   if not m.isfile() or m.mode!=0o644 or tar.extractfile(m).read()!=files[m.name]:raise ValueError('Execution archive bytes/types/modes differ')
  archived_shell=smoke(tar.extractfile('tools/build_tcl_scrollbar.sh').read(),bash)
  archived_launch=smoke(tar.extractfile('proofs/launch-template.sh').read(),bash)
 code="import importlib.util,json,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import prepare_tcl_scrollbar_stage as stage;stage.packet_check(Path(sys.argv[2]),sys.argv[3]);s=importlib.util.spec_from_file_location('resource_monitor',Path(sys.argv[1])/'resource-monitor.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps({'isolated_imports_passed':True}))"
 result=subprocess.run([sys.executable,'-I','-B','-c',code,str((a.output/'tools').resolve()),str(a.output.resolve()),sha(files['packet.json'])],capture_output=True,timeout=30)
 result.check_returncode()
 report=dict(packet=str(a.output),packet_sha256=sha(files['packet.json']),archive_sha256=sha(archive.read_bytes()),
  archive_bytes_types_and_modes_verified=True,archive_build_shell=archived_shell,archive_launch_template=archived_launch,isolated_imports=json.loads(result.stdout),infrastructure_delta=delta,
  host_staged=False,compiler_launched=False)
 Path(str(a.output)+'.verification.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
 print(json.dumps(report))


if __name__=='__main__':main()

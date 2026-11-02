"""Freeze isolated native13 from reviewed native12; never stage or launch host jobs."""
import argparse
import ast
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from prepare_tcl_ime_handover import sources,once
from prepare_tcl_ime_handover_flags import sha
from check_pack_shell_text import smoke

PACKET12='b8d873dcaf0ed75946670efbf5241a1ee7480519181171167c9fd97dcfa6889d'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
FLAGS='faf76189eda12b26f695f62bd7ac215fbe00ec5e2e8895046f0ab4599f9a48a8'
PREDICTION='80e0ce14b29a7a1272a7c5cceee594b993eda1659a34933c9dc88f0700e0a631'
REVIEW='a780e970acc7ad915576e95583294d6b1ccbf8ddeeda49eb409da11b4fc291f4'

RETAINED12='''
def retained12(root):
    import importlib.util
    import sys
    previous=root/'tcl-dialog-build12';recovery=previous/'export-recovery01'
    pins={
      'staging.json':'794416e1fdc169b1374010c0550f1ea51d45eedc65f3c669bb64de06045a3600',
      'control-inputs.json':'9a4bea5999ebdfbff17baf554d0937739e6a4a90ab161dfe24be1e1e2b3decd4',
      'cache-preservation.json':'04b1802f3503e808c8218f18b3bc6b908b2377bcb7b360d1a91b2e2bee445907',
      'export-recovery01/outputs.json':'16d578f19e384fd4e922b1f913f7f1e1637b2318ad54169fdb756b6ebe4ffed1',
      'export-recovery01/compiled-audit.json':'a780e970acc7ad915576e95583294d6b1ccbf8ddeeda49eb409da11b4fc291f4',
      'export-recovery01/recovery.json':'1def8a52b57e955a28ce1f9097130a230083bfab2b2f4ad5ca2d90b750f26c12',
      'out/soong/hiddenapi/hiddenapi-flags.csv':'d1c91728e194307c40157dc10c9c0e72ff31804a83ab2c407adbb6195764dc15'}
    for name,pin in pins.items():
        path=previous/name
        if path.resolve(strict=True)!=path or sha(path)!=pin:raise ValueError('Retained12 proof changed: '+name)
    controls=json.loads((previous/'control-inputs.json').read_text())
    for name,pin in controls.items():
        if (previous/name).is_symlink() or sha(previous/name)!=pin:raise ValueError('Retained12 control changed')
    layer_spec=importlib.util.spec_from_file_location('retained12_layer',previous/'layered_dialog_output.py')
    old_layer=importlib.util.module_from_spec(layer_spec);layer_spec.loader.exec_module(old_layer)
    active_layer=sys.modules.get('layered_dialog_output')
    try:
        sys.modules['layered_dialog_output']=old_layer
        module_spec=importlib.util.spec_from_file_location('retained12_monitor',previous/'disk-monitor.py')
        monitor=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(monitor)
        staged=monitor.load_stage(root,previous);monitor.verify_inputs(previous,staged)
    finally:
        if active_layer is None:sys.modules.pop('layered_dialog_output',None)
        else:sys.modules['layered_dialog_output']=active_layer
    cid='d463b0b93294f6d65712d46702eac3bb15b18a4c94f4714560489901c5a93aa3'
    info=json.loads(subprocess.check_output(['sudo','-n','docker','inspect',cid],text=True))[0]
    monitor.validate_container(info,root,previous,cid);state=info.get('State',{})
    if state.get('Status')!='exited' or state.get('Running') is not False or state.get('Pid')!=0 or state.get('ExitCode')!=1 or state.get('OOMKilled') is not False or (previous/'build.exit').read_text().strip()!='1' or (previous/'container-id').read_text().strip()!=cid:
        raise ValueError('Original12 failed export receipt or terminal identity differs')
    reviewed=json.loads((recovery/'compiled-audit.json').read_text());restored=json.loads((recovery/'recovery.json').read_text())
    cache=json.loads((previous/'cache-preservation.json').read_text());exports=json.loads((recovery/'outputs.json').read_text())['files']
    if reviewed.get('full_acceptance') is not True or restored.get('passed') is not True or restored.get('compiler_restarted') is not False or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('lower_entries')!=565530 or cache.get('projected_removed_entries')!=[] or len(exports)!=30 or exports.get('framework/framework.jar')!='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054':
        raise ValueError('Accepted native12 recovery/review/cache/exports differ')
    pins.update(controls);pins.update({'inputs/'+n:d for n,d in staged['inputs'].items()})
    pins.update({'export-recovery01/output/'+n:d for n,d in exports.items()})
    for name,pin in pins.items():
        path=previous/name
        if path.resolve(strict=True)!=path or sha(path)!=pin:raise ValueError('Retained12 bytes changed: '+name)
    return {(previous/n).relative_to(root).as_posix():d for n,d in pins.items()}

'''

def packet_files(root,packet12,prediction):
 manifest=(packet12/'packet.json').read_bytes()
 if sha(manifest)!=PACKET12 or sha(prediction.read_bytes())!=PREDICTION:raise ValueError('Frozen native12/prediction identity differs')
 old=json.loads(manifest);files={}
 actual={p.relative_to(packet12).as_posix() for p in packet12.rglob('*') if p.is_file()}
 if actual!=set(old['files'])|{'packet.json'} or any(p.is_symlink() for p in packet12.rglob('*')):raise ValueError('Frozen12 coverage/link differs')
 for name,pin in old['files'].items():
  data=(packet12/name).read_bytes()
  if sha(data)!=pin:raise ValueError('Frozen12 payload changed: '+name)
  files[name]=data.replace(b'tcl-dialog-build12',b'tcl-dialog-build13') if name.startswith('tools/') else data
 delta=sources(packet12/'overlay/core/java/android/widget')
 for name,data in delta.items():files['overlay/core/java/android/widget/'+name]=data
 if {n for n in old['files'] if n.startswith('overlay/') and sha(files[n])!=old['files'][n]}!={'overlay/core/java/android/widget/'+n for n in delta}:raise ValueError('More than two source units changed')
 proof=(root/'docs/evidence/tcl-app-widgets-native12-parent-review01.json').read_bytes()
 if sha(proof)!=REVIEW:raise ValueError('Parent native12 review identity differs')
 files['proofs/native12-parent-review.json']=proof;files['proofs/native13-hiddenapi-prediction.json']=prediction.read_bytes()
 files['proofs/native12-packet.json']=manifest
 files['proofs/handover-sdk.json']=(root/'docs/evidence/tcl-ime-handover-sdk01.json').read_bytes()
 pending=['audit_tcl_ime_handover.py','prepare_tcl_ime_handover.py','prepare_tcl_ime_handover_flags.py'];seen=set()
 while pending:
  name=pending.pop()
  if name in seen:continue
  seen.add(name);data=(root/'tools'/name).read_bytes().replace(b'\r\n',b'\n');files['audit/'+name]=data
  for node in ast.walk(ast.parse(data)):
   imported=([node.module] if isinstance(node,ast.ImportFrom) and node.module else [a.name for a in node.names] if isinstance(node,ast.Import) else [])
   for value in imported:
    candidate=value+'.py'
    if (root/'tools'/candidate).is_file():pending.append(candidate)
 key='tools/prepare_tcl_ime_picker_build.py';prep=files[key].decode()
 prep=once(prep,'GIB=1024**3','POLICY.update('+repr({'core/java/android/widget/'+n:sha(d) for n,d in delta.items()})+')\nGIB=1024**3')
 prep=once(prep,'def prepare(root,overlay,stage):',RETAINED12+'def prepare(root,overlay,stage):')
 prep=once(prep,'    accepted_pins.update(retained11(root,overlay))','    accepted_pins.update(retained11(root,overlay))\n    accepted_pins.update(retained12(root))')
 anchor="    if len(inputs)!=98:raise ValueError('Expected exact98 source inputs')"
 prep=once(prep,anchor,anchor+'''
    prior12=json.loads((root/'tcl-dialog-build12/staging.json').read_text())['inputs']
    if set(inputs)!=set(prior12) or {n for n in inputs if inputs[n]!=prior12[n]}!={'KeypadImeController.java','KeypadImeModeState.java'}:
        raise ValueError('Native13 source input delta exceeds two reviewed units')''')
 prep=once(prep,"accepted_framework_baseline='a5f20e01980dbc5a7ea71f883b24d7f77d2781b2407fda9aa0e298f7c4490330'","accepted_framework_baseline='"+FRAMEWORK+"'")
 prep=once(prep,'builder_identity=dict(image_id=IMAGE,image_user=\'builder\',uid=1000,gid=1000),',"builder_identity=dict(image_id=IMAGE,image_user='builder',uid=1000,gid=1000),runtime_limit_seconds=1800,")
 files[key]=prep.encode()
 key='tools/prepare_tcl_dialog_build.py';launch=files[key].decode()
 launch=once(launch,'--network none','--network none --user builder --cpus 2 --memory 8g --memory-swap 8g --pids-limit 512')
 files[key]=launch.encode()
 key='tools/monitor_tcl_dialog_ime_disk.py';monitor=files[key].decode()
 monitor=once(monitor,"    builder=spec.get('builder_identity')\n    if builder:\n        owner=stage.stat()","    if spec.get('runtime_limit_seconds')!=1800:raise ValueError('Native13 deadline differs')\n    builder=spec.get('builder_identity')\n    if builder:\n        owner=stage.stat()")
 anchor="    spec=json.loads((stage/'staging.json').read_text())\n    builder=spec.get('builder_identity')"
 monitor=once(monitor,anchor,"""    spec=json.loads((stage/'staging.json').read_text())
    host=info.get('HostConfig',{})
    if host.get('Memory')!=8*GIB or host.get('MemorySwap')!=8*GIB or host.get('NanoCpus')!=2000000000 or host.get('PidsLimit')!=512:
        raise ValueError('Native13 resource caps differ')
    if info.get('Config',{}).get('Cmd')!=['bash','/build/'+stage.name+'/build.sh']:
        raise ValueError('Native13 build command differs')
    builder=spec.get('builder_identity')""")
 monitor=once(monitor,'    attempted = False\n',"    deadline=time.time()+spec['runtime_limit_seconds']\n    attempted = False\n")
 anchor="        reason='validation_failure' if validation_error is not None else row['breach']"
 monitor=once(monitor,anchor,anchor+"\n        if reason is None and time.time()>deadline:reason='build_deadline'")
 files[key]=monitor.encode()
 key='tools/build_tcl_ime_picker.sh';build=files[key].decode().replace('-j4','-j2')
 build=once(build,'set -eo pipefail','set -euo pipefail')
 build=once(build,'source build/envsetup.sh','set +u # Retain AOSP envsetup optional-variable behavior.\nsource build/envsetup.sh')
 build=once(build,"'6a9d085640be47d5d8a3409e102e422d2dde0cfa964409362a6881ee2ce61d8e'",repr(FLAGS))
 build=once(build,"assert sha(product/'framework/framework.jar')!=m['before_closure']['framework/framework.jar']","assert sha(product/'framework/framework.jar')!=m['before_closure']['framework/framework.jar']\nassert sha(product/'framework/framework.jar')!=m['accepted_framework_baseline'],'No new handover framework'")
 anchor=" assert any(b'Landroid/widget/KeypadImePicker$StyledImeRow;' in b for b in dex),'App-selector row helper missing'"
 build=once(build,anchor,anchor+"\n assert any(b'Landroid/widget/KeypadImeController$3;' in b and b'ownershipGeneration' in b and b'queueSelection' in b for b in dex),'New handover class/policy missing'")
 build=build.replace('retained-plus-eight-private-API','retained12-plus23-members-one-inherited-Runnable')
 build=once(build,"scope='Native11 Kika footer geometry; four native10 Java inputs and generator retained; compile cache48; future pack separate'","scope='Native13 picker/editor handover; exact two-unit delta over accepted12; cache48; audit/pack separate'")
 files[key]=build.encode()
 for name,data in files.items():
  if name.startswith(('tools/','audit/')) and name.endswith(('.py','.sh')) and b'\r' in data:raise ValueError('Executable text is not canonical LF')
  if name.endswith('.py'):ast.parse(data,filename=name,feature_version=(3,8))
 return files

def retry14_files(files):
 """New stage, identical payloads; raise only the proven insufficient RAM cap."""
 result=dict(files)
 for name,data in files.items():
  if name.startswith('tools/'):
   result[name]=data.replace(b'tcl-dialog-build13',b'tcl-dialog-build14')
 key='tools/prepare_tcl_dialog_build.py'
 result[key]=once(result[key].decode(),'--memory 8g --memory-swap 8g','--memory 32g --memory-swap 32g').encode()
 key='tools/monitor_tcl_dialog_ime_disk.py'
 result[key]=once(result[key].decode(),"host.get('Memory')!=8*GIB or host.get('MemorySwap')!=8*GIB","host.get('Memory')!=32*GIB or host.get('MemorySwap')!=32*GIB").encode()
 return result


def main():
 root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--native12-packet',type=Path,default=root/'work/tcl-app-widgets-build-packet12-03')
 p.add_argument('--prediction',type=Path,default=root/'work/tcl-ime-handover-flags01/prediction.json');p.add_argument('--output',type=Path,required=True)
 p.add_argument('--retry14',action='store_true',help='Fresh build14 with32GiB cap; preserve failed13 unchanged')
 a=p.parse_args()
 files=packet_files(root,a.native12_packet,a.prediction)
 if a.retry14:files=retry14_files(files)
 bash=Path('bash') if os.name=='nt' else Path('/bin/bash')
 shell=smoke(files['tools/build_tcl_ime_picker.sh'],bash)
 manifest=dict(scope='Frozen isolated native13 framework handover compile; no host execution',stage='tcl-dialog-build13',backing='/mnt/ext1/kaidroid-tcl-dialog-build13',native_audit_baseline=FRAMEWORK,
  native12_packet_sha256=PACKET12,native12_parent_review_sha256=REVIEW,source_delta=['KeypadImeController.java','KeypadImeModeState.java'],
  generated_csv_sha256=FLAGS,retained_csv_rows=429770,added_csv_rows=23,new_blacklist_rows=22,new_inherited_runnable_rows=1,
  predicted_changed_methods=5,predicted_added_methods=15,predicted_removed_methods=0,all30_exports_required=True,source_inputs=98,
  cpu=2,memory_bytes=8*1024**3,pids_limit=512,runtime_limit_seconds=1800,root_and_external_floor_bytes=20*1024**3,external_growth_bytes=14*1024**3,
  shell_smoke=shell,modes={n:0o755 if n.startswith('hiddenapi-generator/') else 0o644 for n in files},files={n:sha(d) for n,d in sorted(files.items())},host_staged=False,launched=False,installed=False,full_parity=False)
 if a.retry14:
  manifest.update(stage='tcl-dialog-build14',backing='/mnt/ext1/kaidroid-tcl-dialog-build14',memory_bytes=32*1024**3,
   scope='Fresh native13 retry in stage14; identical Android sources and audit;32GiB memory cap',
   failed_prior_container='2aa86f672f56482c21c12ad7bfbd9331aaf36227aebe76b8a57a437e0515fede')
 files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode();a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as raw:
  with gzip.GzipFile(fileobj=raw,filename='',mode='wb',mtime=0) as zipped:
   with tarfile.open(fileobj=zipped,mode='w') as tar:
    for name,data in sorted(files.items()):
     info=tarfile.TarInfo(name);info.mode=manifest['modes'].get(name,0o644);info.size=len(data);tar.addfile(info,io.BytesIO(data))
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  if len(members)!=len(files) or {m.name for m in members}!=files.keys():raise ValueError('Archive coverage differs')
  for m in members:
   if not m.isfile() or m.mode!=manifest['modes'].get(m.name,0o644) or tar.extractfile(m).read()!=files[m.name]:raise ValueError('Archive type/mode/bytes differ')
 code="import sys,json;sys.path.insert(0,sys.argv[1]);import audit_tcl_ime_handover;sys.path.insert(0,sys.argv[2]);import prepare_tcl_ime_picker_build;print(json.dumps({'frozen_audit_and_prepare_imports_passed':True}))"
 result=subprocess.run([sys.executable,'-I','-B','-c',code,str((a.output/'audit').resolve()),str((a.output/'tools').resolve())],capture_output=True,timeout=30)
 result.check_returncode()
 report=dict(packet=str(a.output),packet_sha256=sha(files['packet.json']),archive_sha256=sha(archive.read_bytes()),all_archive_bytes_modes_types_verified=True,build_shell_smoke=shell,isolated_imports=json.loads(result.stdout),host_staged=False,launched=False)
 Path(str(a.output)+'.verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()

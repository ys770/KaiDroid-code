"""Prepare fresh external native10 packet: frozen09 Java, exact two raw16 API flags."""
import argparse
import ast
import gzip
import io
import json
from pathlib import Path
import tarfile

import prepare_tcl_dialog_adapter_build_packet as prior
from prepare_tcl_dialog_hiddenapi_candidate import source,BASE,SIGNATURES
from audit_tcl_dialog_hiddenapi10 import GENERATOR

# Historical packet10 prediction: Windows simulation wrote CRLF. Keep frozen
# reproduction exact; Linux9926 recovery/audit is separately reviewed.
GENERATED_FLAGS='ee6e5fe650ac2a63fceab4b422fcf527b4758c9f85a6291e7ca8b0a8487a6de5'

FRAMEWORK09='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
AUX='generate_hiddenapi_lists.py'
SOURCE='aosp/frameworks/base/tools/hiddenapi/'+AUX
DEST='/build/'+SOURCE
GREYLIST='a6a42954cbec5e71db9c9f8b59b87b155c6b38f4f65b08137a3b8d06821657cc'

RETAINED09=prior.RETAINED08
for old,new in {
 'retained08':'retained09','Retained08':'Retained09','tcl-dialog-build08':'tcl-dialog-build09',
 'e19fbd2355e262bac4706ea5c4d663c442c6e45f0e88cb4bec3d73804427a889':'7906f73642bf9dc8e34c5ebe420c90db3ac0e7dab8c4e2c0234690ff5771dfa3',
 'daac9ca0d3b950604041ba7a352fe026c6bddd48d409771f0fd1639c77b7f067':'a6df424e87b68c89dee426344304fdf9ffc6927fa2b977a33d5f00ad50f5a264',
 '6be37ca14c1af60ba023344fe2cbe2a79d9f31a077d01c18c689b947cf97e62b':'7b72f5d7f8b819d8c1c6e70c04d4791b647fc1f3f78fdbd65047b46ccd42a3d0',
 '259ae484f1b5097a63720e1b400d38b41fca39cfd9f0fd6a5ff35b06c92dcafd':'e155e8859371b572945f453696776850349b823590cc33d4617ae9168ff0650d',
 prior.FRAMEWORK08:FRAMEWORK09,
}.items():
 if old not in RETAINED09:raise ValueError('Frozen09 proof template changed: '+old)
 RETAINED09=RETAINED09.replace(old,new)

RETAINED54=prior.RETAINED53
for old,new in {
 'retained53':'retained54','Retained53':'Retained54',
 'engineering-tcl-ime-guard-stage-53':'engineering-tcl-calendar-adapter-stage-54',
 '80b7d658f07773e709f567e2279fd9ab521a92331425f7e955a174412f566ffe':'4dc7567d7ef1119c290d6d21b1a158bfd2aa75339ac65ae0e59ac169e3701f80',
 '4ed37c11ee869bc85c2d8a993126311326438778625feb85e8a75a601d7b8dea':'bb24aa37af9ec27465b798454daaeb4784b054373e3deef31ad568e8835615f6',
 'f587f445ce66e397718110762c7e952fcb19c03feef4b1ae35c7638209c51f56':'b53162ebca3a11fd57e3d99ba7d4c9998130ddefdcf90be085995bcf9829fcd8',
 'ae336c7500bb892b219f1bbbea2e12ccb5fa50121ae4a7d03607dd2ea158fe2f':'9d72a8fd1f9411b1dcc7e476d20af4ec748eb280d6999546f004f188cfe64f7d',
 '7eb4ac9515976d201e7dc0a217494d225189616805f5beca9a3eb9466dcb7d7b':'f0d13f9999fda447e8ea98b8ecee740af48d6b73e07a59dc4c73b2fbce3fc481',
 prior.FRAMEWORK08:FRAMEWORK09,
 'kaidroid-tcl-ime-guard-image53':'kaidroid-tcl-calendar-adapter-image54',
}.items():
 if old not in RETAINED54:raise ValueError('Frozen54 proof template changed: '+old)
 RETAINED54=RETAINED54.replace(old,new)
RETAINED54=RETAINED54.replace("    pins={\n","    pins={\n        'outputs.json':'d773f1967c0a0312bc68a130e5774cc3441b53edfe51d5a15e71930c5a8cd4cd',\n")


def auxiliary_info():
 return dict(input=AUX,source=SOURCE,original_sha256=BASE,candidate_sha256=GENERATOR,mode=0o755)


def packet_files(root):
 for name,pin in {
  'prepare_tcl_dialog_adapter_build_packet.py':'b93e27e58a1c374e9751457a4894c2d5beb804895d4c355531796ff4e38bcdfa',
  'tcl_dialog_external_storage.py':'c8d41bfde094ecbd574a33b7220b0ddc6cb2c139817db1804f7ca5de2e0166b9',
 }.items():
  if prior.frozen.sha((root/'tools'/name).read_bytes())!=pin:raise ValueError('Frozen09 packet dependency changed: '+name)
 files=prior.packet_files(root);replace=prior.frozen.replace_once
 generator=source((root/'tests/fixtures/generate_hiddenapi_lists_original01.py').read_bytes())
 if prior.frozen.sha(generator)!=GENERATOR:raise ValueError('Exact generator candidate changed')
 files['hiddenapi-generator/'+AUX]=generator
 key='tools/prepare_tcl_ime_picker_build.py';prep=files[key].decode()
 prep=replace(prep,"stage!=root/'tcl-dialog-build09'","stage!=root/'tcl-dialog-build10'")
 prep=replace(prep,"backing='/mnt/ext1/kaidroid-tcl-dialog-build09'","backing='/mnt/ext1/kaidroid-tcl-dialog-build10'")
 prep=replace(prep,'def prepare(root,overlay,stage):',RETAINED09+RETAINED54+'\ndef prepare(root,overlay,stage):')
 prep=replace(prep,'    accepted_pins.update(retained53(root))',
  '    accepted_pins.update(retained53(root))\n    accepted_pins.update(retained09(root))\n    accepted_pins.update(retained54(root))\n'+
  '    original_generator=root/'+repr(SOURCE)+'\n'+
  '    if sha(original_generator)!='+repr(BASE)+" or original_generator.stat().st_mode & 0o777 != 0o755:raise ValueError('Original executable generator changed')\n"+
  '    accepted_pins['+repr(SOURCE)+']='+repr(BASE)+'\n'+
  "    accepted_pins['aosp/frameworks/base/config/hiddenapi-greylist.txt']="+repr(GREYLIST))
 prep=replace(prep,"accepted_framework_baseline='"+prior.FRAMEWORK08+"'","accepted_framework_baseline='"+FRAMEWORK09+"'")
 marker="    if changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java','KeypadImeModeState.java'}:raise ValueError('Unexpected source input delta')"
 prep=replace(prep,marker,marker+'\n'+
  "    auxiliary=overlay.parent/'hiddenapi-generator'/"+repr(AUX)+'\n'+
  '    if auxiliary.resolve(strict=True)!=auxiliary or sha(auxiliary)!='+repr(GENERATOR)+":raise ValueError('Exact private generator input changed')\n"+
  "    shutil.copyfile(auxiliary,stage/'inputs'/"+repr(AUX)+')\n'+
  "    (stage/'inputs'/"+repr(AUX)+').chmod(0o755)  # New private copy only; never chmod shared source.\n'+
  '    inputs['+repr(AUX)+"] = sha(stage/'inputs'/"+repr(AUX)+')')
 prep=replace(prep,'        external_storage=dict(', '        hiddenapi_generator='+repr(auxiliary_info())+',\n        external_storage=dict(')
 marker="    launch=launcher_source(root,stage,bind,True,staging_sha,stage/'out')"
 extra=' -v "$stage/inputs/'+AUX+':'+DEST+':ro" \\\n'
 prep=replace(prep,marker,'    bind+='+repr(extra)+'\n'+marker)
 prep=replace(prep,'    return launch',
  '    completion_check=\'test "$(cat "$stage/preparation.complete")" = "\'+staging_sha+\'"\'\n'+
  '    launch=launch.replace(\'test -f "$stage/preparation.complete"\',\'test -f "$stage/preparation.complete"\\n\'+completion_check,1)\n'+
  '    return launch')
 files[key]=prep.encode()

 key='tools/layered_dialog_output.py'
 layer=files[key].decode().replace('tcl-dialog-build09','tcl-dialog-build10')
 files[key]=layer.encode()
 key='tools/monitor_tcl_dialog_ime_disk.py';monitor=files[key].decode()
 marker="    spec = json.loads((stage/'staging.json').read_text())\n    builder=spec.get('builder_identity')"
 monitor=replace(monitor,marker,"    spec = json.loads((stage/'staging.json').read_text())\n"+
  "    if (stage/'preparation.complete').read_text().strip()!=sha(stage/'staging.json'):raise ValueError('Preparation completion hash mismatch')\n"+
  "    storage=spec.get('external_storage',{})\n"+
  "    if storage.get('volume')!='/mnt/ext1' or storage.get('backing')!='/mnt/ext1/kaidroid-tcl-dialog-build10' or storage.get('device')!='8:0' or storage.get('root_floor_bytes')!=20*GIB or type(storage.get('root_initial_free_bytes')) is not int or storage['root_initial_free_bytes']<=20*GIB:raise ValueError('External storage metadata does not match exact physical stage')\n"+
  '    if spec.get(\'hiddenapi_generator\')!='+repr(auxiliary_info())+":raise ValueError('Unreviewed auxiliary generator metadata')\n"+
  "    auxiliary=stage/'inputs'/"+repr(AUX)+'\n'+
  '    if auxiliary.is_symlink() or sha(auxiliary)!='+repr(GENERATOR)+" or auxiliary.stat().st_mode & 0o777 != 0o755:raise ValueError('Private executable generator changed')\n"+
  "    builder=spec.get('builder_identity')")
 marker="    actual = {}"
 monitor=replace(monitor,marker,'    expected['+repr(DEST)+"]=(str(stage/'inputs'/"+repr(AUX)+'),False)\n'+marker)
 files[key]=monitor.encode()

 key='tools/build_tcl_ime_picker.sh';build=files[key].decode()
 marker="for n,d in m['overlay'].items():assert sha(Path('/build/aosp/frameworks/base')/n)==d,n"
 build=replace(build,marker,marker+'\n'+
  'generator=Path('+repr(DEST)+')\n'+
  'assert sha(generator)=='+repr(GENERATOR)+",'Private generator source not bound'\n"+
  "assert generator.stat().st_mode & 0o777 == 0o755,'Private generator not executable'")
 marker='# Hardware reviews the actual plan/hash while this same container waits.'
 plan="""python3 - "$stage" <<'PY'
import hashlib,json,re,sys
from pathlib import Path
s=Path(sys.argv[1]);source='frameworks/base/tools/hiddenapi/generate_hiddenapi_lists.py'
graph=Path('/build/out-eng-02/soong/build.ninja').read_text().replace('$\\n','')
edges=[b for b in re.split(r'(?m)^(?=build )',graph) if 'soong/hiddenapi/hiddenapi-flags.csv:' in b.split('\\n',1)[0] and source in b]
assert len(edges)==1,'Actual private graph must depend on exact source generator'
text=(s/'dependency-plan.log').read_text()
commands=[line for line in text.splitlines() if source in line and '--output' in line and 'hiddenapi-flags.csv' in line]
assert commands,'Actual plan must regenerate CSV through private source; no stale flags/binary shortcut'
(s/'hiddenapi-plan.json').write_text(json.dumps(dict(source=source,edge=edges[0].split('\\n',1)[0],commands=commands,
 actual_plan_sha256=hashlib.sha256((s/'dependency-plan.log').read_bytes()).hexdigest()),indent=2)+'\\n')
PY
"""
 build=replace(build,marker,plan+marker)
 marker="assert sha(product/'framework/framework.jar')!=m['before_closure']['framework/framework.jar']"
 build=replace(build,marker,marker+'\n'+
  "flags=Path('/build/out-eng-02/soong/hiddenapi/hiddenapi-flags.csv')\n"+
  'assert sha(flags)=='+repr(GENERATED_FLAGS)+",'Full generated flags differ from exact two-row prediction'\n"+
  "shutil.copyfile(flags,s/'hiddenapi-flags.csv')")
 build=replace(build," plan_review_sha256=sha(s/'plan-review.json'),",
  " plan_review_sha256=sha(s/'plan-review.json'),hiddenapi_generated_flags_sha256=sha(s/'hiddenapi-flags.csv'),\n"+
  ' hiddenapi_generator_sha256='+repr(GENERATOR)+',')
 build=build.replace('Native51 picker correction only; compile cache48, future image baseline separately reviewed',
  'Native10 exact adapter whitelist/test-api flags only; Java frozen09, compile cache48; future image baseline separately reviewed')
 files[key]=build.encode()
 for name,data in files.items():
  if name.endswith('.py'):ast.parse(data,filename=name,feature_version=(3,10))
 if {n[8:]:prior.frozen.sha(b) for n,b in files.items() if n.startswith('overlay/')}!=prior.INPUTS:
  raise ValueError('Frozen09 four Java source bytes changed')
 return files


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];files=packet_files(root)
 manifest=dict(scope='Offline native10 packet; hardware owns fresh external mount/preparation/actual plan/launch',
  stage='tcl-dialog-build10',backing='/mnt/ext1/kaidroid-tcl-dialog-build10',native_audit_baseline=FRAMEWORK09,
  unchanged_java_inputs=prior.INPUTS,hiddenapi_generator=auxiliary_info(),generated_csv_sha256=GENERATED_FLAGS,
  exact_flag_changes={n:dict(before=2,after=16) for n in sorted(SIGNATURES)},
  retained_native09_and_image54=True,total_container_binds=13,control_files=6,
  external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,external_floor_bytes=20*1024**3,root_floor_bytes=20*1024**3,
  modes={n:(0o755 if n=='hiddenapi-generator/'+AUX else 0o644) for n in files},
  files={n:prior.frozen.sha(b) for n,b in sorted(files.items())},source_generator_regeneration_required=True,
  binary_patch_allowed=False,global_runtime_policy_changed=False,stubs_changed=False,
  symbols_inset_candidate_included=False,launched=False,installed=False)
 files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for name,data in sorted(files.items()):
     info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755 if name=='hiddenapi-generator/'+AUX else 0o644
     tar.addfile(info,io.BytesIO(data))
 print(json.dumps(dict(packet=str(a.output),archive=str(archive),sha256=prior.frozen.sha(archive.read_bytes()),launched=False)))


if __name__=='__main__':main()

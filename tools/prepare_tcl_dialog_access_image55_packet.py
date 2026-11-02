"""Freeze image55 tools and observed native10 export-recovery proofs locally; never launch."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import stage_tcl_dialog_access_image55 as stage

PINS={
 'stage_tcl_dialog_access_image55.py':'d062d44b7b433fdcc2a9bdc285964ed2d498fa525209aa91f453cc0e366c537c',
 'build_tcl_dialog_access_image55.sh':'03600d5aa0ebf33e5373b28fac54714d691e6d8bcac21dca83fffe827af2b978',
 'verify_image55_closure.py':'1f6ecc00798d2788f6db850458301b1038696c164bbd3fed9121cc3ee137bb63',
}


def packet_files(root,audit,recovery):
 stage.require_observed_pins();files={}
 for name,pin in PINS.items():
  path=root/'tools'/name
  if path.is_symlink() or stage.sha(path)!=pin:raise ValueError('Frozen55 tool changed: '+name)
  files['tools/'+name]=path.read_bytes()
 for path,name,pin,validate in [(audit,'compiled-audit.json',stage.AUDIT_RAW,stage.validate_audit),
                                (recovery,'recovery-proof.json',stage.RECOVERY_RAW,stage.validate_recovery_review)]:
  if path.is_symlink() or stage.sha(path)!=pin:raise ValueError('Observed10 recovery proof changed: '+name)
  validate(json.loads(path.read_text(encoding='utf-8')));files[name]=path.read_bytes()
 manifest=dict(image=55,baseline_image=54,base_stage=stage.BASE_NAME,stage=stage.STAGE_NAME,
  base_raw_sha256=stage.BASE_RAW,base_manifest_sha256=stage.BASE_MANIFEST,base_outputs_sha256=stage.BASE_OUTPUTS,
  compiled_stage=stage.COMPILED,compiled_framework_sha256=stage.FRAMEWORK,compiled_manifest_sha256=stage.COMPILE_STAGE,
  compiled_outputs_sha256=stage.EXPORT,compiled_cache_proof_sha256=stage.CACHE_PROOF,
  original_compile_exit_code=1,export_only_recovery=True,compiled_terminal_container_id=stage.COMPILED_CID,expected_changed_files=sorted(stage.EXPECTED_CHANGED),
  retained_systemui_camera_runtime_labels_providers_alarms_art=True,optional_fec=False,signed_hashtree_required=True,
  files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())},
  hardware_review_and_host_reservation_required=True,image_staged=False,image_built=False,installed=False,
  symbols_30px_layout_fix_included=False,full_parity=False)
 files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 return files


def main():
 p=argparse.ArgumentParser(description=__doc__);root=Path(__file__).resolve().parents[1]
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--audit',type=Path,default=root/'work/tcl-hiddenapi10-native-audit01/result.json')
 p.add_argument('--recovery-proof',type=Path,default=root/'work/tcl-hiddenapi10-export-recovery01/recovery.json')
 a=p.parse_args();files=packet_files(root,a.audit,a.recovery_proof)
 a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  target=a.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for name,data in sorted(files.items()):
     info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
 print(json.dumps(dict(packet=str(a.output),archive=str(archive),sha256=stage.sha(archive),launched=False)))


if __name__=='__main__':main()

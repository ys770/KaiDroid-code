"""Freeze image54 tools and exact observed native09 proofs locally; never launch."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import stage_tcl_calendar_adapter_image54 as stage

PINS={
 'stage_tcl_calendar_adapter_image54.py':'555620dd3b99bfbbafda871aee551588598da5cd236eb0066af1228680320589',
 'build_tcl_calendar_adapter_image54.sh':'e0ff283c8e0d4aa4e021b041484de99c2fa37bf4b8b86e8e2657595e2567eb9e',
 'verify_image54_closure.py':'de72b64575edbe417e346c65d27394d674d5865625547ec49103c7d6340d70b7',
}


def packet_files(root,audit,body):
 stage.require_observed_pins();files={}
 for name,pin in PINS.items():
  path=root/'tools'/name
  if path.is_symlink() or stage.sha(path)!=pin:raise ValueError('Frozen54 tool changed: '+name)
  files['tools/'+name]=path.read_bytes()
 for path,name,pin,validate in [(audit,'compiled-audit.json',stage.AUDIT_RAW,stage.validate_audit),
                                (body,'body-review.json',stage.BODY_REVIEW_RAW,stage.validate_body_review)]:
  if path.is_symlink() or stage.sha(path)!=pin:raise ValueError('Observed09 proof changed: '+name)
  validate(json.loads(path.read_text(encoding='utf-8')));files[name]=path.read_bytes()
 manifest=dict(image=54,baseline_image=53,base_stage=stage.BASE_NAME,stage=stage.STAGE_NAME,
  base_raw_sha256=stage.BASE_RAW,base_manifest_sha256=stage.BASE_MANIFEST,base_outputs_sha256=stage.BASE_OUTPUTS,
  compiled_stage=stage.COMPILED,compiled_framework_sha256=stage.FRAMEWORK,compiled_manifest_sha256=stage.COMPILE_STAGE,
  compiled_outputs_sha256=stage.EXPORT,compiled_cache_proof_sha256=stage.CACHE_PROOF,
  compiled_terminal_container_id=stage.COMPILED_CID,expected_changed_files=sorted(stage.EXPECTED_CHANGED),
  retained_systemui_camera_runtime_labels_providers_alarms_art=True,optional_fec=False,signed_hashtree_required=True,
  files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())},
  hardware_review_and_host_reservation_required=True,image_staged=False,image_built=False,installed=False,
  symbols_30px_layout_fix_included=False,full_parity=False)
 files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 return files


def main():
 p=argparse.ArgumentParser(description=__doc__);root=Path(__file__).resolve().parents[1]
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--audit',type=Path,default=root/'work/tcl-dialog-adapter-native09-audit01/result.json')
 p.add_argument('--body-review',type=Path,default=root/'docs/evidence/tcl-native09-body-review01.json')
 a=p.parse_args();files=packet_files(root,a.audit,a.body_review)
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

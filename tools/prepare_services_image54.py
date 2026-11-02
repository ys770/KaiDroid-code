"""Prospective native09/image54 services-image binding; final raw/boot acceptance pending."""
import argparse,difflib,hashlib,json
from pathlib import Path
from prepare_services_image53 import generate as generate53,SOURCE,SIGNATURE
from prepare_oat_rx_image50 import inspect_oat,LIBART
from check_oat_location_helpers import extract
OUTPUTS='7b72f5d7f8b819d8c1c6e70c04d4791b647fc1f3f78fdbd65047b46ccd42a3d0'
STAGE='a6df424e87b68c89dee426344304fdf9ffc6927fa2b977a33d5f00ad50f5a264'
OAT='acb5e828e9452f7f3dea26fcac04322d78548d78b227df397044bdb0d2fa4beb'
ART='6506cf9c1fab8cd77d695fbf8b076eb4cde8031211660f853c031d38e9b74ba9'
FRAMEWORK='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
SERVICES='4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'

def sha(raw):return hashlib.sha256(raw).hexdigest()

def generate(original):
    text=generate53(original).decode()
    for old,new in [('exact-image53','prospective-native09-image54'),('836049105u','3915454583u')]:
        if text.count(old)!=1:raise ValueError('Prior source anchor changed')
        text=text.replace(old,new,1)
    return text.encode()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('stage','source','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();raw=(a.stage/'outputs.json').read_bytes();manifest=json.loads(raw)
    if sha(raw)!=OUTPUTS or (a.stage/'build.exit').read_text().strip()!='0' or len(manifest['files'])!=30:raise ValueError('Wrong/incomplete native09 outputs')
    if sha((a.stage/'staging.json').read_bytes())!=STAGE:raise ValueError('Native09 stage manifest changed')
    for name,pin in manifest['files'].items():
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts or not name.startswith('framework/') or sha((a.stage/'output'/rel).read_bytes())!=pin:raise ValueError('Native09 file/path/hash differs')
    pins={'framework/oat/arm/services.odex':OAT,'framework/oat/arm/services.art':ART,'framework/framework.jar':FRAMEWORK,'framework/services.jar':SERVICES}
    if any(manifest['files'].get(n)!=h for n,h in pins.items()):raise ValueError('Wrong reviewed artifact')
    header=inspect_oat((a.stage/'output/framework/oat/arm/services.odex').read_bytes())
    if (header['checksum'],header['oat_size'],header['code_offset'])!=(3915454583,12699918,2895872):raise ValueError('Prospective OAT tuple differs')
    original=a.source.read_bytes();candidate=generate(original)
    caller='std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat('
    oldcaller=extract(original.decode(),caller)
    if extract(candidate.decode(),caller)!=oldcaller:raise ValueError('Acceptance/fallback caller changed')
    reverted=candidate.decode().replace(extract(candidate.decode(),SIGNATURE),extract(original.decode(),SIGNATURE),1).replace('#include "gc/heap.h"\n','',1).replace('#include "oat.h"\n','',1)
    if reverted!=original.decode():raise ValueError('Changed outside helper/includes')
    stage=json.loads((a.stage/'staging.json').read_text())
    if len(stage['art_apex'])!=24:raise ValueError('Missing retained ART Java/preopt closure')
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep outputs in workspace')
    out.mkdir(parents=True,exist_ok=False)
    patch=''.join(difflib.unified_diff(original.decode().splitlines(True),candidate.decode().splitlines(True),fromfile='a/art/runtime/oat_file_manager.cc',tofile='b/art/runtime/oat_file_manager.cc')).encode()
    for name,data in [('original.cc',original),('candidate.cc',candidate),('candidate.patch',patch)]:out.joinpath(name).write_bytes(data)
    r=dict(status='prospective_native09_not_final_raw_bound_or_boot_accepted',image=54,prospective=True,final_raw_bound=False,accepted_boot=False,raw_sha256=None,
        outputs_manifest_sha256=OUTPUTS,stage_manifest_sha256=sha((a.stage/'staging.json').read_bytes()),native09_files=manifest['files'],retained_art_apex=stage['art_apex'],expected_baseline_libart_sha256=LIBART,
        services_oat_sha256=OAT,services_image_sha256=ART,services_jar_sha256=SERVICES,framework_sha256=FRAMEWORK,services_oat_fingerprint={k:header[k] for k in ('checksum','oat_size','code_offset')},
        original_sha256=SOURCE,candidate_sha256=sha(candidate),patch_sha256=sha(patch),unchanged_open_dex_function_sha256=sha(oldcaller.encode()),built_target=False,installed=False,
        limits=['Local30 native09 outputs and build.exit validate; outputs.json pending-audit flags are historical, not asserted runtime acceptance.','No image54 raw/boot is bound by this step. Final raw must match every native09 output, ART24 and baseline libart before build scheduling.','Source filter uses exact prospective services OAT tuple; future preopt requires another binding.','Original53/50 candidates are unchanged; no host/phone actions.','No Android ABI/functionality/memory saving established by source preparation.'])
    (out/'candidate.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k] for k in ('status','services_oat_fingerprint','candidate_sha256','patch_sha256')},indent=2))

if __name__=='__main__':main()

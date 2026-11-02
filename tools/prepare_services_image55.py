"""Bind an isolated services app-image experiment to the reviewed image55 raw."""
import argparse,difflib,hashlib,json
from pathlib import Path
from prepare_services_image53 import generate as generate53,SOURCE,SIGNATURE
from prepare_oat_rx_image50 import inspect_oat,LIBART
from check_oat_location_helpers import extract
RAW='c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
STAGE='fe0d50f7771b7e1dca982a94b3025a68ee228f4b68399378ad84b449f10fbdde'
OAT='7ccc2039785860155f161ba8a8583adf50ee64c8364553f3718c8d3774b1b608'
ART='06367ceca49dfd29ee2732a62b217f42399c04a631c07cb2a63226f822f17ff4'
FRAMEWORK='429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53'
SERVICES='4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def file_sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def generate(original):
    text=generate53(original).decode()
    for old,new in [('exact-image53','exact-image55'),('836049105u','307763368u')]:
        if text.count(old)!=1:raise ValueError('Prior source anchor changed')
        text=text.replace(old,new,1)
    return text.encode()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('stage','image','source','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();manifest_raw=a.stage.read_bytes();m=json.loads(manifest_raw)
    if sha(manifest_raw)!=STAGE or m['image']!=55 or m['baseline_image']!=54:raise ValueError('Wrong reviewed stage')
    if len(m['exported_files'])!=30 or len(m['art_apex'])!=24:raise ValueError('Missing preopt inventory')
    identity=(a.image.stat().st_size,a.image.stat().st_mtime_ns)
    if identity[0]!=834666496 or m['system_partition_bytes']!=identity[0] or file_sha(a.image)!=RAW:raise ValueError('Wrong raw size/hash')
    expected={}
    for group in ('exported_files','art_apex','protected54_sha256','preserved_alarm_files'):
        for name,pin in m[group].items():
            rel=Path(name)
            if rel.is_absolute() or '..' in rel.parts or name.startswith('/') or '\\' in name:raise ValueError('Unsafe manifest path')
            if name in expected and expected[name]!=pin:raise ValueError('Conflicting manifest hash')
            expected[name]=pin
    pins={'framework/oat/arm/services.odex':OAT,'framework/oat/arm/services.art':ART,'framework/framework.jar':FRAMEWORK,'framework/services.jar':SERVICES,'apex/com.android.art.release/lib/libart.so':LIBART}
    for name,pin in pins.items():
        if name in expected and expected[name]!=pin:raise ValueError('Reviewed artifact differs')
        expected[name]=pin
    from dissect.extfs import ExtFS
    with a.image.open('rb') as f:
        fs=ExtFS(f)
        if fs.get('/system/build.prop').open().read().splitlines().count(b'ro.kaidroid.image=55')!=1:raise ValueError('Wrong build property')
        for name,pin in expected.items():
            if sha(fs.get('/system/'+name).open().read())!=pin:raise ValueError('Raw file differs: '+name)
        header=inspect_oat(fs.get('/system/framework/oat/arm/services.odex').open().read())
    if (a.image.stat().st_size,a.image.stat().st_mtime_ns)!=identity:raise ValueError('Raw changed during verification')
    if (header['checksum'],header['oat_size'],header['code_offset'])!=(307763368,12699918,2895872):raise ValueError('OAT tuple differs')
    original=a.source.read_bytes();candidate=generate(original)
    caller='std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat('
    oldcaller=extract(original.decode(),caller)
    if extract(candidate.decode(),caller)!=oldcaller:raise ValueError('Acceptance/fallback caller changed')
    reverted=candidate.decode().replace(extract(candidate.decode(),SIGNATURE),extract(original.decode(),SIGNATURE),1).replace('#include "gc/heap.h"\n','',1).replace('#include "oat.h"\n','',1)
    if reverted!=original.decode():raise ValueError('Changed outside helper/includes')
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep outputs in workspace')
    out.mkdir(parents=True,exist_ok=False)
    patch=''.join(difflib.unified_diff(original.decode().splitlines(True),candidate.decode().splitlines(True),fromfile='a/art/runtime/oat_file_manager.cc',tofile='b/art/runtime/oat_file_manager.cc')).encode()
    for name,data in [('original.cc',original),('candidate.cc',candidate),('candidate.patch',patch)]:out.joinpath(name).write_bytes(data)
    r=dict(status='exact_image55_raw_bound_source_only',image=55,prospective=False,final_raw_bound=True,accepted_clean_startup=False,raw_sha256=RAW,stage_manifest_sha256=STAGE,
        verified_files=expected,verified_file_count=len(expected),expected_baseline_libart_sha256=LIBART,services_oat_sha256=OAT,services_image_sha256=ART,services_jar_sha256=SERVICES,framework_sha256=FRAMEWORK,
        services_oat_fingerprint={k:header[k] for k in ('checksum','oat_size','code_offset')},original_sha256=SOURCE,candidate_sha256=sha(candidate),patch_sha256=sha(patch),unchanged_open_dex_function_sha256=sha(oldcaller.encode()),built_target=False,installed=False,
        parent_reported_runtime=dict(boot_id='00000000-0000-0000-0001-000000000001',raw_boot_wifi_dialogs28='PASS reported by hardware lane',startup_mms='Invalid subscriptionID before SIM initialized; UI guard pending',all_hardware_verified=False),
        limits=['Local raw/file and exact source binding; no host, phone or target compilation.', 'Parent runtime report is attribution, not independent acceptance or a clean-startup claim. Baseline55 services mapping residency has not been freshly measured here.', 'Exact OAT tuple filter is not authentication. A future framework/preopt requires a separate binding.', 'Modeled controls do not prove Android ABI, fallback class loading, startup, GC, functionality or memory savings.', 'Full raw metadata/xattr/AVB and hardware acceptance remain with the hardware lane.'])
    (out/'candidate.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({k:r[k] for k in ('status','verified_file_count','services_oat_fingerprint','candidate_sha256','patch_sha256')},indent=2))
if __name__=='__main__':main()

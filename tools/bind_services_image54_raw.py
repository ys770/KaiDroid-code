"""Bind prospective54 source to a parent-reviewed local raw image; not boot acceptance."""
import argparse,hashlib,json
from pathlib import Path
from prepare_services_image54 import generate,OUTPUTS,STAGE,LIBART

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def bind(a):
    r=json.loads((a.candidate_dir/'candidate.json').read_text())
    if r['outputs_manifest_sha256']!=OUTPUTS or r['stage_manifest_sha256']!=STAGE or r['final_raw_bound'] or not r['prospective']:raise ValueError('Wrong prospective binding')
    if (a.candidate_dir/'candidate.cc').read_bytes()!=generate((a.candidate_dir/'original.cc').read_bytes()) or sha(a.candidate_dir/'candidate.cc')!=r['candidate_sha256'] or sha(a.candidate_dir/'candidate.patch')!=r['patch_sha256']:raise ValueError('Candidate source/patch changed')
    if sha(a.stage/'outputs.json')!=OUTPUTS or sha(a.stage/'staging.json')!=STAGE:raise ValueError('Native09 manifests changed')
    outputs=json.loads((a.stage/'outputs.json').read_text())['files'];art=json.loads((a.stage/'staging.json').read_text())['art_apex']
    if r['native09_files']!=outputs or r['retained_art_apex']!=art:raise ValueError('Prospective file inventories differ')
    identity=(a.image.stat().st_size,a.image.stat().st_mtime_ns)
    if identity[0]!=834666496 or sha(a.image)!=a.image_sha256:raise ValueError('Wrong reviewed raw hash/size')
    from dissect.extfs import ExtFS
    with a.image.open('rb') as f:
        fs=ExtFS(f)
        if fs.get('/system/build.prop').open().read().splitlines().count(b'ro.kaidroid.image=54')!=1:raise ValueError('Raw image is not54')
        expected={**outputs,**art,'apex/com.android.art.release/lib/libart.so':LIBART,'priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c','system_ext/priv-app/SystemUI/SystemUI.apk':'aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'}
        for path,pin in expected.items():
            if hashlib.sha256(fs.get('/system/'+path).open().read()).hexdigest()!=pin:raise ValueError('Final54 input differs: '+path)
    if (a.image.stat().st_size,a.image.stat().st_mtime_ns)!=identity:raise ValueError('Raw changed during verification')
    return dict(image=54,raw_sha256=a.image_sha256,final_raw_bound=True,accepted_boot=False,build_authorized_by_this_tool=False,
        prospective_candidate_sha256=r['candidate_sha256'],candidate_manifest_sha256=sha(a.candidate_dir/'candidate.json'),verified_files=expected,verified_file_count=len(expected),
        binder_sha256=sha(Path(__file__)),limits=['Local raw/file binding only; parent must separately validate boot, installed hashes, functionality and authorize/schedule build.','Does not replace the full raw content/metadata/xattr/AVB closure or original bootchain/vendor preservation checks.','No host/phone command, source promotion, build, image mutation or saving claim.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('candidate-dir','stage','image','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--image-sha256',required=True);a=p.parse_args();r=bind(a)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(final_raw_bound=True,accepted_boot=False,verified_files=r['verified_file_count'])))

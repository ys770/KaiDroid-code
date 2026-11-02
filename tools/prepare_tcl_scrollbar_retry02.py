"""Hardware-owned fresh retry02 controls; reuse sealed01 resources/cache baseline.

No source acquisition/snapshot, old-stage mutation or launch. Parent allocates
the exact empty external02 bind first and reviews the resulting stage/plan.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
sys.dont_write_bytecode = True

ROOT = Path('/opt/kaidroid/kaidroid-build-20261023')
PARENT = ROOT/'tcl-scrollbar-build01'
STAGE = ROOT/'tcl-scrollbar-build02'
PARENT_STAGE = 'af097d2f00a7686a13fd5fb56b340d96387cedd9cf95d5e9243ff6d639826e27'
PARENT_CACHE = '640acfe18162cb733c4461b942f50147a9cbcf86eb9d19bc60215f8d7246284c'
PARENT_CID = 'ad59a0dc84510e53d89e7b228320b32abcbdb119311029dd975e11cb99fc2297'
SNAPSHOT = 'ed3c558bb2fc9fb3fcf165f7ae5a4301b183a927ff364a8437f8d175cbc923f6'
GIB = 1024**3


def require(value,message):
    if not value:
        raise ValueError(message)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
    return h.hexdigest()


def run(args):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True,timeout=30)


def parent_proof(staging,cache,state):
    require(hashlib.sha256(staging).hexdigest()==PARENT_STAGE,'Original stage identity changed')
    require(hashlib.sha256(cache).hexdigest()==PARENT_CACHE,'Actual terminal cache proof changed')
    spec=json.loads(staging);receipt=json.loads(cache)
    require(receipt['container_id']==PARENT_CID and receipt['before_inventory_sha256']==SNAPSHOT and
            receipt['lower_entries']==565530 and receipt['original_lower_all_files_content_metadata_unchanged'] is True and
            receipt['projected_changed_entries']==0 and receipt['projected_removed_entries']==[],
            'Sealed01 cache/lower preservation not established')
    require(state.get('Status')=='exited' and state.get('Running') is False and state.get('Restarting') is False and
            state.get('Dead') is False and state.get('OOMKilled') is False and state.get('ExitCode')==1 and
            state.get('Pid')==0 and state==receipt['terminal_state'],'Original exact job is not authoritative terminal1')
    require(spec['source_controls']['build.sh']=='332124036f40dd0aaec3959923c52c1f3d68629c707a360aaf44201aeecad2b0',
            'Failed wrapper identity differs')
    return spec


def retry_spec(parent,stage,pins,controls,packet_hash,free,root_free):
    require(stage==STAGE and free>=34*GIB and root_free>=20*GIB,'Retry namespace/storage headroom differs')
    spec=copy.deepcopy(parent)
    spec['inputs']=pins
    spec['source_controls']=controls
    spec['packet_sha256']=packet_hash
    spec['output_source']=(stage/'out').as_posix()
    spec['layered_output']=dict(lower=(ROOT/'tcl-dialog-build01/out').as_posix(),lower_ro=(stage/'lower-ro').as_posix(),
        upper=(stage/'cache-upper').as_posix(),work=(stage/'cache-work').as_posix(),merged=(stage/'out').as_posix(),
        before_inventory_sha256=SNAPSHOT,original_lower_read_only=True)
    spec['external_storage']=dict(volume='/mnt/ext1',backing='/mnt/ext1/kaidroid-tcl-scrollbar-build02',device='8:0',
        root_floor_bytes=20*GIB,root_initial_free_bytes=root_free)
    spec['disk_plan']=dict(free_after_clone_bytes=free,incremental_budget_bytes=14*GIB,emergency_floor_bytes=20*GIB)
    spec['retry_parent']=dict(stage=PARENT.as_posix(),staging_sha256=PARENT_STAGE,container_id=PARENT_CID,
        cache_receipt_sha256=PARENT_CACHE,initial_snapshot_sha256=SNAPSHOT,sealed_parent_unchanged=True,
        resource_tree_reused_read_only=True,original_verified_cache_baseline_reused=True,
        original_failed_upper_not_reused_or_modified=True,no_new_cache_snapshot=True,
        actual_source_graph_and_plan_review_still_required=True)
    return spec


def prepare(packet,pin):
    require(os.name=='posix' and (os.geteuid(),os.getegid())==(1000,1000),'Use Linux1000:1000')
    require(packet.is_absolute() and packet.resolve(strict=True)==packet and sha(packet/'packet.json')==pin,'Fresh retry packet path/hash differs')
    meta=json.loads((packet/'packet.json').read_text())
    require(meta['kind']=='tcl-scrollbar-execution-retry02' and meta['stage']=='tcl-scrollbar-build02','Wrong retry packet namespace')
    actual={p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_file()}
    require(actual==set(meta['files'])|{'packet.json'} and not any(p.is_symlink() for p in packet.rglob('*')),'Retry packet coverage/links differ')
    for name,value in meta['files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and '\\' not in name and
                Path(name).as_posix()==name and sha(packet/name)==value,'Retry payload differs')
    sys.path.insert(0,str(packet/'tools'))
    import tcl_scrollbar_build_contract as c
    import layered_dialog_output as layer
    import prepare_tcl_scrollbar_stage as prior
    require(c.ROOT==ROOT and c.NAME==STAGE.name,'Retry-only contract not loaded')
    for module,name in ((c,'tcl_scrollbar_build_contract.py'),(layer,'layered_dialog_output.py'),(prior,'prepare_tcl_scrollbar_stage.py')):
        require(sha(Path(module.__file__))==meta['files']['tools/'+name],'Loaded retry control differs: '+name)
    prior.idle()
    layer.verify_external_storage(STAGE,fresh=True)
    inspected=json.loads(run(['sudo','-n','docker','inspect',PARENT_CID]).stdout)
    require(len(inspected)==1 and inspected[0]['Id']==PARENT_CID,'Original exact CID changed')
    parent=parent_proof((PARENT/'staging.json').read_bytes(),(PARENT/'cache-preservation.json').read_bytes(),inspected[0]['State'])
    require((PARENT/'build.exit').read_text().strip()=='1','Original build.exit differs')
    require((PARENT/'preparation.complete').read_text().strip()==PARENT_STAGE and
            sha(PARENT/'control-inputs.json')=='ade98fabe53c20555f03212878cf50ab158eed9b0162f53366da15f1bb5e21a1',
            'Original completion/control manifest changed')
    require(sha(PARENT/'cache-lower-before.json')==SNAPSHOT,'Original lower snapshot changed')
    for name,value in parent['source_controls'].items():
        require(sha(PARENT/name)==value,'Original sealed control changed: '+name)
    original_inputs={p.relative_to(PARENT/'inputs').as_posix() for p in (PARENT/'inputs').rglob('*') if p.is_file() and not c.within(p,PARENT/'inputs/res')}
    require(original_inputs==set(parent['inputs']),'Original input membership changed')
    for name,value in parent['inputs'].items():
        source=PARENT/'inputs'/name
        require(source.resolve(strict=True)==source and sha(source)==value,'Original sealed input changed: '+name)
    require(sha(PARENT/'inputs/resource-before.json')==parent['inputs']['resource-before.json'] and
            sha(PARENT/'inputs/resource-after.json')==parent['inputs']['resource-after.json'],'Original resource inventories changed')
    require(not any(STAGE.iterdir()),'Existing retry preparation/job; inspect it')
    (STAGE/'prepare.pid').write_text(str(os.getpid())+'\n')
    inputs=STAGE/'inputs';inputs.mkdir()
    for source in (PARENT/'inputs').iterdir():
        if source.name=='res':continue
        target=inputs/source.name
        require(not source.is_symlink(),'Unexpected original input link')
        if source.is_dir():shutil.copytree(source,target,symlinks=True)
        else:shutil.copy2(source,target)
    (inputs/'res').mkdir(mode=0o755)
    run(['sudo','-n','mount','--bind',PARENT/'inputs/res',inputs/'res'])
    run(['sudo','-n','mount','-o','remount,bind,ro',inputs/'res'])
    for source in (packet/'tools').iterdir():
        require(source.is_file() and not source.is_symlink(),'Unexpected retry tool type')
        shutil.copyfile(source,inputs/'tools'/source.name)
    # Copy the existing verified baseline snapshot; never invoke snapshot mode.
    shutil.copy2(PARENT/'cache-lower-before.json',STAGE/'cache-lower-before.json')
    for source,dest in [('build_tcl_scrollbar.sh','build.sh'),('resource-monitor.py','disk-monitor.py'),
                        ('layered_dialog_output.py','layered_dialog_output.py'),('tcl_scrollbar_build_contract.py','tcl_scrollbar_build_contract.py')]:
        shutil.copyfile(packet/'tools'/source,STAGE/dest)
    for name in ('lower-ro','cache-upper','cache-work','out'):(STAGE/name).mkdir(mode=0o755)
    lower=ROOT/'tcl-dialog-build01/out'
    run(['sudo','-n','mount','--bind',lower,STAGE/'lower-ro'])
    run(['sudo','-n','mount','-o','remount,bind,ro',STAGE/'lower-ro'])
    options='lowerdir='+str(STAGE/'lower-ro')+',upperdir='+str(STAGE/'cache-upper')+',workdir='+str(STAGE/'cache-work')+',index=off,redirect_dir=off,metacopy=off'
    run(['sudo','-n','mount','-t','overlay','overlay','-o',options,STAGE/'out'])
    for name,value in parent['retained_product'].items():
        require(sha(STAGE/'out/target/product/n139dl/system'/name)==value,'Retained product differs: '+name)
    require(sha(STAGE/'out/target/product/n139dl/system/framework/framework-res.apk')==c.BASE,'Original resource baseline differs')
    require(set(parent['cpus'])<=set(os.sched_getaffinity(0)) and len(parent['cpus'])==2,'Original two CPUs unavailable')
    (STAGE/'targets.txt').write_text(c.TARGET+'\n')
    (STAGE/'launch.sh').write_text(prior.launcher(STAGE,parent['cpus']))
    pins={p.relative_to(inputs).as_posix():sha(p) for p in inputs.rglob('*') if p.is_file() and not c.within(p,inputs/'res')}
    controls={n:sha(STAGE/n) for n in c.CONTROLS}
    spec=retry_spec(parent,STAGE,pins,controls,pin,shutil.disk_usage('/mnt/ext1').free,shutil.disk_usage(ROOT).free)
    layer.verify_mounts(STAGE,spec)
    before=json.loads((STAGE/'cache-lower-before.json').read_text())
    require(layer.semantic(before)==layer.inventory(STAGE/'out',identity=False),'Fresh private cache projection differs from reused baseline')
    c.dump(STAGE/'staging.json',spec)
    c.dump(STAGE/'control-inputs.json',{**controls,'staging.json':sha(STAGE/'staging.json')})
    (STAGE/'preparation.complete').write_text(sha(STAGE/'staging.json')+'\n')
    loaded=c.load_stage(ROOT,STAGE);c.verify_inputs(STAGE,loaded);prior.idle()
    require(sha(PARENT/'staging.json')==PARENT_STAGE and sha(PARENT/'cache-preservation.json')==PARENT_CACHE,'Sealed parent changed')
    print(json.dumps(dict(stage=str(STAGE),staging_sha256=sha(STAGE/'staging.json'),prepared=True,launched=False,
                         parent_staging_sha256=PARENT_STAGE,parent_cache_sha256=PARENT_CACHE,new_snapshot_taken=False)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet',required=True,type=Path)
    parser.add_argument('--packet-sha256',required=True)
    args=parser.parse_args()
    prepare(args.packet,args.packet_sha256)


if __name__=='__main__':main()

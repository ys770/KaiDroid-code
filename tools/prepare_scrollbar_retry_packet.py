"""Freeze resource retry02 from exact original packet and actual terminal proofs."""
import argparse
import ast
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import tarfile

from prepare_scrollbar_wrapper_retry import ARCHIVE,corrected
from prepare_scrollbar_reservation_amendment import amend_source
from prepare_tcl_scrollbar_retry02 import PARENT_STAGE,PARENT_CACHE,PARENT_CID,parent_proof

ROOT=Path(__file__).resolve().parents[1]
NAME='tcl-scrollbar-build01'
RETRY='tcl-scrollbar-build02'
HELPER='77d83c00538034d1597e4ad708f913bd403620009af561e1c91ef8ac12924cda'
ORIGINAL_META='894ff445d5e4d5b9cbf0137920392412fe98c40237e79de904e08ed273112ed3'


def sha(data):return hashlib.sha256(data).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def prepare(archive,stage,cache,terminal,output):
    require(not output.exists() and not output.is_symlink(),'Fresh retry packet output required')
    raw=archive.read_bytes();require(sha(raw)==ARCHIVE,'Original archive changed')
    data={};modes={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as original:
        for member in original.getmembers():
            p=PurePosixPath(member.name)
            require(member.isfile() and not p.is_absolute() and '..' not in p.parts and
                    p.as_posix()==member.name and member.name not in data,'Unsafe original archive member')
            data[member.name]=original.extractfile(member).read();modes[member.name]=member.mode
    require(sha(data['packet.json'])==ORIGINAL_META,'Original packet manifest differs')
    before=dict(data);meta=json.loads(data['packet.json'])
    require(set(data)==set(meta['files'])|{'packet.json'} and all(sha(data[n])==v for n,v in meta['files'].items()),'Original payload coverage/hash differs')
    terminal_bytes=terminal.read_bytes();end=json.loads(terminal_bytes)
    parent=parent_proof(stage.read_bytes(),cache.read_bytes(),end['observed_container_state'])
    require(end['container_id']==PARENT_CID and end['terminal'] and end['exit_file_matches_docker'],'Original job not terminal')
    namespace_files=['tools/layered_dialog_output.py','tools/resource-monitor.py','tools/tcl_scrollbar_build_contract.py','tools/prepare_tcl_scrollbar_stage.py','proofs/launch-template.sh']
    for name in namespace_files:
        data[name]=data[name].replace(NAME.encode(),RETRY.encode())
    data['tools/prepare_tcl_scrollbar_stage.py']=amend_source(data['tools/prepare_tcl_scrollbar_stage.py'])
    data['tools/build_tcl_scrollbar.sh']=corrected(before['tools/build_tcl_scrollbar.sh'])
    helper=(ROOT/'tools/scrollbar_host_reservation.py').read_bytes();require(sha(helper)==HELPER,'Reviewed namespace-aware helper changed')
    data['tools/scrollbar_host_reservation.py']=helper
    data['tools/prepare_tcl_scrollbar_retry02.py']=(ROOT/'tools/prepare_tcl_scrollbar_retry02.py').read_bytes()
    for name,value in data.items():
        if name.endswith('.py'):ast.parse(value.decode(),feature_version=(3,8))
    # Normalize only namespace literals and the one idle call to prove no
    # infrastructure lifecycle/capability/monitor logic changed.
    from prepare_scrollbar_reservation_amendment import OLD,NEW
    for name in namespace_files:
        restored=data[name].replace(RETRY.encode(),NAME.encode())
        if name.endswith('prepare_tcl_scrollbar_stage.py'):restored=restored.replace(NEW.encode(),OLD.encode())
        require(restored==before[name],'Unreviewed infrastructure change: '+name)
    proof=dict(kind='sealed-scrollbar-retry02',parent_staging_sha256=PARENT_STAGE,parent_cache_sha256=PARENT_CACHE,
        parent_container_id=PARENT_CID,parent_terminal_sha256=sha(terminal_bytes),parent_terminal_exit=1,
        original_archive_sha256=ARCHIVE,original_manifest_sha256=ORIGINAL_META,
        retry_namespace=RETRY,backing='/mnt/ext1/kaidroid-tcl-scrollbar-build02',
        namespace_only_files=namespace_files,build_wrapper_sha256=sha(data['tools/build_tcl_scrollbar.sh']),
        nounset_off_only_during_source_lunch=True,source_lunch_failures_propagated=True,strict_modes_restored=True,
        resource_inputs_reused_from_sealed_parent_readonly=True,cache_baseline_snapshot_reused=True,
        new_cache_upper_work_only=True,no_snapshot_or_original_prepare_invocation=True,sealed_parent_not_modified=True,
        one_apk_target_and_original_caps_deadline_plan_gates_retained=True,
        host_staged=False,compiler_launched=False,full_parity=False)
    data['proofs/retry-parent.json']=encoded(proof)
    meta.update(kind='tcl-scrollbar-execution-retry02',stage=RETRY,backing=proof['backing'],
                retry_parent=proof,files={n:sha(v) for n,v in data.items() if n!='packet.json'})
    data['packet.json']=encoded(meta)
    output.mkdir(parents=True);packet=output/'packet';packet.mkdir()
    for name,value in data.items():
        target=packet/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(value)
    archive_out=output/'packet.tar.gz'
    with archive_out.open('xb') as stream:
        with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as target:
                for name in sorted(data):
                    info=tarfile.TarInfo(name);info.mode=modes.get(name,0o644);info.size=len(data[name]);target.addfile(info,io.BytesIO(data[name]))
    with tarfile.open(archive_out) as check:
        require(len(check.getnames())==len(data) and len(set(check.getnames()))==len(data),'Retry archive membership differs')
        for member in check.getmembers():
            require(member.isfile() and check.extractfile(member).read()==data[member.name] and
                    member.mode==modes.get(member.name,0o644),'Retry archive bytes/types/modes differ')
    result=dict(archive_sha256=sha(archive_out.read_bytes()),packet_manifest_sha256=sha(data['packet.json']),
        entries=len(data),changed_original_files=[n for n in before if before[n]!=data[n]],
        added_files=sorted(set(data)-set(before)),proof=proof,
        old_resource_payloads_unchanged=all(before[n]==data[n] for n in before if n.startswith('proposal/')),
        original_archive_still_unchanged=sha(archive.read_bytes())==ARCHIVE,host_staged=False,compiler_launched=False)
    (output/'result.json').write_bytes(encoded(result));return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','stage','cache','terminal','output'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args();print(json.dumps(prepare(a.archive,a.stage,a.cache,a.terminal,a.output)))


if __name__=='__main__':main()

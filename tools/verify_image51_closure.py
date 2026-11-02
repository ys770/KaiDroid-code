"""Verify full immutable50-to-picker51 raw content/UID/GID/modes/xattrs closure."""
import argparse
import json
import re
from pathlib import Path
from stage_tcl_ime_picker_image51 import BASE_RAW, FRAMEWORK, OLD_FRAMEWORK, PINS, PARTITION, FILES, COMPILE_STAGE, EXPORT, AUDIT, METADATA_AUDIT, BASE_MANIFEST, CACHE_PROOF, canonical, sha


def validate_manifest(m):
    if m.get('image')!=51 or m.get('baseline_image')!=50 or m.get('base_raw_sha256')!=BASE_RAW or \
            m.get('framework_sha256')!=FRAMEWORK or m.get('build_manifest_sha256')!=COMPILE_STAGE or \
            m.get('outputs_sha256')!=EXPORT or m.get('compiled_audit_canonical_sha256')!=AUDIT or \
            canonical(m.get('exported_files'))!=FILES or len(m.get('preserved_alarm_files',{}))!=8 or \
            len(m.get('art_apex',{}))!=24 or m.get('protected50_sha256')!=PINS or m.get('cache_preservation_verified') is not True or \
            m.get('cache_preservation_sha256')!=CACHE_PROOF or m.get('base_manifest_sha256')!=BASE_MANIFEST or m.get('compiled_metadata_audit_canonical_sha256')!=METADATA_AUDIT:
        raise ValueError('Unreviewed image51 manifest')
    if not set(m['changed']) <= set(m['exported_files'])|{'build.prop'} or 'build.prop' not in m['changed']:
        raise ValueError('Unreviewed change set')


def compare_raw(before,after,oldprops,newprops,m,oldattrs,newattrs):
    validate_manifest(m)
    if before.keys()!=after.keys():raise ValueError('Raw entry set changed')
    changed={n for n in before if before[n]!=after[n]}
    expected={'/system/'+n for n in m['changed']}
    if changed!=expected:raise ValueError('Raw changed set differs from reviewed stage')
    for name in changed:
        old,new=before[name],after[name]
        if {k:v for k,v in old.items() if k!='sha256'}!={k:v for k,v in new.items() if k!='sha256'}:
            raise ValueError('Raw inode mode/UID/GID/kind changed: '+name)
        staged=m['changed'][name.removeprefix('/system/')]
        if old.get('sha256')!=staged['before'][2] or new.get('sha256')!=staged['after'][2]:
            raise ValueError('Raw content differs from staged delta: '+name)
    for name,digest in m['exported_files'].items():
        if after['/system/'+name].get('sha256')!=digest:raise ValueError('Export content mismatch: '+name)
    for name,digest in {**PINS,**m['preserved_alarm_files'],**m['art_apex']}.items():
        if before['/system/'+name].get('sha256')!=digest or after['/system/'+name].get('sha256')!=digest:
            raise ValueError('Protected50 content changed: '+name)
    if before['/system/framework/framework.jar'].get('sha256')!=OLD_FRAMEWORK:
        raise ValueError('Wrong baseline framework')
    if oldprops.splitlines().count(b'ro.kaidroid.image=50')!=1 or \
            newprops!=oldprops.replace(b'ro.kaidroid.image=50',b'ro.kaidroid.image=51'):
        raise ValueError('Unexpected build.prop change')
    if oldattrs!=newattrs or oldattrs.keys()!=before.keys():raise ValueError('Raw extended attributes/path coverage changed')
    return changed


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','manifest','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True);p.add_argument('--manifest-sha256',required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    if sha(a.manifest)!=a.manifest_sha256:raise ValueError('Unreviewed staging manifest bytes')
    m=json.loads(a.manifest.read_text(encoding='utf-8'));validate_manifest(m)
    for path,pin in ((a.baseline,BASE_RAW),(a.candidate,a.candidate_sha256)):
        if path.stat().st_size!=PARTITION or sha(path)!=pin:raise ValueError('Wrong raw image size/hash')
    from verify_image43_closure import inventory
    from verify_image40_xattrs import inventory as xattrs
    before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
    bx,_=xattrs(a.baseline);ax,counts=xattrs(a.candidate)
    changed=compare_raw(before,after,oldprops,newprops,m,bx,ax)
    report=dict(baseline_sha256=BASE_RAW,candidate_sha256=a.candidate_sha256,manifest_sha256=a.manifest_sha256,
        image=51,baseline_image=50,filesystem_entries=len(before),changed=sorted(changed),
        all_other_contents_identical=True,all_inode_modes_uid_gid_symlinks_identical=True,
        all_extended_attributes_identical=True,compared_xattrs=sum(counts.values()),
        retained50_systemui_provider_alarms_art=True,exported_framework_files=30,installed=False,
        exclusions=['timestamps','inode allocation','runtime behavior'],avb_verification='Separate packager AVB artifact required')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()

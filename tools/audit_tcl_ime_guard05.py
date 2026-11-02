"""Strict native07-to-guard05 and complete native51-to-guard05 audit, including literal bits."""
import argparse
import json
from pathlib import Path
import struct

import compare_dexdump_methods as parser
from audit_resolver_title_dex import inventory,sha
from audit_tcl_ime_picker_metadata import metadata
import audit_tcl_ime_correction as correction

BASE07='fc87c5f661224cedbe5d4960b8c00b8d41025ce8b9852af657b5899df90a9d08'
SOURCE05='d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd'
CALLBACK=(correction.OWNER,'lambda$showPicker$4$KeypadImeController','(Landroid/view/View;JLjava/util/List;I)V')
ORIGINAL_NORMALIZE=parser.normalize
OPCODES={0x12:'const/4',0x13:'const/16',0x14:'const',0x15:'const/high16',
         0x16:'const-wide/16',0x17:'const-wide/32',0x18:'const-wide',0x19:'const-wide/high16'}


def literal(data,offset):
    opcode=data[offset]
    if opcode not in OPCODES:raise ValueError('Not a numeric constant opcode')
    width=64 if opcode>=0x16 else 32
    register=(data[offset+1]&15) if opcode==0x12 else data[offset+1]
    if opcode==0x12:
        value=data[offset+1]>>4
        if value>=8:value-=16
    elif opcode in (0x13,0x16):value=struct.unpack_from('<h',data,offset+2)[0]
    elif opcode in (0x14,0x17):value=struct.unpack_from('<i',data,offset+2)[0]
    elif opcode==0x15:value=struct.unpack_from('<H',data,offset+2)[0]<<16
    elif opcode==0x18:value=struct.unpack_from('<Q',data,offset+2)[0]
    else:value=struct.unpack_from('<H',data,offset+2)[0]<<48
    return OPCODES[opcode]+' v'+str(register)+', #bits'+str(width)+' 0x'+format(value&((1<<width)-1),'0'+str(width//4)+'x')


def normalize_exact(method,data):
    result=ORIGINAL_NORMALIZE(method,data)
    raw=[r for r in method['instructions'] if not r['spacer']]
    if len(raw)!=len(result['instructions']):raise ValueError('Instruction correspondence changed')
    for index,row in enumerate(raw):
        if data[row['file_offset']] in OPCODES:
            # dexdump renders some int bit patterns as rounded float/double text.
            # Read the actual encoded literal; adjacent pixel colors must differ.
            result['instructions'][index]=literal(data,row['file_offset'])
    return result


def exact_inventory(jar,output,dexdump):
    original=parser.normalize
    try:
        parser.normalize=normalize_exact
        return inventory(jar,output,dexdump)
    finally:parser.normalize=original


def compare07(before,after,old_meta,new_meta):
    added=set(after)-set(before);removed=set(before)-set(after)
    changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
    meta_same=old_meta==new_meta
    return dict(before_methods=len(before),after_methods=len(after),added=sorted(added),removed=sorted(removed),
        changed=sorted(changed),expected_changed=[CALLBACK],all_declared_metadata_unchanged=meta_same,
        unexpected_changed_classes=sorted(k for k in old_meta.keys()&new_meta.keys() if old_meta[k]!=new_meta[k]),
        added_classes=sorted(set(new_meta)-set(old_meta)),removed_classes=sorted(set(old_meta)-set(new_meta)),
        passed=not added and not removed and changed=={CALLBACK} and meta_same)


def diffs(before,after):
    return [dict(method=k,before=before.get(k),after=after.get(k))
            for k in sorted(before.keys()|after.keys()) if before.get(k)!=after.get(k)]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline07','baseline51','candidate','controller-source','state-source','dexdump','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    a=p.parse_args()
    if sha(a.baseline07)!=BASE07 or sha(a.baseline51)!=correction.BASE:
        raise ValueError('Unreviewed native baseline')
    if sha(a.candidate)!=a.candidate_sha256 or a.candidate_sha256 in (BASE07,correction.BASE):
        raise ValueError('Unreviewed candidate')
    if sha(a.controller_source)!=SOURCE05 or sha(a.state_source)!=correction.STATE_SOURCE:
        raise ValueError('Unreviewed guard05 source')
    a.output.mkdir(parents=True,exist_ok=False)
    old51=exact_inventory(a.baseline51,a.output/'before51',a.dexdump)
    candidate=exact_inventory(a.candidate,a.output/'candidate',a.dexdump)
    meta51,new_meta=metadata(a.baseline51),metadata(a.candidate)
    full51=correction.compare_methods(old51,candidate)
    full_meta=correction.compare_metadata(meta51,new_meta,full51)
    (a.output/'method-diffs-51.json').write_text(json.dumps(diffs(old51,candidate),indent=2)+'\n',encoding='utf-8')
    del old51,meta51
    old07=exact_inventory(a.baseline07,a.output/'before07',a.dexdump)
    delta07=compare07(old07,candidate,metadata(a.baseline07),new_meta)
    passed=delta07['passed'] and full51['expected_method_delta_only'] and full_meta['expected_metadata_delta_only']
    report=dict(baseline07_sha256=BASE07,baseline51_sha256=correction.BASE,candidate_sha256=a.candidate_sha256,
        controller_source_sha256=SOURCE05,state_source_sha256=correction.STATE_SOURCE,dexdump_sha256=sha(a.dexdump),
        numeric_literals_compared_as_exact_encoded_dex_bits=True,
        delta07=delta07,complete51_methods=full51,complete51_metadata=full_meta,passed=passed,native_runtime_verified=False)
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (a.output/'method-diffs-07.json').write_text(json.dumps(diffs(old07,candidate),indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=passed,delta07=delta07['passed'],full51=full51['expected_method_delta_only'],metadata=full_meta['expected_metadata_delta_only'])))
    if not passed:raise ValueError('Unexpected native guard05 delta; preserve output and review, never widen automatically')


if __name__=='__main__':main()

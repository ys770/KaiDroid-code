"""Strict native09-to10 flag-only audit; two API words2->16, no other payload change."""
import argparse
import json
from pathlib import Path
import re
import struct
import zipfile
import zlib

from audit_resolver_title_dex import sha
from audit_tcl_ime_guard05 import exact_inventory, diffs
from audit_tcl_ime_picker_metadata import metadata
from read_dex_hiddenapi import inventory as flag_inventory
from prepare_tcl_dialog_hiddenapi_candidate import SIGNATURES,FLAGS,compare_csv
from prepare_tcl_dialog_adapter_build_packet import INPUTS

BASE='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
GENERATOR='9d60003265ad857c8ba802b34aac909da60436d40d4f356fc9985a277e8a7898'
GENERATED_FLAGS='9926fe86df5b86b04e9b4eae065d2aa5a1b65f3e640f20e46210e265ff70716c'
ENCODER_SOURCE='8819b96e34794dbc6263c069f3083b537123e239809d8bef0f148d5488b64653'


def compare_flags(before,after):
    old={k:(v['flag'],v['member_kind']) for k,v in before.items()}
    new={k:(v['flag'],v['member_kind']) for k,v in after.items()}
    changed={k for k in old.keys()&new.keys() if old[k]!=new[k]}
    known=all(v[0] is not None for v in list(old.values())+list(new.values()))
    passed=(known and old.keys()==new.keys() and changed==SIGNATURES and
            all(old[k]==(2,3) and new[k]==(16,3) for k in SIGNATURES))
    return dict(before_members=len(old),after_members=len(new),all_flags_present=known,
        added=sorted(new.keys()-old.keys()),removed=sorted(old.keys()-new.keys()),
        changed={k:dict(before=old[k],after=new[k]) for k in sorted(changed)},exact_two_raw_flag_changes=passed)


def compare_binary(before,after,oldflags,newflags):
    errors=[];dexes={}
    with zipfile.ZipFile(before) as old,zipfile.ZipFile(after) as new:
        names=old.namelist();other=new.namelist()
        if len(names)!=len(set(names)) or len(other)!=len(set(other)) or set(names)!=set(other):
            return dict(passed=False,errors=['Archive entry set/uniqueness changed'])
        for name in names:
            a,b=old.read(name),new.read(name)
            if name.startswith('classes') and name.endswith('.dex'):
                for label,data in [('baseline',a),('candidate',b)]:
                    if len(data)<112 or not re.fullmatch(rb'dex\n0[0-9]{2}\0',data[:8]) or struct.unpack_from('<I',data,32)[0]!=len(data) or struct.unpack_from('<I',data,40)[0]!=0x12345678:
                        errors.append('Invalid DEX header: '+label+'/'+name)
                    elif struct.unpack_from('<I',data,8)[0]!=(zlib.adler32(data[12:])&0xffffffff):
                        errors.append('Invalid DEX Adler32: '+label+'/'+name)
            selected=[k for k in SIGNATURES if oldflags.get(k,{}).get('dex')==name]
            if not selected:
                if a!=b:errors.append('Unrelated archive/DEX payload changed: '+name)
                continue
            if len(a)!=len(b):errors.append('DEX length changed: '+name);continue
            if a[12:32]!=b[12:32]:errors.append('Original encoder DEX signature bytes changed: '+name)
            offsets=[]
            for signature in selected:
                x,y=oldflags[signature],newflags.get(signature,{})
                offset=x.get('flag_offset')
                if y.get('dex')!=name or offset is None or offset!=y.get('flag_offset') or not 32<=offset<len(a) or a[offset]!=2 or b[offset]!=16:
                    errors.append('Flag offset/encoding differs from fixed prediction: '+signature)
                else:offsets.append(offset)
            unexpected=[i for i,(x,y) in enumerate(zip(a,b)) if x!=y and not 8<=i<12 and i not in offsets]
            if unexpected:errors.append('Unexpected bytes outside checksum/header/two flags: '+name)
            dexes[name]=dict(expected_flag_offsets=offsets,unexpected_byte_offsets=unexpected[:32],unexpected_byte_count=len(unexpected))
    return dict(passed=not errors,errors=errors,dexes=dexes,
        scope='Every archive payload byte identical except exact two one-byte flags and their independently recomputed DEX Adler32 bytes8..11. Original signature bytes12..31 identical. No annotation/debug/static-value exclusions.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','inputs','generator-source','encoder-source','baseline-flags','flags','dexdump','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True);a=p.parse_args()
    if sha(a.baseline)!=BASE or sha(a.candidate)!=a.candidate_sha256 or a.candidate_sha256==BASE:raise ValueError('Wrong native09/candidate identity')
    if sha(a.generator_source)!=GENERATOR or sha(a.encoder_source)!=ENCODER_SOURCE or sha(a.baseline_flags)!=FLAGS or sha(a.flags)!=GENERATED_FLAGS:raise ValueError('Wrong exact generator/encoder/CSV provenance')
    for name,digest in INPUTS.items():
        if sha(a.inputs/Path(name).name)!=digest:raise ValueError('Frozen09 Java source changed: '+name)
    a.output.mkdir(parents=True,exist_ok=False)
    before,bd=flag_inventory(a.baseline);after,ad=flag_inventory(a.candidate)
    flags=compare_flags(before,after);binary=compare_binary(a.baseline,a.candidate,before,after)
    csv=compare_csv(a.baseline_flags.read_bytes(),a.flags.read_bytes())
    methods_before=exact_inventory(a.baseline,a.output/'before09',a.dexdump)
    methods_after=exact_inventory(a.candidate,a.output/'candidate10',a.dexdump)
    method_delta=diffs(methods_before,methods_after);same_meta=metadata(a.baseline)==metadata(a.candidate)
    passed=flags['exact_two_raw_flag_changes'] and binary['passed'] and csv['exact_two_signature_delta'] and not method_delta and same_meta
    report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,source_inputs=INPUTS,
        generator_source_sha256=GENERATOR,encoder_source_sha256=ENCODER_SOURCE,baseline_flags_sha256=FLAGS,generated_flags_sha256=GENERATED_FLAGS,
        flags=flags,binary=binary,csv=csv,all_method_bodies_unchanged=not method_delta,all_declared_metadata_unchanged=same_meta,
        before_methods=len(methods_before),after_methods=len(methods_after),before_dex=bd,after_dex=ad,
        numeric_literals_compared_as_exact_encoded_bits=True,predictions_fixed_before_native10_output=True,
        passed=passed,runtime_verified=False,full_parity=False)
    (a.output/'method-diffs.json').write_text(json.dumps(method_delta,indent=2)+'\n',encoding='utf-8')
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=passed,flags=flags['exact_two_raw_flag_changes'],binary=binary['passed'],methods=not method_delta,metadata=same_meta)))
    if not passed:raise ValueError('Unexpected flag-only candidate delta; preserve evidence and investigate, never widen')


if __name__=='__main__':main()

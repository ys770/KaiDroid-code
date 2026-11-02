"""Offline allocated-data/relocation/unwind census for a matched off/on link pair."""
import sys
sys.dont_write_bytecode = True
import argparse
from collections import Counter
import difflib
import json
from pathlib import Path
import struct
from audit_services_phase_link_scope01 import Image, digest, packed_rel


def section_location(image, address):
    for s in image.sections:
        if s['sh_addr'] <= address < s['sh_addr'] + s['sh_size']:
            return (s.name, address - s['sh_addr'])
    return ('unmapped', hex(address))


def relocations(image):
    dynsym = image.elf.get_section_by_name('.dynsym')
    result = {}
    for offset, index, kind in packed_rel(image.elf.get_section_by_name('.rel.dyn').data()):
        key = section_location(image, offset)
        if key in result:
            raise ValueError('Duplicate relocation location')
        value = struct.unpack('<I', image.read(offset, 4))[0]
        result[key] = ('dynamic', kind, dynsym.get_symbol(index).name if index else None, value)
    for offset in image.relative:
        key = section_location(image, offset)
        if key in result:
            raise ValueError('Duplicate RELR/REL location')
        value = struct.unpack('<I', image.read(offset, 4))[0]
        result[key] = ('relative', image.target(value))
    rel = image.elf.get_section_by_name('.rel.plt')
    for row in rel.iter_relocations():
        offset = row['r_offset']
        key = section_location(image, offset)
        if key in result:
            raise ValueError('Duplicate PLT relocation location')
        value = struct.unpack('<I', image.read(offset, 4))[0]
        result[key] = ('plt', row['r_info_type'], dynsym.get_symbol(row['r_info_sym']).name, image.target(value))
    return result


def prel(place, value):
    value &= 0x7fffffff
    return (place + value - (0x80000000 if value & 0x40000000 else 0)) & 0xffffffff


def exidx(image):
    section = image.elf.get_section_by_name('.ARM.exidx')
    data, base = section.data(), section['sh_addr']
    if len(data) % 8:
        raise ValueError('Bad exidx extent')
    extab = image.elf.get_section_by_name('.ARM.extab')
    pointers, rows, errors, addresses = set(), [], [], []
    text = image.elf.get_section_by_name('.text')
    executable = [(s['sh_addr'], s['sh_addr'] + s['sh_size']) for s in image.sections if s['sh_flags'] & 4]
    for offset in range(0, len(data), 8):
        first, second = struct.unpack_from('<II', data, offset)
        address = prel(base + offset, first) & ~1
        addresses.append(address)
        if first & 0x80000000 or not any(low <= address <= high for low, high in executable):
            errors.append(dict(index=offset//8, error='function address outside executable bounds'))
        target = ('text_end',) if address == text['sh_addr'] + text['sh_size'] else image.target(address)
        if second == 1:
            kind, value = 'cantunwind', 1
        elif second & 0x80000000:
            kind, value = 'inline', second
        else:
            kind, value = 'extab', prel(base + offset + 4, second)
            if value % 4 or not extab['sh_addr'] <= value < extab['sh_addr'] + extab['sh_size']:
                errors.append(dict(index=offset//8, error='extab pointer outside bounds'))
            pointers.add(value)
        rows.append((target, kind, value))
    if any(a >= b for a,b in zip(addresses, addresses[1:])):
        errors.append(dict(error='exidx function addresses not strictly increasing'))
    boundaries = sorted(pointers | {extab['sh_addr'] + extab['sh_size']})
    records = {}
    for low, high in zip(boundaries, boundaries[1:]):
        raw = image.read(low, high-low)
        if raw is None or len(raw)<4:
            errors.append(dict(error='unreadable extab record', address=low))
            continue
        word = struct.unpack_from('<I',raw)[0]
        records[low] = ('compact',raw.hex()) if word&0x80000000 else ('generic',image.target(prel(low,word)),raw[4:].hex())
    return dict(rows=[(target,kind,records.get(value,('missing',hex(value))) if kind=='extab' else value) for target,kind,value in rows],
                errors=errors, unique_extab_records=len(records))


def rodata_change_census(before, after, source):
    a,b=before.split(b'\0'),after.split(b'\0')
    changes=[]
    for tag,low,high,start,stop in difflib.SequenceMatcher(None,a,b,autojunk=True).get_opcodes():
        if tag=='equal':
            continue
        inserted=b[start:stop]
        source_literals=all(not value or (all(byte in (9,10,13) or 32<=byte<127 for byte in value) and value in source) for value in inserted)
        changes.append(dict(kind=tag,before_tokens=[v.hex() for v in a[low:high]],after_tokens=[v.hex() for v in inserted],
                            only_source_literals_or_null_padding=tag=='insert' and source_literals))
    return dict(changes=changes,binary_changes_explained_as_source_literal_insertions=all(row['only_source_literals_or_null_padding'] for row in changes))


def text_gaps(image):
    section=image.elf.get_section_by_name('.text')
    low,high=section['sh_addr'],section['sh_addr']+section['sh_size']
    intervals=sorted((f['address'],f['address']+f['size']) for f in image.functions.values() if low<=f['address']<high)
    merged=[]
    for start,stop in intervals:
        if merged and start<=merged[-1][1]:
            merged[-1][1]=max(merged[-1][1],stop)
        else:
            merged.append([start,stop])
    result=[];cursor=low
    for start,stop in merged+[[high,high]]:
        if cursor<start:
            raw=image.read(cursor,start-cursor)
            result.append(dict(before=sorted(name for name,f in image.functions.items() if f['address']+f['size']==cursor),
                               after=sorted(name for name,f in image.functions.items() if f['address']==start),bytes=raw.hex()))
        cursor=max(cursor,stop)
    return result


def eh_frames(image):
    def instructions(items):
        return [(item.opcode,[image.target(arg) if item.opcode==1 else arg for arg in item.args]) for item in items]
    entries=image.elf.get_dwarf_info().EH_CFI_entries()
    fdes={}
    rows=[]
    for entry in entries:
        if type(entry).__name__!='FDE':
            continue
        augmentation=dict(entry.augmentation_dict)
        if augmentation:
            raise ValueError('Unreviewed EH FDE augmentation')
        row=(image.target(entry['initial_location']),entry['address_range'],instructions(entry.instructions),instructions(entry.cie.instructions),
             entry.cie['code_alignment_factor'],entry.cie['data_alignment_factor'],entry.cie['return_address_register'])
        fdes[entry.offset]=(entry,row)
        rows.append(row)
    hdr=image.elf.get_section_by_name('.eh_frame_hdr');raw=hdr.data();base=hdr['sh_addr']
    frame=image.elf.get_section_by_name('.eh_frame')
    if raw[:4]!=bytes((1,0x1b,3,0x3b)) or len(raw)<12:
        raise ValueError('Unreviewed EH header encoding')
    pointer,count=struct.unpack_from('<iI',raw,4)
    if base+4+pointer!=frame['sh_addr'] or count!=len(fdes) or len(raw)!=12+count*8:
        raise ValueError('Invalid EH header extent/pointer')
    previous=-1
    for offset in range(12,len(raw),8):
        pc,fp=struct.unpack_from('<ii',raw,offset);pc+=base;fp+=base
        if pc<=previous or fp-frame['sh_addr'] not in fdes or fdes[fp-frame['sh_addr']][0]['initial_location']!=pc:
            raise ValueError('Invalid EH lookup table target')
        previous=pc
    return rows


def census(off, on, source):
    a,b=Image(off),Image(on)
    aa={s.name:s for s in a.sections};bb={s.name:s for s in b.sections}
    source_raw=Path(source).read_bytes()
    result=dict(off_sha256=digest(a.raw),on_sha256=digest(b.raw),source_sha256=digest(source_raw),sections={},
                full_unwind_semantics_proven=False,full_code_equivalence_proven=False,installed=False,savings_proven=False)
    for name in sorted(aa.keys()|bb.keys()):
        x,y=aa.get(name),bb.get(name)
        result['sections'][name]=dict(before_size=x['sh_size'] if x else None,after_size=y['sh_size'] if y else None,
                                     before_address=x['sh_addr'] if x else None,after_address=y['sh_addr'] if y else None,
                                     bytes_equal=x.data()==y.data() if x is not None and y is not None else False)
    old,new=relocations(a),relocations(b)
    differences=[]
    for key in sorted(old.keys()|new.keys()):
        if old.get(key)!=new.get(key):
            differences.append(dict(location=key,before=old.get(key),after=new.get(key)))
    result['relocations']=dict(before_count=len(old),after_count=len(new),differences=differences)
    words={}
    for name in ('.data.rel.ro','.got','.got.plt','.data','.init_array','.fini_array'):
        x,y=aa[name],bb[name];left,right=x.data(),y.data();changes=[]
        if len(left)!=len(right):
            changes.append(dict(error='extent changed'))
        for offset in range(0,min(len(left),len(right)),4):
            p,q=left[offset:offset+4],right[offset:offset+4]
            if p==q:
                continue
            key=(name,offset)
            if key in old and old.get(key)==new.get(key):
                continue
            changes.append(dict(offset=offset,before=p.hex(),after=q.hex(),relocation_before=old.get(key),relocation_after=new.get(key)))
        words[name]=changes
    result['nonrelocated_writable_word_changes']=words
    ua,ub=exidx(a),exidx(b)
    result['exidx']=dict(before_entries=len(ua['rows']),after_entries=len(ub['rows']),before_errors=ua['errors'],after_errors=ub['errors'],
                         differences=[dict(index=i,before=p,after=q) for i,(p,q) in enumerate(zip(ua['rows'],ub['rows'])) if p!=q])
    def strings(raw):
        return Counter(value for value in raw.split(b'\0') if value and all(byte in (9,10,13) or 32<=byte<127 for byte in value))
    sa,sb=strings(aa['.rodata'].data()),strings(bb['.rodata'].data())
    result['rodata_string_multiset']=dict(added=[dict(text=s.decode('ascii'),count=n,present_in_source=s in source_raw) for s,n in sorted((sb-sa).items())],
                                            removed=[dict(text=s.decode('ascii'),count=n) for s,n in sorted((sa-sb).items())],
                                            binary_rodata_equivalence_proven=False)
    result['rodata_binary_census']=rodata_change_census(aa['.rodata'].data(),bb['.rodata'].data(),source_raw)
    ga,gb=text_gaps(a),text_gaps(b)
    gap_key=lambda row:json.dumps((row['before'],row['after']))
    ga_map,gb_map={gap_key(row):row for row in ga},{gap_key(row):row for row in gb}
    gap_differences=[dict(before=ga_map.get(key),after=gb_map.get(key)) for key in sorted(ga_map.keys()|gb_map.keys()) if ga_map.get(key)!=gb_map.get(key)]
    result['text_outside_function_ranges']=dict(before_gaps=len(ga),after_gaps=len(gb),same_boundary_names_and_bytes=ga==gb,
        differences=gap_differences,changed_gap_bytes_only_D4_fill_under_16_bytes=all(all(row is None or (len(row['bytes'])<32 and set(bytes.fromhex(row['bytes']))<={0xd4}) for row in (change['before'],change['after'])) for change in gap_differences))
    def objects(image):
        return Counter((name,size,section_location(image,address)[0]) for address,rows in image.objects.items() for name,size in rows)
    oa,ob=objects(a),objects(b)
    result['allocated_objects']=dict(added=[dict(name=n,size=s,section=section,count=count) for (n,s,section),count in sorted((ob-oa).items())],
                                     removed=[dict(name=n,size=s,section=section,count=count) for (n,s,section),count in sorted((oa-ob).items())])
    ea,eb=eh_frames(a),eh_frames(b)
    result['eh_frame']=dict(before_fdes=len(ea),after_fdes=len(eb),lookup_tables_valid=True,
                           differences=[dict(index=i,before=p,after=q) for i,(p,q) in enumerate(zip(ea,eb)) if p!=q])
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('off','on','source','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    result=census(args.off,args.on,args.source)
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(relocation_changes=len(result['relocations']['differences']),unwind_changes=len(result['exidx']['differences']),
                          writable_changes={k:len(v) for k,v in result['nonrelocated_writable_word_changes'].items()},strings=result['rodata_string_multiset'])))

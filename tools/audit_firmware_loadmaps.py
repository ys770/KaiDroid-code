"""Read historical engineering modem FAT/MDT metadata; never infer reclaimable RAM from ELF gaps."""
import argparse
import hashlib
import io
import json
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

ENGINEERING_MODEM_SHA='93b3864c9e6c74aee6cec7b2e65a79c96b7aea1d33756fe5112c96c8efcbe253'


def extent_summary(segments):
    load=[s for s in segments if s['type']=='PT_LOAD' and s['memsz']]
    if not load or any(not 0<=s['filesz']<=s['memsz'] for s in load):
        raise ValueError('Invalid load-memory extents')
    intervals=sorted((s['paddr'],s['paddr']+s['memsz']) for s in load);merged=[]
    for start,end in intervals:
        if merged and start<=merged[-1][1]:merged[-1][1]=max(end,merged[-1][1])
        else:merged.append([start,end])
    end=max(end for start,end in intervals);span=end-intervals[0][0]
    union=sum(end-start for start,end in merged)
    return dict(load_file_bytes_sum=sum(s['filesz'] for s in load),
                load_mem_bytes_sum=sum(s['memsz'] for s in load),
                zero_fill_bytes_sum=sum(s['memsz']-s['filesz'] for s in load),
                declared_paddr_union_bytes=union,declared_paddr_span_bytes=span,
                declared_paddr_start=intervals[0][0],declared_paddr_end=end,
                declared_address_space_holes_bytes=span-union)


def audit(modem,manifest,dt,sevenzip):
    modem=Path(modem);manifest=Path(manifest);dt=Path(dt)
    digest=hashlib.sha256(modem.read_bytes()).hexdigest()
    if digest!=ENGINEERING_MODEM_SHA:raise ValueError('Not the retained engineering modem acquisition')
    matches=[e for e in json.loads(manifest.read_text())['extracted'] if e['sha256']==digest]
    if len(matches)!=1 or matches[0]['bytes']!=modem.stat().st_size:raise ValueError('Acquisition manifest mismatch')
    reserved=json.loads(dt.read_text());rows=[]
    for name,node in [('modem','modem_region@0'),('adsp','adsp_fw_region@0'),('wcnss','wcnss_fw_region@0')]:
        command=[sevenzip,'e','-so',str(modem),'image/'+name+'.mdt']
        extracted=subprocess.run(command,check=True,capture_output=True)
        data=extracted.stdout;elf=ELFFile(io.BytesIO(data))
        segments=[dict(index=i,type=s['p_type'],paddr=s['p_paddr'],vaddr=s['p_vaddr'],
                       filesz=s['p_filesz'],memsz=s['p_memsz'],flags=s['p_flags'],alignment=s['p_align'])
                  for i,s in enumerate(elf.iter_segments())]
        region=next(n['regions'][0] for n in reserved['nodes'] if n['node'].endswith('/'+node))
        extent=extent_summary(segments)
        rows.append(dict(name=name,mdt_sha256=hashlib.sha256(data).hexdigest(),mdt_bytes=len(data),
                         machine=elf['e_machine'],segments=segments,reserved_region=region,
                         reserved_minus_declared_span_bytes=region['bytes']-extent['declared_paddr_span_bytes'],
                         extraction_command=command,**extent))
    return dict(source='Historical same-handset engineering acquisition; not newly read runtime firmware',
                acquisition_path=matches[0]['path'],modem_partition_sha256=digest,
                partition_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                dt_evidence_sha256=hashlib.sha256(dt.read_bytes()).hexdigest(),
                dt_image=reserved.get('source_image'),dt_boot=reserved.get('source_boot'),firmwares=rows,
                scope='ELF-declared file/memory extents only. Physical-address fields have not been interpreted through exact PIL relocation/secure-loader rules. File sizes omit zero-fill/runtime memory; holes and reserve-minus-span are not proven reclaimable. No firmware rewriting, loading, device query, reservation change or memory saving.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('modem','manifest','dt','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--sevenzip',default='7z');args=parser.parse_args()
    report=audit(args.modem,args.manifest,args.dt,args.sevenzip)
    with args.output.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps([{key:row[key] for key in ('name','load_file_bytes_sum','zero_fill_bytes_sum','declared_paddr_span_bytes','reserved_minus_declared_span_bytes')} for row in report['firmwares']]))

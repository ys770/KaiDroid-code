"""Compare an unchanged Nokia Symbols PNG with the frozen original TCL capture.

No image editing, translation, tolerance-based acceptance or device operations.
Status and the requested soft-key exception remain explicit separate regions.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
DONOR=ROOT/'docs/screenshots/2026-10-27-tcl-symbols-reference/symbols-open.png'
DONOR_SHA='0d473271fa1fa79cc45a7ac557aa6ab5a82d46998feca8fbd9086c617ab23244'


def load(path,pin):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=pin:
        raise ValueError('Capture hash mismatch: '+str(path))
    with Image.open(path) as source:
        if source.size!=(240,320):raise ValueError('Expected actual240x320 screen')
        return source.convert('RGB')


def compare(left,right,left_box,right_box=None):
    a=left.crop(left_box);b=right.crop(right_box or left_box)
    if a.size!=b.size:raise ValueError('Comparison dimensions differ')
    histogram=Counter(max(abs(x-y) for x,y in zip(p,q)) for p,q in zip(a.get_flattened_data(),b.get_flattened_data()))
    total=a.width*a.height
    return dict(donor_bounds=list(left_box),nokia_bounds=list(right_box or left_box),
        pixels=total,identical_pixels=histogram[0],different_pixels=total-histogram[0],
        maximum_channel_delta=max(histogram),maximum_channel_delta_histogram=dict(sorted(histogram.items())))


def analyze(nokia,pin):
    donor=load(DONOR,DONOR_SHA);phone=load(nokia,pin)
    regions={name:compare(donor,phone,box) for name,box in [
        ('status',(0,0,240,24)),('editor_above_symbols',(0,24,240,224)),
        ('symbols_expected_position',(0,224,240,290)),
        ('softkey_exception',(0,290,240,320)),('full_frame',(0,0,240,320))]}
    # Diagnostic only: quantify the previously observed misplaced panel too.
    old=compare(donor,phone,(0,224,240,290),(0,254,240,320))
    return dict(scope='Actual unchanged captures; panel at donor coordinates with no translation',
        donor=dict(path=str(DONOR),sha256=DONOR_SHA),nokia=dict(path=str(nokia),sha256=pin),
        regions=regions,previous_wrong_position_diagnostic=old,
        pixel_perfect_symbols=regions['symbols_expected_position']['different_pixels']==0,
        full_frame_pixel_identical=regions['full_frame']['different_pixels']==0,
        geometry_inferred_from_pixels=False,remaining_differences_accepted=False,
        physical_keys_tested=False,full_parity=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nokia',type=Path,required=True)
    p.add_argument('--sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();report=analyze(a.nokia,a.sha256)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(dict(output=str(a.output),pixel_perfect_symbols=report['pixel_perfect_symbols'],
        regions={k:{name:v[name] for name in ('different_pixels','maximum_channel_delta')}
                 for k,v in report['regions'].items()})))


if __name__=='__main__':main()

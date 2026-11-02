"""Quantify captured Symbols residuals after measured translation; never edit images."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from PIL import Image

INPUTS=[('docs/screenshots/2026-10-27-tcl-symbols-reference/symbols-open.png',
 '0d473271fa1fa79cc45a7ac557aa6ab5a82d46998feca8fbd9086c617ab23244',(0,224,240,290)),
 ('docs/screenshots/2026-10-27-image53/notes-symbols-panel.png',
 'a4708e7e0eadbd0d5c2853e489b964b558383f8cdef0fda36ffbe3684317f587',(0,254,240,320))]


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];panels=[]
 for name,pin,box in INPUTS:
  path=root/name
  if hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise ValueError('Captured source PNG changed')
  with Image.open(path) as image:
   if image.size!=(240,320):raise ValueError('Unexpected capture dimensions')
   panels.append(image.convert('RGB').crop(box))
 old,new=panels;hist=Counter();regions=Counter();pairs=Counter()
 for y in range(66):
  for x in range(240):
   b,c=old.getpixel((x,y)),new.getpixel((x,y))
   delta=max(abs(i-j) for i,j in zip(b,c));hist[delta]+=1
   if delta:
    regions['top_left_33px_selection' if x<33 and y<33 else 'remaining_panel']+=1;pairs[(b,c)]+=1
 offsets=[]
 for name,top,bottom in [('top',0,33),('bottom',33,66)]:
  choices=[]
  for dx in range(-3,4):
   for dy in range(-4,5):
    count=sum(old.getpixel((x,y))!=new.getpixel((x+dx,y+dy)) for y in range(top+4,bottom-4) for x in range(34,236))
    choices.append(dict(dx=dx,dy=dy,different_pixels=count))
  offsets.append(dict(row=name,best=sorted(choices,key=lambda r:r['different_pixels'])[:4]))
 report=dict(scope='Only original TCL and image53 Symbols panel after exact30px translation; screenshots unchanged',
  source_captures=[dict(path=n,sha256=h,panel_bounds=b) for n,h,b in INPUTS],
  pixels=240*66,identical_pixels=hist[0],different_pixels=240*66-hist[0],max_channel_delta=max(hist),
  max_channel_delta_histogram=dict(sorted(hist.items())),different_pixels_by_region=dict(regions),
  largest_difference_color_pairs=[dict(donor=b,nokia=c,pixels=count) for (b,c),count in pairs.most_common(5)],
  glyph_interior_offset_search=offsets,
  inference='Residuals are mostly one-channel-level rendering/composition differences; exact cause is not established',
  full_frame_comparison=False,remaining_pixel_differences_accepted=False,native_footer_candidate_installed=False,full_parity=False)
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with a.output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
 print(json.dumps(report))


if __name__=='__main__':main()

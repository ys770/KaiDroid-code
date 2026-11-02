"""Check captured Clock picker geometry/selector colors; no phone operations."""
import argparse
import hashlib
import json
from pathlib import Path
from PIL import Image
from check_tcl_ime_picker_layout import validate, xml_nodes

ACTIVE=(101,136,186)
NORMAL=(239,240,243)


def check(png,xml,selected):
 layout=validate(xml_nodes(xml))
 if not layout['passed']:raise ValueError('Clock six-mode geometry differs: '+str(layout['errors']))
 with Image.open(png) as source:
  if source.size!=(240,320):raise ValueError('Wrong screenshot size')
  rgb=source.convert('RGB')
  colors=[rgb.getpixel((5,(b[1]+b[3])//2)) for b in layout['row_text_bounds']]
 expected=[ACTIVE if i==selected else NORMAL for i in range(6)]
 if colors!=expected:raise ValueError('Clock app selector pixels or active row differ: '+str(colors))
 return dict(six_mode_geometry_passed=True,expected_selected_row=selected,row_background_rgb=colors,
             original_clock_selector_colors=True,full_pixel_parity=False,physical_keys=False)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('png','xml','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--sha256',required=True)
 p.add_argument('--selected',type=int,choices=range(6),required=True)
 a=p.parse_args()
 if hashlib.sha256(a.png.read_bytes()).hexdigest()!=a.sha256:raise ValueError('Capture hash differs')
 result=check(a.png,a.xml.read_text(),a.selected)
 result['png_sha256']=a.sha256
 result['xml_sha256']=hashlib.sha256(a.xml.read_bytes()).hexdigest()
 with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result))


if __name__=='__main__':main()

"""Quantify captured Clock/Tools content; preserve footer and state differences explicitly."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from PIL import Image,ImageChops

PAIRS=[('alarm','clock-entry','clock-entry'),('timer','clock-next-tab01','clock-timer'),
 ('stopwatch','clock-next-tab02','clock-stopwatch'),('world','clock-next-tab03','clock-world'),
 ('snooze','clock-snooze-dialog','clock-snooze-dialog'),('settings','clock-settings','clock-settings'),
 ('tools','tools-folder','tools-folder'),('tools-clock-focus','tools-clock-right','tools-clock-right')]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def image(root,state):
 path=root/state/'screen.png';receipt=json.loads((root/state/'capture.json').read_text())
 if sha(path)!=receipt['screenshot_sha256']:raise ValueError('Capture receipt mismatch: '+str(path))
 with Image.open(path) as im:
  if im.size!=(240,320):raise ValueError('Wrong capture dimensions')
  return im.convert('RGB'),dict(path=str(path),sha256=sha(path))


def region(a,b,box):
 left,right=a.crop(box),b.crop(box)
 hist=Counter(max(abs(x-y) for x,y in zip(p,q)) for p,q in zip(left.get_flattened_data(),right.get_flattened_data()))
 bbox=ImageChops.difference(left,right).getbbox()
 if bbox:bbox=[bbox[0]+box[0],bbox[1]+box[1],bbox[2]+box[0],bbox[3]+box[1]]
 return dict(bounds=box,pixels=left.width*left.height,identical_pixels=hist[0],different_pixels=sum(n for k,n in hist.items() if k),
   maximum_channel_delta=max(hist),maximum_channel_delta_histogram=dict(sorted(hist.items())),difference_bounds=bbox)


def labels(root,state):
 nodes=ET.fromstring((root/state/'hierarchy.xml').read_text(encoding='utf-8')).iter('node')
 return [n.get('text') for n in nodes if n.get('resource-id')=='com.android.launcher3:id/icon' and n.get('text')]


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('donor-root','nokia-root','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();restored=json.loads((a.nokia_root/'result.json').read_text())
 if not all(restored.get(k) is True for k in ['same_ime_and_bluetooth','original_clock_data_same','tcl_clock_appfiles_same','exact_home_restored']):
  raise ValueError('Nokia restoration/data preservation not verified')
 comparisons=[]
 for name,donor,nokia in PAIRS:
  old,op=image(a.donor_root,donor);new,np=image(a.nokia_root,nokia)
  comparisons.append(dict(scenario=name,source=[op,np],content=region(old,new,[0,24,240,290]),
    footer=region(old,new,[0,290,240,320]),
    starting_state_fully_matched=name not in ('settings','tools','tools-clock-focus'),
    state_difference=('Alarm volume donor12/Nokia0; no setting changed for comparison' if name=='settings' else
      'Different selected wallpapers; body includes background, so this is not an isolated layout comparison' if name.startswith('tools') else None)))
 report=dict(scope='Exact captured PNG comparison; no images changed, shifted or color-normalized',
  comparisons=comparisons,status_bar_excluded_reason='Different clock,radio,notification andbattery states; not pixel acceptance',
  footer_reported_separately_reason='Requested Kyocera soft-key exception; counts retained, no inferred blanket waiver',
  launcher_grid=dict(donor=labels(a.donor_root,'tools-navigation-grid'),nokia=labels(a.nokia_root,'tools-grid'),
    observed_difference='Donor Apps folder is absent on Nokia, changing Tools cell and Music-Down destination',
    cause_established=False,installed_app_inventory_equivalence_verified=False),
  nokia_runtime=dict(image=56,boot=restored['boot'],same_ime_and_bluetooth=True,original_clock_data_same=True,tcl_clock_appfiles_same=True,exact_home_restored=True),
  key_input='ADB-injected; physical timing/switches not tested',pixel_acceptance=False,full_frame_comparison=False,full_parity=False)
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with a.output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
 print(json.dumps({r['scenario']:dict(different=r['content']['different_pixels'],max_delta=r['content']['maximum_channel_delta']) for r in comparisons}))


if __name__=='__main__':main()

"""Exact resource-only build boundaries; pure checks except explicitly named I/O."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
NAME='tcl-scrollbar-build01'
BACKING='/mnt/ext1/kaidroid-tcl-scrollbar-build01'
IMAGE='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
RESOURCE='aosp/frameworks/base/core/res/res'
TARGET='/build/out-eng-02/target/product/n139dl/system/framework/framework-res.apk'
BASE='42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
STYLES='7e9be3dec059b888860ff34f6995c1a3957d13bc8ec521c35797a386adb74fbe'
GIB=1024**3
CONTROLS={'build.sh','launch.sh','targets.txt','disk-monitor.py','layered_dialog_output.py','tcl_scrollbar_build_contract.py'}
OVERLAY={
 'values/styles.xml':'bc5d94a3f61009f9419e6577bc95b0e2838a866c62d1bda15d233ed31ccaf9a3',
 'drawable-mdpi/zz_kaidroid_tcl_listview_scrollbar_img.9.png':'193448a679f1cfefed56ead2f3d44a4fef82baa2cceecfc65718081182509a48',
 'drawable-mdpi/zz_kaidroid_tcl_listview_track_img.9.png':'55ff6bfd5c4beb64b8e368a3955a92b40ea8460e2f03af2843cd1e662c8220eb',
}


def sha(path):
 digest=hashlib.sha256()
 with path.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
 return digest.hexdigest()


def within(path,root):
 try:path.relative_to(root);return True
 except ValueError:return False


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def dump(path,value):
 with path.open('x',encoding='utf-8',newline='\n') as stream:json.dump(value,stream,indent=2);stream.write('\n')


def safe_relative(name):
 p=Path(name)
 if p.anchor or '..' in p.parts or '\\' in name or not name or p.as_posix()!=name:
  raise ValueError('Unsafe relative path: '+name)
 return p


def inventory(root):
 rows={}
 def item(path):
  relative=path.relative_to(root).as_posix();s=path.lstat()
  row=dict(mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,
           xattrs={n:os.getxattr(path,n,follow_symlinks=False).hex() for n in os.listxattr(path,follow_symlinks=False)})
  if stat.S_ISREG(s.st_mode):row['sha256']=sha(path)
  elif stat.S_ISLNK(s.st_mode):
   row['target']=os.readlink(path)
   if not within(path.resolve(strict=True),root):raise ValueError('Escaping resource symlink: '+str(path))
  elif not stat.S_ISDIR(s.st_mode):raise ValueError('Unexpected resource source type: '+str(path))
  rows[relative]=row
 item(root)
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:item(Path(folder)/name)
 return rows


def compare_source(before,after):
 added=set(after)-set(before);removed=set(before)-set(after)
 expected=set(OVERLAY)-{'values/styles.xml'}
 changed={n for n in before.keys()&after.keys() if before[n]!=after[n]}
 if added!=expected or removed or changed!={'values/styles.xml'}:
  raise ValueError('Resource tree drift beyond one style file and two new assets')
 if before['values/styles.xml'].get('sha256')!=STYLES:raise ValueError('Wrong original styles')
 for name,pin in OVERLAY.items():
  row=after[name]
  if row.get('sha256')!=pin or stat.S_IFMT(row['mode'])!=stat.S_IFREG:
   raise ValueError('Wrong resource overlay payload/type: '+name)
  if name in before:
   if {k:v for k,v in row.items() if k!='sha256'}!={k:v for k,v in before[name].items() if k!='sha256'}:
    raise ValueError('Existing style metadata changed')
  elif (row['mode'],row['uid'],row['gid'],row['xattrs'])!=(stat.S_IFREG|0o644,1000,1000,{}):
   raise ValueError('New private asset metadata differs')
 return dict(modified=['values/styles.xml'],added=sorted(added),removed=[])


def bind_map(root,stage):
 cp='/build/'+NAME
 values={'/build':(root.as_posix(),False),'/baseline':(root.as_posix(),False),
  cp:(stage.as_posix(),True),'/build/out-eng-02':((stage/'out').as_posix(),True),
  '/build/'+RESOURCE:((stage/'inputs/res').as_posix(),False),
  cp+'/inputs':((stage/'inputs').as_posix(),False),cp+'/lower-ro':((stage/'lower-ro').as_posix(),False),
  cp+'/out':((stage/'out').as_posix(),True),cp+'/control-inputs.json':((stage/'control-inputs.json').as_posix(),False)}
 for name in sorted(CONTROLS|{'staging.json','preparation.complete'}):
  values[cp+'/'+name]=((stage/name).as_posix(),False)
 return values


def verify_pins(root,pins):
 for name,pin in pins.items():
  p=root/safe_relative(name)
  if p.resolve(strict=True)!=p or sha(p)!=pin:raise ValueError('Retained/shared source changed: '+name)


def load_stage(root,stage):
 root=root.resolve(strict=True);stage=stage.resolve(strict=True)
 if root not in (ROOT,Path('/build')) or stage!=root/NAME:raise ValueError('Wrong resource build stage')
 spec=json.loads((stage/'staging.json').read_text())
 if (stage/'preparation.complete').read_text().strip()!=sha(stage/'staging.json'):
  raise ValueError('Preparation identity changed')
 if spec.get('kind')!='tcl-scrollbar-resource-only01' or spec.get('target')!=TARGET or spec.get('baseline_framework_res_sha256')!=BASE:
  raise ValueError('Unreviewed resource-only target/baseline')
 controls=json.loads((stage/'control-inputs.json').read_text())
 if set(controls)!=CONTROLS|{'staging.json'} or spec.get('source_controls')!={n:controls[n] for n in CONTROLS}:
  raise ValueError('Exact resource control set changed')
 for name,pin in controls.items():
  if (stage/name).resolve(strict=True)!=stage/name or sha(stage/name)!=pin:raise ValueError('Frozen control changed: '+name)
 storage=spec.get('external_storage',{})
 if storage.get('volume')!='/mnt/ext1' or storage.get('backing')!=BACKING or storage.get('device')!='8:0' or storage.get('root_floor_bytes')!=20*GIB:
  raise ValueError('Resource storage boundary differs')
 plan=spec.get('disk_plan',{})
 if plan.get('incremental_budget_bytes')!=14*GIB or plan.get('emergency_floor_bytes')!=20*GIB or type(plan.get('free_after_clone_bytes')) is not int or plan['free_after_clone_bytes']<34*GIB:
  raise ValueError('Unreviewed resource disk budget')
 if spec.get('runtime_limit_seconds')!=1800:raise ValueError('Unreviewed compiler deadline')
 builder=spec.get('builder_identity',{});owner=stage.stat()
 if builder!=dict(image_id=IMAGE,image_user='builder',uid=1000,gid=1000) or (owner.st_uid,owner.st_gid)!=(1000,1000) or stat.S_IMODE(owner.st_mode)!=0o700:
  raise ValueError('Resource stage/builder identity differs')
 from layered_dialog_output import verify_mounts
 verify_mounts(stage,spec)
 return spec


def verify_inputs(stage,spec):
 verify_pins(ROOT if stage.parent==ROOT else Path('/baseline'),spec['baseline_pins'])
 expected=spec['inputs'];actual={p.relative_to(stage/'inputs').as_posix() for p in (stage/'inputs').rglob('*') if p.is_file() and not within(p,stage/'inputs/res')}
 if actual!=set(expected):raise ValueError('Non-resource source coverage changed')
 for name,pin in expected.items():
  p=stage/'inputs'/safe_relative(name)
  if p.resolve(strict=True)!=p or sha(p)!=pin:raise ValueError('Resource input proof changed: '+name)
 before=json.loads((stage/'inputs/resource-before.json').read_text())
 after=json.loads((stage/'inputs/resource-after.json').read_text())
 compare_source(before,after)
 if inventory(stage/'inputs/res')!=after:raise ValueError('Owned resource source tree changed')
 original=(ROOT if stage.parent==ROOT else Path('/baseline'))/RESOURCE
 if inventory(original)!=before:raise ValueError('Original shared resource source changed')


def validate_container(info,root,stage,cid):
 spec=json.loads((stage/'staging.json').read_text());config=info.get('Config',{});host=info.get('HostConfig',{})
 if not re.fullmatch('[0-9a-f]{64}',cid) or info.get('Id')!=cid or info.get('Name')!='/kaidroid-'+NAME or info.get('Image')!=IMAGE or config.get('Image')!='kaidroid-build:20261023' or config.get('User')!='builder':
  raise ValueError('Resource container identity differs')
 if config.get('Cmd')!=['bash','/build/'+NAME+'/build.sh'] or config.get('Labels',{}).get('kaidroid.dialog.stage')!=NAME or config.get('Labels',{}).get('kaidroid.dialog.staging')!=sha(stage/'staging.json'):
  raise ValueError('Resource command/staging identity differs')
 if host.get('NetworkMode')!='none' or host.get('Memory')!=8*GIB or host.get('MemorySwap')!=8*GIB or host.get('PidsLimit')!=512 or host.get('NanoCpus')!=2000000000 or host.get('CpusetCpus')!=','.join(map(str,spec['cpus'])) or host.get('OomKillDisable') not in (None,False):
  raise ValueError('Resource container caps differ')
 actual={}
 for mount in info.get('Mounts',[]):
  dest=mount.get('Destination')
  if mount.get('Type')!='bind' or dest in actual:raise ValueError('Unknown/duplicate resource mount')
  actual[dest]=(mount.get('Source'),mount.get('RW'))
 if actual!=bind_map(root,stage):raise ValueError('Resource container writable scope differs')

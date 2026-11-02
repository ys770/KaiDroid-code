"""Validate the observed recursive-RO/source plus explicit-RW pack mount graph."""
import re
from pathlib import PurePosixPath

ROOT='/opt/kaidroid/kaidroid-build-20261023'
EXPECTED={
 'engineering-tcl-ime-footer-stage-57':'/mnt/ext1/kaidroid-tcl-ime-footer-image57',
 'engineering-tcl-ime-footer-stage-57-retry01':'/mnt/ext1/kaidroid-tcl-ime-footer-image57-retry01',
 'engineering-tcl-ime-footer-stage-57-retry02':'/mnt/ext1/kaidroid-tcl-ime-footer-image57-retry02',
}


def parse(text):
 def decode(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
 rows=[];ids=set()
 for line in text.splitlines():
  left,right=line.split(' - ',1);a=left.split();b=right.split()
  if len(a)<6 or len(b)<3:raise ValueError('Incomplete mountinfo record')
  mid,parent=int(a[0]),int(a[1])
  if mid<=0 or mid in ids or not re.fullmatch(r'\d+:\d+',a[2]):raise ValueError('Duplicate/invalid mount identity')
  ids.add(mid)
  rows.append(dict(id=mid,parent=parent,device=a[2],root=decode(a[3]),point=decode(a[4]),
    options=set(a[5].split(',')),optional=a[6:],fstype=b[0],source=decode(b[1]),super_options=set(b[2].split(','))))
 return rows


def validate(text,stage_name,backing):
 if EXPECTED.get(stage_name)!=backing:raise ValueError('Unreviewed stage/backing pair')
 rows=parse(text);point='/build/'+stage_name;extroot='/'+PurePosixPath(backing).name
 def at(path):return [r for r in rows if r['point']==path]
 def single(path):
  found=at(path)
  if len(found)!=1:raise ValueError('Expected one mount: '+path)
  return found[0]
 def mode(row,expected):
  if expected not in row['options'] or ({'ro','rw'}-{expected})&row['options']:raise ValueError('Effective mount mode differs: '+row['point'])
 def external(row,root,parent,expected):
  if row['device']!='8:0' or row['root']!=root or row['source']!='/dev/sda' or row['fstype']!='ext4' or row['parent']!=parent or row['optional'] or 'rw' not in row['super_options'] or 'ro' in row['super_options']:raise ValueError('External mount identity/parent differs: '+row['point'])
  mode(row,expected)
 top=single('/');mode(top,'ro')
 if top['fstype']!='overlay' or top['source']!='overlay':raise ValueError('Unexpected container root filesystem')
 build=single('/build');mode(build,'ro')
 if build['parent']!=top['id'] or build['root']!=ROOT or build['device']!='259:2' or build['source']!='/dev/nvme0n1p2' or build['fstype']!='ext4' or build['optional']:raise ValueError('Read-only build source identity differs')
 stack=at(point)
 if len(stack)!=2:raise ValueError('Expected exact inherited-RO and explicit-RW stage stack')
 lower=[r for r in stack if r['parent']==build['id']]
 if len(lower)!=1:raise ValueError('Inherited stage does not descend from read-only build mount')
 lower=lower[0];upper=[r for r in stack if r['parent']==lower['id']]
 if len(upper)!=1:raise ValueError('Explicit stage does not overmount the inherited stage')
 upper=upper[0];external(lower,extroot,build['id'],'ro');external(upper,extroot,lower['id'],'rw')
 children={point+'/'+n:extroot+'/'+n for n in ('inputs','records','staging.json','staging.complete')}
 child_ids={}
 for path,root in children.items():
  row=single(path);external(row,root,upper['id'],'ro');child_ids[path]=row['id']
 for row in rows:
  if row['point'].startswith(point+'/') and row['point'] not in children:raise ValueError('Unexpected submount inside pack stage')
  if row['point'].startswith('/build/') and row['point']!=point and not row['point'].startswith(point+'/'):mode(row,'ro')
 tmp=single('/tmp');external(tmp,extroot+'/tmp',top['id'],'rw')
 return dict(exact_two_stage_mounts=True,inherited_readonly_mount=lower['id'],effective_writable_mount=upper['id'],
  parent_chain=[top['id'],build['id'],lower['id'],upper['id']],same_external_device_root_source=True,
  readonly_child_mounts=child_ids,private_tmp_mount=tmp['id'],all_other_build_submounts_readonly=True,
  mountinfo_order_not_used=True)

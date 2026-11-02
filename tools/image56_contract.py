"""Fixed image55-to56 content/metadata contract; no process or device operations."""
import hashlib,json,stat
from pathlib import Path
BASE='c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
BASE_MANIFEST='fe0d50f7771b7e1dca982a94b3025a68ee228f4b68399378ad84b449f10fbdde'
BASE_OUTPUTS='15a52b2c52c8765acfc8d03239ec265ae58b0cb1c579cf83af54ddce6a816f55'
PROPOSAL='7bb2006d80a2d3404ba5137effc799aa9508196093983d5e64cb7243de27f676'
OLD='cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62'
NEW='5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258'
LIB='apex/com.android.art.release/lib/libart.so'
CHANGES={LIB,'build.prop'}
ROOT=Path('/opt/kaidroid/kaidroid-build-20261023');BASE_NAME='engineering-tcl-dialog-access-stage-55';NAME='engineering-services-appimage-stage-56'
PARTITION=834666496;FLOOR=20*1024**3
BUILDER='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
TOOLS={'image56_contract.py','stage_services_image56.py','build_services_image56.sh','verify_services_image56_closure.py'}
def digest(stream):
 h=hashlib.sha256()
 for block in iter(lambda:stream.read(1048576),b''):h.update(block)
 return h.hexdigest()
def sha(path):
 with path.open('rb') as f:return digest(f)
def dump(path,value):
 with path.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
def proposal(path):
 if sha(path)!=PROPOSAL:raise ValueError('Exact reviewed proposal required')
 r=json.loads(path.read_text())
 if r['image']!=56 or r['baseline_image']!=55 or r['base_raw_sha256']!=BASE or set(r['changed'])!=CHANGES or r['new_libart_sha256']!=NEW:raise ValueError('Proposal contract differs')
 return r
def props56(raw):
 if raw.splitlines().count(b'ro.kaidroid.image=55')!=1 or raw.count(b'ro.kaidroid.image=55')!=1:raise ValueError('Wrong baseline revision')
 return raw.replace(b'ro.kaidroid.image=55',b'ro.kaidroid.image=56',1)
def config56(text):
 before='/build/'+BASE_NAME+'/';after='/build/'+NAME+'/'
 if text.count(before)!=2 or text.count('--do_not_generate_fec')!=1:raise ValueError('Pack config path/FEC contract changed')
 return text.replace(before,after)
def raw_inventory(path):
 from dissect.extfs import ExtFS
 rows={};attrs={}
 with path.open('rb') as stream:
  fs=ExtFS(stream)
  def visit(node,name):
   row=dict(mode=int(node.inode.i_mode),uid=int(node.inode.i_uid)|(int(node.inode.i_uid_high)<<16),gid=int(node.inode.i_gid)|(int(node.inode.i_gid_high)<<16),kind=node.filetype)
   if node.filetype==stat.S_IFREG:
    with node.open() as data:row['sha256']=digest(data)
   elif node.filetype==stat.S_IFLNK:row['target']=node.link
   rows[name]=row;attrs[name]={}
   for attr in node.xattr:
    if attr.name in attrs[name]:raise ValueError('Duplicate xattr')
    attrs[name][attr.name]=attr.value.hex()
   if node.filetype==stat.S_IFDIR:
    for child in node.iterdir():
     if child.filename not in ('.','..'):visit(child,name.rstrip('/')+'/'+child.filename)
  visit(fs.get('/'),'/');props=fs.get('/system/build.prop').open().read()
 return rows,attrs,props
def compare_raw(before,after,bx,ax,oldprops,newprops):
 if before.keys()!=after.keys() or bx.keys()!=before.keys() or ax.keys()!=after.keys():raise ValueError('Raw path coverage changed')
 if bx!=ax:raise ValueError('Raw xattrs changed')
 changed={n for n in before if before[n]!=after[n]}
 if changed!={'/system/'+n for n in CHANGES}:raise ValueError('Not exact two-file raw delta')
 for n in changed:
  if {k:v for k,v in before[n].items() if k!='sha256'}!={k:v for k,v in after[n].items() if k!='sha256'}:raise ValueError('Raw inode metadata changed')
 if before['/system/'+LIB]['sha256']!=OLD or after['/system/'+LIB]['sha256']!=NEW:raise ValueError('Wrong ART pair')
 if newprops!=props56(oldprops):raise ValueError('Additional build.prop mutation')
 for raw,rows in [(oldprops,before),(newprops,after)]:
  if rows['/system/build.prop']['sha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('Property hash mismatch')
 return changed

"""Create a local exact55->56 payload/closure proposal; no host, pack or phone mode."""
import argparse,hashlib,json,shutil,stat
from pathlib import Path
BASE='c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
MANIFEST='fe0d50f7771b7e1dca982a94b3025a68ee228f4b68399378ad84b449f10fbdde'
OLD='cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62'
NEW='5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258'
LIB='apex/com.android.art.release/lib/libart.so'
PARTITION=834666496

def digest(stream):
 h=hashlib.sha256()
 for block in iter(lambda:stream.read(1048576),b''):h.update(block)
 return h.hexdigest()
def sha(path):
 with path.open('rb') as f:return digest(f)
def dump(path,value):path.write_bytes((json.dumps(value,indent=2)+'\n').encode())
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','manifest','binary','review','output-dir'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();identity=(a.baseline.stat().st_size,a.baseline.stat().st_mtime_ns)
 if identity[0]!=PARTITION or sha(a.baseline)!=BASE or sha(a.manifest)!=MANIFEST or sha(a.binary)!=NEW:raise ValueError('Exact reviewed raw/manifest/binary required')
 stage=json.loads(a.manifest.read_text());review=json.loads(a.review.read_text())
 if stage['image']!=55 or stage['system_partition_bytes']!=PARTITION or not review['linked_layout_review']['trial_recommended'] or not review['interface_screen']['interface_protection_screen_pass'] or review['outputs']['stripped']['sha256']!=NEW or review['installed']:raise ValueError('Source or binary review differs')
 from dissect.extfs import ExtFS
 rows={};attrs={}
 with a.baseline.open('rb') as f:
  fs=ExtFS(f)
  def visit(node,name):
   row=dict(mode=int(node.inode.i_mode),uid=int(node.inode.i_uid),gid=int(node.inode.i_gid),kind=node.filetype)
   if node.filetype==stat.S_IFREG:
    with node.open() as data:row['sha256']=digest(data)
   elif node.filetype==stat.S_IFLNK:row['target']=node.link
   rows[name]=row;attrs[name]={}
   for x in node.xattr:
    if x.name in attrs[name]:raise ValueError('Duplicate xattr')
    attrs[name][x.name]=x.value.hex()
   if node.filetype==stat.S_IFDIR:
    for child in node.iterdir():
     if child.filename not in ('.','..'):visit(child,name.rstrip('/')+'/'+child.filename)
  visit(fs.get('/'),'/');props=fs.get('/system/build.prop').open().read()
 if rows['/system/'+LIB]['sha256']!=OLD:raise ValueError('Baseline libart changed')
 if props.splitlines().count(b'ro.kaidroid.image=55')!=1 or props.count(b'ro.kaidroid.image=55')!=1:raise ValueError('Build identity differs')
 newprops=props.replace(b'ro.kaidroid.image=55',b'ro.kaidroid.image=56',1)
 for group in ('exported_files','art_apex','protected54_sha256','preserved_alarm_files'):
  for name,pin in stage[group].items():
   if rows['/system/'+name]['sha256']!=pin:raise ValueError('Baseline closure changed '+name)
 if (a.baseline.stat().st_size,a.baseline.stat().st_mtime_ns)!=identity:raise ValueError('Raw changed during reading')
 out=a.output_dir.resolve()
 if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep local proposal in workspace')
 out.mkdir(parents=True,exist_ok=False)
 target=out/'payload'/LIB;target.parent.mkdir(parents=True);shutil.copyfile(a.binary,target)
 if sha(target)!=NEW:raise ValueError('Copied binary changed')
 (out/'payload/build.prop').write_bytes(newprops)
 dump(out/'baseline-raw-inventory.json',rows);dump(out/'baseline-xattrs.json',attrs)
 change={}
 for name,pin in [(LIB,NEW),('build.prop',hashlib.sha256(newprops).hexdigest())]:
  old=rows['/system/'+name];change[name]=dict(before=old,after={**old,'sha256':pin},xattrs_unchanged=attrs['/system/'+name])
 result=dict(image=56,baseline_image=55,proposal_only=True,host_staged=False,built=False,installed=False,base_raw_sha256=BASE,base_manifest_sha256=MANIFEST,baseline_raw_bytes=PARTITION,base_host_stage='engineering-tcl-dialog-access-stage-55',proposed_host_stage='engineering-services-appimage-stage-56',
  binary_review_sha256=sha(a.review),compile_record_sha256=review['compile_record_sha256'],candidate_source_sha256='f35f5abc6310b349fb57aed5091ea5a677bb07ac523aeb86d17522195de1c09f',changed=change,
  flattened_apex_source='/system/'+LIB,old_libart_sha256=OLD,new_libart_sha256=NEW,unstripped_artifact_sha256='2f1f266896df25fd458fe362fd5120e2211cf9305926b7737deb06bc558d3f8b',
  baseline_filesystem_entries=len(rows),baseline_xattr_count=sum(len(v) for v in attrs.values()),baseline_inventory_sha256=sha(out/'baseline-raw-inventory.json'),baseline_xattrs_sha256=sha(out/'baseline-xattrs.json'),
  retained_framework_exports=stage['exported_files'],retained_art_java_preopt=stage['art_apex'],retained_protected=stage['protected54_sha256'],retained_alarms=stage['preserved_alarm_files'],
  apex_metadata={k:v for k,v in rows.items() if k.startswith('/system/apex/com.android.art.release/') and '/lib/' not in k and '/javalib/' not in k},
  raw_delta_contract='Exactly2contenthashchanges; all other paths/content, inode mode/UID/GID/kind/symlinks and all xattrs identical to55. Timestamps/inode allocation excluded.',
  pack=dict(builder='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d',partition_size=PARTITION,signed_hashtree=True,signature_algorithm='SHA256_RSA2048',tree_hash_algorithm='sha1',optional_fec=False,max_payload_bytes=828018688,baseline_file_contexts_sha256=stage['metadata_files_sha256']['file_contexts.txt'],baseline_pack_config_sha256=stage['metadata_files_sha256']['system_image_info.compact.txt']),
  paired_artifact_constraints=['Use the new stripped ARM32 release libart only; retain its matching unstripped library/manager object/debuglink provenance outside image.','Retain all55services/framework/bootpreopt/ARTJava and other ART libraries/flattened APEX metadata; no preopt or ART/JAR/APEX regeneration.','All existing vendor/calibration/data/signedbootchain/partitions outside system remain unchanged; preserve original55raw for rollback.','No APN/UI/MMS/IME/catalog/property-policy edits; build.prop changes only ro.kaidroid.image55to56.'],
  limits=['Local complete baseline inventory and payload preparation, not actual host staging/packing/AVB verification or installation.','Packed raw must independently pass exact55two-file closure including all xattrs; staged tree inventories alone are insufficient.','Running selected ART library and fallback behavior/memory must be verified in a separate hardware-owned engineering trial.'])
 dump(out/'proposal.json',result);print(json.dumps(dict(proposal=str(out),proposal_sha256=sha(out/'proposal.json'),entries=len(rows),changed=sorted(change),built=False)))
if __name__=='__main__':main()

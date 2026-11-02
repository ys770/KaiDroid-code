"""Read exact image58 and reviewed native14 receipts offline; never stage or launch."""
import argparse,copy,hashlib,json,re,sys
from pathlib import Path
import ime_handover_image59_contract as c

def inventory(raw,output,deps=None):
 if raw.is_symlink() or raw.stat().st_size!=c.PARTITION or c.sha(raw)!=c.BASE:raise ValueError('Exact image58 raw required')
 if deps:sys.path.insert(0,str(deps.resolve()))
 from image56_contract import raw_inventory
 before,attrs,props=raw_inventory(raw)
 if before['/system/framework/framework.jar']['sha256']!=c.OLD_FRAMEWORK or props.splitlines().count(b'ro.kaidroid.image=58')!=1:raise ValueError('Raw image58 payload identity differs')
 output.mkdir(parents=True,exist_ok=False)
 for n,data in [('raw-inventory.json',before),('xattrs.json',attrs)]:c.dump(output/n,data)
 (output/'build.prop').write_bytes(props)
 c.dump(output/'receipt.json',dict(raw_sha256=c.BASE,raw_bytes=c.PARTITION,
  filesystem_entries=len(before),files={n:c.sha(output/n) for n in ('raw-inventory.json','xattrs.json','build.prop')},read_only=True))
 return dict(inventory=str(output),filesystem_entries=len(before),read_only=True)

def create(baseline,native,cache_path,review_path,config,output):
 receipt=json.loads((baseline/'receipt.json').read_text())
 if receipt.get('raw_sha256')!=c.BASE or receipt.get('raw_bytes')!=c.PARTITION or receipt.get('read_only') is not True:raise ValueError('Baseline raw provenance missing')
 for n in ('raw-inventory.json','xattrs.json','build.prop'):
  if (baseline/n).is_symlink() or c.sha(baseline/n)!=receipt['files'].get(n):raise ValueError('Baseline inventory drift: '+n)
 rows=json.loads((baseline/'raw-inventory.json').read_text());attrs=json.loads((baseline/'xattrs.json').read_text())
 if rows.keys()!=attrs.keys() or rows['/system/framework/framework.jar']['sha256']!=c.OLD_FRAMEWORK:raise ValueError('Baseline coverage/framework differs')
 oldprops=(baseline/'build.prop').read_bytes();newprops=c.props59(oldprops)
 if rows['/system/build.prop']['sha256']!=hashlib.sha256(oldprops).hexdigest():raise ValueError('Baseline properties differ')
 meta=json.loads((native/'staging.json').read_text());exports=json.loads((native/'outputs.json').read_text())
 cache=json.loads(cache_path.read_text());review=json.loads(review_path.read_text())
 # The signed image58 system retains these exact30 export paths from native12.
 previous=json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/tcl-app-widgets-image58-proposal02.json').read_text())
 if set(exports.get('files',{}))!=set(previous['exported_files']):raise ValueError('Native14 export membership differs from accepted30')
 changed={}
 for name,pin in sorted(exports['files'].items()):
  original=rows['/system/'+name]
  if original['kind']!=32768 or not re.fullmatch('[0-9a-f]{64}',pin):raise ValueError('Invalid export payload')
  if original['sha256']!=pin:
   updated=copy.deepcopy(original);updated['sha256']=pin
   changed[name]=dict(before=original,after=updated)
 original=rows['/system/build.prop'];updated=copy.deepcopy(original);updated['sha256']=hashlib.sha256(newprops).hexdigest()
 changed['build.prop']=dict(before=original,after=updated)
 protected={name[len('/system/'):]:row['sha256'] for name,row in sorted(rows.items()) if name.startswith('/system/') and row['kind']==32768 and name[len('/system/'):] not in changed}
 r=dict(image=59,baseline_image=58,base_raw_sha256=c.BASE,base_manifest_sha256=c.BASE_MANIFEST,base_outputs_sha256=c.BASE_OUTPUTS,
  baseline_inventory_sha256=c.sha(baseline/'raw-inventory.json'),baseline_xattrs_sha256=c.sha(baseline/'xattrs.json'),changed=changed,
  exported_files=exports['files'],protected58=protected,native14_framework_sha256=c.FRAMEWORK,
  compiled_stage_sha256=c.sha(native/'staging.json'),compiled_outputs_sha256=c.sha(native/'outputs.json'),
  compiled_cache_sha256=c.sha(cache_path),compiled_review_sha256=c.sha(review_path),reviewed_body_diff_sha256=review.get('body_diff_sha256'),
  messaging_apk_sha256=rows['/system/'+c.MMS]['sha256'],
  pack=dict(partition_bytes=c.PARTITION,optional_fec=False,signed_hashtree_required=True,
   baseline_file_contexts_sha256=c.sha(config/'file_contexts.txt'),baseline_pack_config_sha256=c.sha(config/'system_image_info.compact.txt')),
  stage=c.NAME,backing=c.BACKING,preserved_runtime_art_entries=24,preserved_alarm_files=8,
  content_inset_candidate_included=False,scrollbar_candidate_included=False,ims_candidate_included=False,
  contacts_update_folded_into_system=False,staged=False,built=False,installed=False,full_parity=False)
 c.validate_native_proofs(meta,exports,cache,review,r)
 # Only the scoped image revision may change within build.prop; config paths only.
 c.config59((config/'system_image_info.compact.txt').read_bytes())
 c.dump(output,r);c.proposal(output,c.sha(output))
 return dict(proposal=str(output),proposal_sha256=c.sha(output),changed_paths=len(changed),protected_files=len(protected),launched=False)

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 inv=sub.add_parser('inventory');inv.add_argument('--raw',type=Path,required=True);inv.add_argument('--output',type=Path,required=True);inv.add_argument('--deps',type=Path)
 make=sub.add_parser('proposal')
 for n in ('baseline','native','cache','review','config','output'):make.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 result=inventory(a.raw,a.output,a.deps) if a.mode=='inventory' else create(a.baseline,a.native,a.cache,a.review,a.config,a.output)
 print(json.dumps(result))

if __name__=='__main__':main()

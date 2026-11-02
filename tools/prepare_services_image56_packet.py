"""Freeze deterministic offline56 stage/pack/verifier/payload packet; never launch."""
import argparse,gzip,hashlib,io,json,tarfile
from pathlib import Path
import image56_contract as c
import stage_services_image56 as stage

def files(proposal_dir,tools,baseline_config,file_contexts):
 r=c.proposal(proposal_dir/'proposal.json');result={}
 for n in c.TOOLS:result['tools/'+n]=(tools/n).read_bytes()
 for n in ('proposal.json','baseline-raw-inventory.json','baseline-xattrs.json'):
  result[n]=(proposal_dir/n).read_bytes()
 for n in c.CHANGES:result['payload/'+n]=(proposal_dir/'payload'/n).read_bytes()
 if c.sha(baseline_config)!=r['pack']['baseline_pack_config_sha256'] or c.sha(file_contexts)!=r['pack']['baseline_file_contexts_sha256']:raise ValueError('Exact55 pack config/labels required')
 result['config/file_contexts.txt']=file_contexts.read_bytes();result['config/system_image_info.compact55.txt']=baseline_config.read_bytes();result['config/system_image_info.compact56.txt']=c.config56(baseline_config.read_bytes().decode()).encode()
 manifest=dict(image=56,baseline_image=55,proposal_sha256=c.PROPOSAL,base_raw_sha256=c.BASE,base_manifest_sha256=c.BASE_MANIFEST,base_outputs_sha256=c.BASE_OUTPUTS,stage=c.NAME,new_libart_sha256=c.NEW,changed=sorted(c.CHANGES),optional_fec=False,signed_hashtree_required=True,files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(result.items())},host_staged=False,built=False,installed=False)
 result['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode();return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--proposal-dir',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--baseline-config',type=Path,required=True);p.add_argument('--file-contexts',type=Path,required=True);a=p.parse_args();out=a.output_dir.resolve()
 if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep local packet in workspace')
 contents=files(a.proposal_dir,Path(__file__).resolve().parent,a.baseline_config,a.file_contexts);out.mkdir(parents=True,exist_ok=False)
 for name,data in contents.items():
  path=out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 pin=c.sha(out/'packet.json');stage.packet_check(out,pin)
 archive=Path(str(out)+'.tar.gz')
 with archive.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,filename='',mode='wb',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for n,b in sorted(contents.items()):
     info=tarfile.TarInfo(n);info.size=len(b);info.mode=0o644;tar.addfile(info,io.BytesIO(b))
 print(json.dumps(dict(packet=str(out),packet_sha256=pin,archive=str(archive),archive_sha256=c.sha(archive),file_count=len(contents),host_staged=False,built=False)))
if __name__=='__main__':main()

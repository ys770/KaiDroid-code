import hashlib,json,os,re,shutil,subprocess
from pathlib import Path
r=Path('/opt/kaidroid/kaidroid-build-20261023');s=r/'engineering-frame-backlight-stage-60';src=r/'aosp';bin=r/'out-eng-02/host/linux-x86/bin';py=r/'display-resume-init01/python/cpython-3.11.16-linux-x86_64-gnu/bin'
assert (s/'staging.json').exists();assert not (s/'pack.log').exists();assert shutil.disk_usage(s).free>5*1024**3
for n in ['ninja','soong_build','e2fsdroid']:assert subprocess.run(['pgrep','-x',n],capture_output=True).returncode==1
original=json.loads((s/'candidate-tree.json').read_text())
env=dict(os.environ,PATH=str(py)+':'+str(bin)+':'+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(s/'tmp'),LC_ALL='C')
log=(s/'pack.log').open('x');commands=[]
def run(a,output=None):
 commands.append(a);log.write('COMMAND '+json.dumps(a)+'\n');log.flush()
 if output:
  with output.open('x') as out:subprocess.run(a,cwd=src,env=env,stdout=out,stderr=log,check=True)
 else:subprocess.run(a,cwd=src,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
try:
 key='external/avb/test/data/testkey_rsa2048.pem'
 run([str(bin/'avbtool'),'add_hashtree_footer','--partition_size','834666496','--algorithm','SHA256_RSA2048','--key',key,'--do_not_generate_fec','--calc_max_image_size'],s/'avb-max.txt')
 assert int((s/'avb-max.txt').read_text())==828018688
 run([str(bin/'sefcontext_compile'),'-o',str(s/'file_contexts.bin'),str(s/'records/file_contexts.txt')])
 run([str(py/'python3.11'),'build/make/tools/releasetools/build_image.py',str(s/'compact-system'),str(s/'records/system_image_info.compact.txt'),str(s/'compact-image/system.img'),str(s/'compact-system')])
 raw=s/'compact-image/system.raw.img'
 run([str(bin/'simg2img'),str(s/'compact-image/system.img'),str(raw)])
 assert raw.stat().st_size==834666496
 run([str(bin/'avbtool'),'verify_image','--image',str(raw),'--key',key],s/'avb-verification.txt')
 run([str(bin/'avbtool'),'info_image','--image',str(raw)],s/'avb-info.txt')
 info=(s/'avb-info.txt').read_text()
 for pat in [r'FEC num roots:\s+0\s*$',r'FEC size:\s+0 bytes\s*$',r'Algorithm:\s+SHA256_RSA2048\s*$',r'Hash Algorithm:\s+sha1\s*$']:assert re.search(pat,info,re.M),pat
 for rel,row in original.items():
  path=s/'compact-system'/rel
  if row[0]=='file':assert sha(path)==row[2],rel
 report={'image':60,'raw_sha256':sha(raw),'bytes':raw.stat().st_size,'avb_verified':True,'fec':False,'source_files_preserved':True,'staging_sha256':sha(s/'staging.json'),'commands':commands,'raw_closure_verified':False,'installed':False}
 (s/'outputs.json').write_text(json.dumps(report,indent=2));(s/'pack.exit').write_text('0\n');print(json.dumps(report))
except BaseException:
 (s/'pack.exit').write_text('1\n');raise
finally:log.close()

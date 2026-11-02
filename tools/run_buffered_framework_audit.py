"""Run frozen framework checks with bounded local DEX scratch and buffered archival.

Only inventory I/O changes; the frozen literal-aware parser and all acceptance
checks remain in use. Existing evidence is never overwritten.
"""
import argparse
import gzip
import hashlib
import importlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

def buffered_inventory(jar, output, dexdump, scratch, methods):
 output.mkdir();result={}
 with zipfile.ZipFile(jar) as archive:
  names=[n for n in archive.namelist() if n.startswith('classes') and n.endswith('.dex')]
  assert names and len(names)==len(set(names)) and all('/' not in n for n in names)
  for name in names:
   if shutil.disk_usage(scratch).free<64*1024**2:raise ValueError('Require64MiB local scratch headroom')
   # TemporaryDirectory owns only this newly created local directory.
   with tempfile.TemporaryDirectory(prefix='dex-audit-',dir=scratch) as folder:
    local=Path(folder);dex=local/name;dex.write_bytes(archive.read(name));dump=local/(name+'.txt.gz')
    with (local/(name+'.stderr')).open('wb') as error,gzip.open(dump,'wb') as target:
     proc=subprocess.Popen([str(dexdump),'-d',str(dex)],stdout=subprocess.PIPE,stderr=error)
     try:
      with proc.stdout:shutil.copyfileobj(proc.stdout,target,1024**2)
      if proc.wait()!=0:raise ValueError('dexdump failed: '+name)
     finally:
      if proc.poll() is None:proc.terminate();proc.wait(timeout=10)
    rows=methods(dump,dex)
    assert not result.keys() & rows.keys();result.update(rows)
    for item in local.iterdir():
     destination=output/item.name
     with item.open('rb') as source,destination.open('xb',buffering=8*1024**2) as target:
      shutil.copyfileobj(source,target,8*1024**2)
     def sha(path):
      with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
     assert sha(item)==sha(destination),'Archived diagnostic differs'
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--frozen-audit',type=Path,required=True);p.add_argument('--scratch',type=Path,required=True)
 a,remaining=p.parse_known_args();scratch=a.scratch.resolve(strict=True)
 sys.path.insert(0,str(a.frozen_audit.resolve(strict=True)))
 guard=importlib.import_module('audit_tcl_ime_guard05')
 original=importlib.import_module('audit_resolver_title_dex')
 guard.inventory=lambda jar,out,dex:buffered_inventory(jar,out,dex,scratch,original.methods)
 audit=importlib.import_module('audit_tcl_ime_handover')
 sys.argv=[str(a.frozen_audit/'audit_tcl_ime_handover.py')]+remaining
 audit.main()

if __name__=='__main__':main()

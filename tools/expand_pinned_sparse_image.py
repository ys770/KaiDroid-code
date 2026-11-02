"""Expand a pinned Android sparse image and verify its complete raw hash."""
import argparse,hashlib,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--size',type=int,required=True);a=p.parse_args()
with a.source.open('rb') as src,a.output.open('xb') as dst:
 header=src.read(28);magic,major,minor,fh,ch,bs,blocks,chunks,checksum=struct.unpack('<I4H4I',header)
 assert magic==0xed26ff3a and major==1 and fh>=28 and ch>=12 and bs%4==0
 assert bs*blocks==a.size;src.read(fh-28);written=0
 for _ in range(chunks):
  typ,res,count,total=struct.unpack('<2H2I',src.read(12));assert total>=ch;src.read(ch-12);size=count*bs;payload=total-ch
  if typ==0xcac1:
   assert payload==size
   remaining=size
   while remaining:
    data=src.read(min(1048576,remaining));assert data;dst.write(data);remaining-=len(data)
  elif typ in (0xcac2,0xcac3):
   assert payload==(4 if typ==0xcac2 else 0)
   word=src.read(4) if typ==0xcac2 else b'\0'*4;assert len(word)==4
   chunk=word*(1048576//4);remaining=size
   while remaining:
    n=min(remaining,len(chunk));dst.write(chunk[:n]);remaining-=n
  elif typ==0xcac4:
   assert payload==4 and count==0;assert len(src.read(4))==4
  else:raise ValueError(hex(typ))
  written+=size
 assert written==a.size and src.read(1)==b''
with a.output.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
assert actual==a.sha256,(actual,a.sha256)
print(actual)

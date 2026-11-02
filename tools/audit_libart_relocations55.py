"""Resolve actual image55 linked PIC literals/relocations; no automatic semantic approval."""
import argparse,bisect,hashlib,json,re,struct
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
class Image:
 def __init__(self,path,new=False):
  self.raw=path.read_bytes();self.elf=ELFFile(BytesIO(self.raw));self.new=new
  self.sections=[s for s in self.elf.iter_sections() if s['sh_flags']&2];self.data={s.name:s.data() for s in self.sections if s['sh_type']!='SHT_NOBITS'}
  self.funcs=[];self.bias={}
  for x in self.elf.get_section_by_name('.symtab').iter_symbols():
   if x.name and x['st_info']['type']=='STT_FUNC' and x['st_size']:
    self.funcs.append((int(x['st_value'])&~1,int(x['st_size']),x.name));self.bias[x.name]=4 if int(x['st_value'])&1 else 8
  self.funcs.sort();self.starts=[x[0] for x in self.funcs]
 def section(self,va):return next((s for s in self.sections if s['sh_addr']<=va<s['sh_addr']+s['sh_size']),None)
 def u32(self,va):
  s=self.section(va)
  if s is None or s.name not in self.data:raise ValueError('Missing literal '+hex(va))
  return struct.unpack_from('<I',self.data[s.name],va-s['sh_addr'])[0]
 def token(self,va):
  va&=0xffffffff;s=self.section(va&~1)
  if s is None:return ('constant',va)
  off=va-s['sh_addr']
  if s.name=='.rodata' and self.new:
   if 48290<=off<48330:return ('new_path',off-48290)
   if off>=48330:off-=40
  if s.name=='.text':
   address=va&~1;i=bisect.bisect_right(self.starts,address)-1
   if i>=0:
    start,size,name=self.funcs[i]
    if start<=address<start+size:
     aliases=[n for st,sz,n in self.funcs[max(0,i-4):i+1] if st==start and sz==size]
     return ('function',min(aliases),address-start,va&1)
  return (s.name,off)
 def pic(self,disassembly):
  rows={};registers={};function=None
  for l in disassembly.read_text().splitlines():
   h=re.match(r'^[0-9a-f]+ <(.*)>:$',l)
   if h:function=h[1];registers={};continue
   m=re.match(r'^\s*([0-9a-f]+):\s*(.*)',l)
   if not m:continue
   va=int(m[1],16);ins=m[2]
   load=re.match(r'ldr(?:\.w)?\s+(\w+), \[pc,.*?@\s*\(?([0-9a-f]+)',ins)
   if load:
    reg,ptr=load[1],int(load[2],16);registers[reg]=(ptr,va);continue
   add=re.match(r'add(?:\.w)?\s+(\w+), pc(?:\s|$)',ins)
   if add and add[1] in registers:
    ptr,origin=registers.pop(add[1]);value=self.u32(ptr);target=(value+va+self.bias.get(function,4))&0xffffffff
    rows[(function,origin-self.address(function))]=dict(literal=ptr,add=va,target=target,token=self.token(target));continue
   # Conservative short straight-line tracking; never pass a call/branch.
   if re.match(r'(?:b(?:l|lx|x|\.w|\.n)?|cbz|cbnz)\s',ins):registers={};continue
   dest=re.match(r'(?:ldr\w*|mov\w*|add\w*|sub\w*|pop)\s+(\w+)',ins)
   if dest:registers.pop(dest[1],None)
  return rows
 def address(self,name):
  if not hasattr(self,'byname'):self.byname={n:st for st,sz,n in self.funcs}
  return self.byname.get(name,0)
 def relocations(self):
  rows=[]
  for s in self.elf.iter_sections():
   if not isinstance(s,RelocationSection):continue
   syms=self.elf.get_section(s['sh_link'])
   for r in s.iter_relocations():
    at=int(r['r_offset']);symbol=syms.get_symbol(r['r_info_sym']).name if r['r_info_sym'] else None
    rows.append((s.name,self.token(at),int(r['r_info_type']),symbol,self.token(self.u32(at))))
  relr=self.elf.get_section_by_name('.relr.dyn');where=0
  if relr:
   for entry in struct.unpack('<'+'I'*(relr['sh_size']//4),relr.data()):
    if not entry&1:locations=[entry];where=entry+4
    else:locations=[where+4*i for i in range(31) if entry&(1<<(i+1))];where+=124
    for at in locations:rows.append(('.relr.dyn',self.token(at),23,None,self.token(self.u32(at))))
  return rows
 def exidx(self):
  s=self.elf.get_section_by_name('.ARM.exidx');rows=[]
  signed=lambda n:(n&0x3fffffff)-(n&0x40000000)
  for off in range(0,s['sh_size'],8):
   a,b=struct.unpack_from('<II',s.data(),off);pc=s['sh_addr']+off
   rows.append((self.token(pc+signed(a)),b if b&0x80000000 or b==1 else self.token(pc+4+signed(b))))
  return rows

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','disassembly-dir','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();b=Image(a.baseline);c=Image(a.candidate,True)
 if hashlib.sha256(b.raw).hexdigest()!='d356f4ba46bec4ca6110b0b1591ec6b0a79beefe2b6bcb7a4d1ab76e9fa48fa5' or hashlib.sha256(c.raw).hexdigest()!='2f1f266896df25fd458fe362fd5120e2211cf9305926b7737deb06bc558d3f8b':raise ValueError('Exact reviewed image55 compile03 pair required')
 path=b'/system/framework/oat/arm/services.odex\0';old=b.data['.rodata'];new=c.data['.rodata']
 if new.replace(path,b'',1)!=old or new.index(path)!=48290:raise ValueError('Unexpected rodata layout')
 pb=b.pic(a.disassembly_dir/'baseline-objdump.txt');pc=c.pic(a.disassembly_dir/'candidate-objdump.txt');common=pb.keys()&pc.keys();mismatches={str(k):dict(before=pb[k],after=pc[k]) for k in common if pb[k]['token']!=pc[k]['token']}
 rb=b.relocations();rc=c.relocations();eb=b.exidx();ec=c.exidx()
 result=dict(rodata_only_new_path=True,pic_baseline=len(pb),pic_candidate=len(pc),pic_common=len(common),pic_mismatch_count=len(mismatches),pic_mismatches=mismatches,pic_before_only=[str(k) for k in pb.keys()-pc.keys()],pic_after_only=[str(k) for k in pc.keys()-pb.keys()],dynamic_relocation_count_before=len(rb),dynamic_relocation_count_after=len(rc),dynamic_relocations_equal=rb==rc,dynamic_relocation_differences=[dict(index=i,before=x,after=y) for i,(x,y) in enumerate(zip(rb,rc)) if x!=y],arm_exidx_count=len(eb),arm_exidx_equal=eb==ec,arm_exidx_differences=[dict(index=i,before=x,after=y) for i,(x,y) in enumerate(zip(eb,ec)) if x!=y],semantic_equivalence_proven=False,ready_for_image=False,limits=['PIC tracking covers conservative straight-line literal-load/add-PC pairs; unmatched pools and changed caller need separate review.','Location normalization uses exact unchanged section offsets and same named function+offset; .rodata mapping is byte-proven one new40byte path insertion.','Relocation and exidx comparisons do not prove complete machine-code/class-layout/runtime correctness.'])
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['pic_common','pic_mismatch_count','dynamic_relocations_equal','arm_exidx_equal']}))
if __name__=='__main__':main()

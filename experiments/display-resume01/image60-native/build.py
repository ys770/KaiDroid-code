import hashlib,json,os,shlex,shutil,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent;r=p.parent;src=r/'aosp'
def sha(f):return hashlib.sha256(Path(f).read_bytes()).hexdigest()
def run(a,name):
 with (p/(name+'.log')).open('x') as f:subprocess.run(a,cwd=src,stdout=f,stderr=subprocess.STDOUT,check=True,env=dict(os.environ,LC_ALL='C',PWD='/proc/self/cwd'))
assert sha(p/'selinux.cpp')=='228d157672b0c638dbef7d45055527286aad2b96b20a89c3e4f826fc59df0be9'
assert sha(p/'kaidroid_precompiled_policy.h')=='356f67a67ec8fc2b9f5b209a73e4e1ce93abc2f5120b517027e5bd8f3ff6bb04'
a=shlex.split((p/'compile-command.txt').read_text());assert a.pop(0)=='PWD=/proc/self/cwd';a=[x.replace('/build/',str(r)+'/') for x in a]
a[a.index('-o')+1]=str(p/'selinux.o');a[a.index('-MF')+1]=str(p/'selinux.o.d');assert a[-1]=='system/core/init/selinux.cpp';a[-1]=str(p/'selinux.cpp')
run(a,'compile');print('init selinux translation unit compiled',flush=True)
a=shlex.split((p/'link-command.txt').read_text());a=[x.replace('/build/',str(r)+'/') for x in a]
idx=next(i for i,x in enumerate(a) if x.endswith('/libinit.a'));old=Path(a[idx]);new=p/'libinit-candidate.a'
ar=src/'prebuilts/clang/host/linux-x86/clang-r383902b/bin/llvm-ar'
names=subprocess.check_output([str(ar),'t',str(old)],text=True).splitlines();assert names.count('selinux.o')==1
oldsha=sha(old);shutil.copyfile(old,new)
run([str(ar),'rcsD',str(new),str(p/'selinux.o')],'archive')
assert subprocess.check_output([str(ar),'t',str(new)],text=True).splitlines()==names
changed=[]
for n in names:
 b=subprocess.check_output([str(ar),'p',str(old),n]);c=subprocess.check_output([str(ar),'p',str(new),n])
 if b!=c:changed.append(n)
assert changed==['selinux.o'];assert sha(old)==oldsha
base=Path(a[a.index('-o')+1]);basesha=sha(base)
j=next(i for i,x in enumerate(a) if x.startswith('@'));rsp=Path(a[j][1:]);rsp2=p/'init.rsp';rsp2.write_text(rsp.read_text().replace('/build/',str(r)+'/'));a[j]='@'+str(rsp2)
# Control link uses every original archive; only its output path is redirected.
a[a.index('-o')+1]=str(p/'init-control-unstripped');run(a,'control-link');assert sha(p/'init-control-unstripped')==basesha
inputs={str(old):oldsha,str(base):basesha,str(rsp):sha(rsp)}
for x in a+shlex.split(rsp2.read_text()):
 if x.startswith('-') or x.startswith('@'):continue
 f=Path(x);f=f if f.is_absolute() else src/f
 if f.is_file():inputs[str(f)]=sha(f)
a[idx]=str(new);a[a.index('-o')+1]=str(p/'init-candidate-unstripped');run(a,'candidate-link')
assert all(sha(Path(f))==h for f,h in inputs.items())
report={'compiled':True,'archive_members':len(names),'changed_members':changed,'control_byte_identical':True,'baseline_unstripped_sha256':basesha,'candidate_unstripped_sha256':sha(p/'init-candidate-unstripped'),'link_inputs_preserved':True,'link_input_count':len(inputs),'guard_sha256':sha(p/'kaidroid_precompiled_policy.h'),'installed':False}
(p/'inputs.json').write_text(json.dumps(inputs,indent=2));(p/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))

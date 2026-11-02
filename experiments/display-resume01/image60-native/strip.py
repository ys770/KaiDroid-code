import hashlib,json,os,shlex,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent;r=p.parent;a=shlex.split((p/'strip-command.txt').read_text());env=dict(os.environ, LC_ALL='C')
while '=' in a[0]:
 k,v=a.pop(0).split('=',1);env[k]=v
a[a.index('-i')+1]=str(p/'init-candidate-unstripped')
a[a.index('-o')+1]=str(p/'init-candidate')
a[a.index('-d')+1]=str(p/'init-candidate.d')
assert not (p/'init-candidate').exists()
with (p/'strip02.log').open('x') as log:subprocess.run(a,cwd=r/'aosp',env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
f=p/'init-candidate';report={'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size,'argv':a}
(p/'strip02-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))

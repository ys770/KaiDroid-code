import hashlib,json,subprocess
from pathlib import Path
root=Path('/opt/kaidroid/kaidroid-build-20261023'); stage=root/'ims-callback-compile01'; out=stage/'binder-probe01';out.mkdir()
jdk=root/'aosp/prebuilts/jdk/jdk11/linux-x86/bin'; previous=json.loads((stage/'output/result.json').read_text()); jars=[Path(x) for x in previous['inputs'] if x.endswith('.jar')]
for path in jars: assert hashlib.sha256(path.read_bytes()).hexdigest()==previous['inputs'][str(path)]
classes=out/'classes';classes.mkdir()
commands=[]
def run(cmd):
 commands.append(list(map(str,cmd))); r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=90); (out/('command%d.log'%len(commands))).write_bytes(r.stdout+r.stderr);r.check_returncode()
run([jdk/'javac','-J-Xmx512m','-J-XX:ActiveProcessorCount=2','-source','8','-target','8','-proc:none','-bootclasspath',jars[-1],'-classpath',':'.join(map(str,jars[:-1])),'-d',classes,stage/'ImsCallbackBinderProbe.java'])
d8=root/'aosp/prebuilts/r8/r8.jar'
for role in ['original','candidate','probe']:
 files=list((classes if role=='probe' else stage/'output'/role/'classes').rglob('*.class'))
 run([jdk/'java','-Xmx512m','-XX:ActiveProcessorCount=2','-cp',d8,'com.android.tools.r8.D8','--min-api','30','--output',out/(role+'.jar'),*files])
report={'commands':commands,'d8_sha256':hashlib.sha256(d8.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((stage/'ImsCallbackBinderProbe.java').read_bytes()).hexdigest(),'outputs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.jar')},'runtime_tested':False}
(out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['outputs']))

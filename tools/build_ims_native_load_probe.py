from pathlib import Path
import json,hashlib,subprocess
root=Path('/opt/kaidroid/kaidroid-build-20261023');stage=root/'ims-native-load01';out=stage/'output';out.mkdir();classes=out/'classes';classes.mkdir()
r=json.loads((root/'ims-callback-compile01/output/result.json').read_text());jars=[Path(x) for x in r['inputs'] if x.endswith('.jar')]
for p in jars: assert hashlib.sha256(p.read_bytes()).hexdigest()==r['inputs'][str(p)]
jdk=root/'aosp/prebuilts/jdk/jdk11/linux-x86/bin';d8=root/'aosp/prebuilts/r8/r8.jar'
cmds=[[str(jdk/'javac'),'-J-Xmx512m','-J-XX:ActiveProcessorCount=2','-source','8','-target','8','-proc:none','-bootclasspath',str(jars[-1]),'-classpath',':'.join(map(str,jars[:-1])),'-d',str(classes),str(stage/'ImsNativeLoadProbe.java')]]
p=subprocess.run(cmds[0],capture_output=True,timeout=60);(out/'javac.log').write_bytes(p.stdout+p.stderr);p.check_returncode()
cmds.append(list(map(str,[jdk/'java','-Xmx512m','-XX:ActiveProcessorCount=2','-cp',d8,'com.android.tools.r8.D8','--min-api','30','--output',out/'probe.jar',*sorted(classes.glob('*.class'))])))
p=subprocess.run(cmds[1],capture_output=True,timeout=60);(out/'d8.log').write_bytes(p.stdout+p.stderr);p.check_returncode()
report={'commands':cmds,'headers':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in jars},'source_sha256':hashlib.sha256((stage/'ImsNativeLoadProbe.java').read_bytes()).hexdigest(),'probe_sha256':hashlib.sha256((out/'probe.jar').read_bytes()).hexdigest(),'d8_sha256':hashlib.sha256(d8.read_bytes()).hexdigest()};(out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(report['probe_sha256'])

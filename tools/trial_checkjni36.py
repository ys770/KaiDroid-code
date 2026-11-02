"""Run isolated resource JNI probes; restore the original property, no framework restart."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb',required=True)
p.add_argument('--jar',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED']
remote='/data/local/tmp/resource-jni-probe36-01.jar'
def shell(c):
    r=subprocess.run(base+['exec-out',c],capture_output=True,check=True,timeout=45)
    return r.stdout.decode().strip()
def guard():
    assert shell('getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').splitlines()==['36','00000000-0000-0000-0000-000000000014','0']
guard()
digest=hashlib.sha256(a.jar.read_bytes()).hexdigest()
assert shell('sha256sum '+remote).split()[0]==digest
original=shell('getprop dalvik.vm.checkjni')
assert original==''
report=dict(jar_sha256=digest,samples=[],restored=False,framework_restarted=False)
try:
    for label,value in [('baseline',''),('candidate','false'),('restored','')]:
        guard()
        shell('setprop dalvik.vm.checkjni "'+value+'"')
        assert shell('getprop dalvik.vm.checkjni')==value
        for i in range(3):
            guard()
            output=shell('CLASSPATH='+remote+' app_process /system/bin ResourceJniProbe36')
            result=json.loads(output)
            assert result['checkjni_override']==value and result['iterations']==20000
            result.update(phase=label,index=i)
            report['samples'].append(result)
            print(json.dumps(result),flush=True)
finally:
    try:
        guard()
        shell('setprop dalvik.vm.checkjni "'+original+'"')
        report['restored']=shell('getprop dalvik.vm.checkjni')==original
        assert report['restored']
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')

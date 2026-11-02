"""Read only the exact vendor service pointer/vtable/callback slots; never attach or write."""
import argparse
import hashlib
import io
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
base=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED']
digest='47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd'
blob=Path('work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so').read_bytes()
if hashlib.sha256(blob).hexdigest()!=digest:raise ValueError('Unexpected library')
elf=ELFFile(io.BytesIO(blob))
# The traced getOemHookService loads this PC-relative singleton reference.
global_offset=(struct.unpack_from('<I',blob,0xf2b050)[0]+0xf2b036)&0xffffffff
if global_offset!=0x104e440:raise ValueError('Unexpected singleton address')
vtable=next(s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name=='_ZTVN6vendor3qti8hardware5radio9qcrilhook4V1_014implementation11OemHookImplE')+12

def command(name,cmd,binary=False):
    r=subprocess.run(base+(['exec-out'] if binary else ['shell'])+[cmd],capture_output=True,timeout=30)
    (a.output/(name+'.raw')).write_bytes(r.stdout)
    (a.output/(name+'.stderr')).write_bytes(r.stderr)
    r.check_returncode()
    return r.stdout

def guard(name):
    value=command(name,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').decode().split()
    if value!=['33','00000000-0000-0000-0000-000000000004','0']:raise ValueError('Identity changed')

guard('before')
if command('hash','sha256sum /vendor/lib/libril-qc-hal-qmi.so').decode().split()[0]!=digest:
    raise ValueError('Installed library differs')
pid=command('pid','pidof qcrild').decode().strip()
if not pid.isdecimal():raise ValueError('Expected one radio process')
maps=command('maps','cat /proc/'+pid+'/maps').decode()
matches=[s for s in maps.splitlines() if s.endswith('/vendor/lib/libril-qc-hal-qmi.so') and s.split()[2]=='00000000']
if len(matches)!=1:raise ValueError('Ambiguous load bias')
bias=int(matches[0].split('-')[0],16)
def read(name,address,count):
    ranges=[(int(s.split('-')[0],16),int(s.split('-')[1].split()[0],16)) for s in maps.splitlines() if s.split()[1].startswith('r')]
    if not any(lo<=address and address+count<=hi for lo,hi in ranges):raise ValueError('Address not in readable mapping')
    raw=command(name,'dd if=/proc/'+pid+'/mem bs=1 skip='+str(address)+' count='+str(count)+' 2>/dev/null',True)
    if len(raw)!=count:raise ValueError('Incomplete memory read')
    return raw

observations=[]
for index in range(2):
    ptr=struct.unpack('<I',read('global'+str(index),bias+global_offset,4))[0]
    if not ptr:raise ValueError('No service object')
    words=struct.unpack('<4I',read('object'+str(index),ptr,16))
    if words[0]!=bias+vtable:raise ValueError('Object vtable mismatch')
    observations.append({'response_present':bool(words[2]),'indication_present':bool(words[3])})
if command('pid-after','pidof qcrild').decode().strip()!=pid:raise ValueError('Radio restarted')
guard('after')
report={'library_sha256':digest,'image':33,'observations':observations,
        'object_vtable_verified':True,'device_written':False,
        'limits':['Two unlocked snapshots, not a reservation or race-free ownership guarantee',
                  'Must recheck and coordinate ownership immediately before any registration',
                  'No modem request, ptrace attachment, callback registration or service restart']}
(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

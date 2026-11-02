"""Audit pinned donor DEX power/end dispatch without copying proprietary source."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

JAR_SHA='709b1cef52a18a89102f361268ac0ed514d87c9241359836817da9d3a6aff412'
DEX_SHA='f81f8eb53d9612bc5524a49a13fbd4a4ee89625d48d7ec5adb82dddcd21e88a2'
BASE=0x5fe5a4  # insns start in pinned interceptKeyBeforeQueueing code item


def audit(jar):
    if hashlib.sha256(jar.read_bytes()).hexdigest()!=JAR_SHA:raise ValueError('Wrong services.jar')
    with zipfile.ZipFile(jar) as z:b=z.read('classes.dex')
    if hashlib.sha256(b).hexdigest()!=DEX_SHA:raise ValueError('Wrong DEX')
    def u32(off):return struct.unpack_from('<I',b,off)[0]
    def words(off,count):return struct.unpack_from('<'+'H'*count,b,BASE+off*2)
    def string(index):
        off=u32(u32(60)+index*4)
        while b[off]&128:off+=1
        off+=1
        return b[off:b.index(0,off)].decode('utf-8')
    def method(index):
        owner,proto,name=struct.unpack_from('<HHI',b,u32(92)+index*8)
        return string(u32(u32(68)+owner*4)),string(name)
    if words(0x13d,4)!=(0x6a12,0x2b12,0xa632,0x170):raise ValueError('ENDCALL branch changed')
    end_target=0x13f+words(0x13f,2)[1]
    if words(0x173,1)!=(0x062b,):raise ValueError('POWER switch changed')
    switch_payload=0x173+struct.unpack_from('<i',b,BASE+0x173*2+2)[0]
    ident,size=words(switch_payload,2)
    first=struct.unpack_from('<i',b,BASE+switch_payload*2+4)[0]
    if (ident,size,first)!=(0x100,3,24):raise ValueError('Wrong switch payload')
    power_target=0x173+struct.unpack_from('<i',b,BASE+switch_payload*2+8+(26-first)*4)[0]
    if end_target!=power_target or end_target!=0x2af:raise ValueError('POWER and END do not share branch')
    if words(end_target,3)!=(0x0a12,0x0029,0x02db):raise ValueError('Shared dispatch changed')
    shared=0x2b0+0x2db
    if shared!=0x58b:raise ValueError('Wrong handler')
    if words(0x600,2)!=(0x0c16,2500):raise ValueError('Long press delay changed')
    calls={}
    for offset,owner,name in [(0x5ef,'Landroid/telecom/TelecomManager;','endCall'),(0x602,'Landroid/os/Handler;','postDelayed'),(0x698,'Lcom/android/server/policy/PhoneWindowManager;','goHome')]:
        opcode,index=words(offset,2)
        if opcode&255 not in (0x6e,0x74) or method(index)!=(owner,name):raise ValueError('Wrong call target')
        calls[hex(offset)]=name
    return dict(jar_sha256=JAR_SHA,dex_sha256=DEX_SHA,method='PhoneWindowManager.interceptKeyBeforeQueueing',
                instruction_base=hex(BASE),power_keycode=26,end_keycode=6,shared_dispatch=hex(shared),
                longpress_ms=2500,verified_calls=calls,
                source_interpretation='Shared end-call down/up handler; short release uses end_button_behavior home bit, long hold schedules global-actions runnable. Gflip6_GC has extra power-up path, not active for Gflip6_USCC.',
                live_resource_short_power=1,live_end_behavior='home',live_device='Gflip6_USCC',
                physical_user_report='Short power/end does not sleep; flip close turns screen off',runtime_adaptation_verified=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--jar',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=audit(a.jar)
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r))

"""Serial-bound original-system write/readback test in stock N139DL recovery.

Default is preflight only. --write-original writes only the hash-pinned original
system image. Never reboots, formats, unlocks, retries or writes another partition.
"""
import argparse
import hashlib
import json
import subprocess
import uuid
from pathlib import Path

SERIAL = 'DEVICE_SERIAL_REQUIRED'
FINGERPRINT = 'Nokia/N139DL/N139DL:10/QKQ1.200623.002/00.2211.12.01:eng/release-keys'
SYSTEM = '/dev/block/bootdevice/by-name/system'
ORIGINAL = 'f600f226fbbfa8ed357153e85d2149726c983cf59a1af576436496825e1b7db8'
SIZE = 834666496
MIB = 1048576


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(8*MIB), b''):
            h.update(b)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--write-original', action='store_true')
    args = parser.parse_args()
    if args.image.stat().st_size != SIZE or digest(args.image) != ORIGINAL:
        raise ValueError('Only the verified original system image is allowed')
    args.output.mkdir(parents=True, exist_ok=False)
    base = [args.adb, '-s', SERIAL]
    journal = args.output / 'journal.jsonl'
    def record(data):
        with journal.open('a') as f:
            f.write(json.dumps(data)+'\n')
    def command(text):
        marker = 'KAIDROID_STATUS_'+uuid.uuid4().hex
        wrapped = '( '+text+' ); rc=$?; printf "\\n'+marker+':%s\\n" "$rc"'
        record({'command': text, 'state': 'started'})
        try:
            q = subprocess.run(base+['exec-out', wrapped], capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            record({'command': text, 'state': 'timeout', 'remote_state': 'unknown; do not retry or reboot'})
            raise
        payload, sep, status = q.stdout.rpartition(('\n'+marker+':').encode())
        record({'command': text, 'transport_exit': q.returncode,
                'stdout': q.stdout.decode(errors='replace'), 'stderr': q.stderr.decode(errors='replace')})
        if q.returncode or not sep or status.strip() != b'0':
            raise RuntimeError('Remote command failed; remain in recovery: '+text)
        return payload.decode().strip()
    def identity():
        state = subprocess.run(base+['get-state'], capture_output=True, check=True, timeout=10).stdout.strip()
        if state != b'recovery': raise ValueError('Recovery transport required')
        values = command('getprop ro.build.fingerprint; getprop ro.product.model; id -u; cat /proc/sys/kernel/random/boot_id').splitlines()
        if values[:3] != [FINGERPRINT, 'N139DL', '0'] or len(values)!=4:
            raise ValueError('Identity/root mismatch')
        mounts = command('cat /proc/mounts')
        if 'rootfs / rootfs ' not in mounts or '/dev/block/' in mounts:
            raise ValueError('All block partitions must be unmounted in recovery')
        return values
    before = identity()
    if command('readlink -f '+SYSTEM) != '/dev/block/mmcblk0p16':
        raise ValueError('Unexpected system block path')
    if command('blockdev --getsize64 '+SYSTEM) != str(SIZE):
        raise ValueError('Unexpected partition length')
    if command('sha256sum '+SYSTEM).split()[0] != ORIGINAL:
        raise ValueError('Current system differs from original; this test cannot overwrite it')
    evidence = json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/n139dl-engineering-bootchain.json').read_text())
    chain = {x['partition']:x['sha256'] for x in evidence['partitions_verified_against_before_after_hashes']}
    def check_chain():
        for name, expected in chain.items():
            if command('sha256sum /dev/block/bootdevice/by-name/'+name).split()[0] != expected:
                raise ValueError('Boot-chain mismatch: '+name)
    check_chain()
    result = {'preflight_passed':True, 'write_requested':args.write_original, 'verified_chunks':0}
    def save(): (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    save()
    if not args.write_original:
        print(json.dumps(result)); return
    # Refuse if less than 32MiB is free on recovery tmpfs.
    free = command('df -k /tmp').splitlines()[-1].split()
    if int(free[3])*1024 < 32*MIB: raise ValueError('Insufficient recovery tmpfs space')
    remote = '/tmp/kaidroid-original-'+uuid.uuid4().hex
    command('mkdir '+remote)
    try:
        with args.image.open('rb') as source:
            for index, offset in enumerate(range(0,SIZE,16*MIB)):
                if identity()!=before: raise ValueError('Recovery boot identity changed')
                chunk=source.read(min(16*MIB,SIZE-offset))
                expected=hashlib.sha256(chunk).hexdigest()
                local=args.output/'chunk.bin';local.write_bytes(chunk)
                q=subprocess.run(base+['push',str(local),remote+'/chunk.bin'],capture_output=True,timeout=120)
                record({'push_index':index,'exit_code':q.returncode,'output':q.stdout.decode(errors='replace')})
                q.check_returncode()
                if command('sha256sum '+remote+'/chunk.bin').split()[0]!=expected:
                    raise ValueError('Staged chunk hash mismatch')
                # This is the only write target; image, size, offsets and handset are fixed.
                command('dd if='+remote+'/chunk.bin of='+SYSTEM+' bs=1048576 seek='+str(offset//MIB)+' count='+str(len(chunk)//MIB)+' conv=notrunc && sync')
                actual=command('dd if='+SYSTEM+' bs=1048576 skip='+str(offset//MIB)+' count='+str(len(chunk)//MIB)+' 2>/dev/null | sha256sum').split()[0]
                if actual!=expected: raise ValueError('Partition chunk readback mismatch')
                result['verified_chunks']=index+1;save()
                print('Verified original chunk',index+1,'of 50',flush=True)
        if command('sha256sum '+SYSTEM).split()[0]!=ORIGINAL:
            raise ValueError('Final partition hash mismatch')
        check_chain()
        if identity()!=before: raise ValueError('Final identity changed')
        result['full_readback_verified']=True;save()
    except Exception as e:
        result['error']=str(e);result['action']='Stop; remain in recovery. Do not reboot or automatically retry.';save()
        raise
    print(json.dumps(result))


if __name__=='__main__': main()

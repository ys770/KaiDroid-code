"""Capture post-trial state, then optionally restore pinned engineering data backups.

Recovery only, all partitions unmounted, fixed handset and targets. No format,
reboot, retries, or writes unless --restore. Preserves all captured files.
"""
import argparse
import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from write_engineering_system import FINGERPRINT, ORIGINAL, SERIAL, SYSTEM, digest

MIB = 1048576
PARTS = {'userdata': 54, 'sysdata': 42, 'cache': 53, 'persist': 41}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--backups', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    specs = json.loads((root/'docs/evidence/n139dl-recovery-data-backup.json').read_text())['partitions']
    chain = json.loads((root/'docs/evidence/n139dl-engineering-bootchain.json').read_text())['partitions_verified_against_before_after_hashes']
    for name, spec in specs.items():
        path = args.backups/(name+'.img')
        if path.stat().st_size != spec['bytes'] or digest(path) != spec['sha256']:
            raise ValueError('Backup mismatch: '+name)
    args.output.mkdir(parents=True, exist_ok=False)
    base = [args.adb, '-s', SERIAL]
    def record(event):
        with (args.output/'journal.jsonl').open('a') as f:
            f.write(json.dumps(event)+'\n')
    def command(text, binary=False):
        marker = 'KAIDROID_STATUS_'+uuid.uuid4().hex
        wrapped = '( '+text+' ); rc=$?; printf "\\n'+marker+':%s\\n" "$rc"'
        record({'command': text, 'state': 'started'})
        q = subprocess.run(base+['exec-out', wrapped], capture_output=True, timeout=180)
        payload, sep, status = q.stdout.rpartition(('\n'+marker+':').encode())
        record({'command': text, 'exit': q.returncode, 'status': status.decode(errors='replace'),
                'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()})
        if q.returncode or not sep or status.strip() != b'0':
            raise RuntimeError('Command failed; stop without retry/reboot: '+text)
        return payload if binary else payload.decode().strip()
    def identity():
        q = subprocess.run(base+['get-state'], capture_output=True, check=True, timeout=10)
        if q.stdout.strip() != b'recovery': raise ValueError('Recovery required')
        v = command('getprop ro.build.fingerprint; id -u; cat /proc/sys/kernel/random/boot_id').splitlines()
        if v[:2] != [FINGERPRINT, '0'] or len(v) != 3: raise ValueError('Identity mismatch')
        mounts = command('cat /proc/mounts')
        if 'rootfs / rootfs ' not in mounts or '/dev/block/' in mounts: raise ValueError('Partitions must be unmounted')
        return v
    before_id = identity()
    def check_chain():
        for spec in chain:
            path = '/dev/block/bootdevice/by-name/'+spec['partition']
            if command('sha256sum '+path).split()[0] != spec['sha256']: raise ValueError('Boot-chain mismatch')
        if command('sha256sum '+SYSTEM).split()[0] != ORIGINAL: raise ValueError('Original system required')
    check_chain()
    result = {'restore_requested': args.restore, 'partitions': {}}
    def save(): (args.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    # Capture every post-trial partition before modifying any of them.
    for name, number in PARTS.items():
        path = '/dev/block/bootdevice/by-name/'+name
        spec = specs[name]
        if command('readlink -f '+path) != '/dev/block/mmcblk0p'+str(number): raise ValueError('Path mismatch')
        if command('blockdev --getsize64 '+path) != str(spec['bytes']): raise ValueError('Size mismatch')
        before_hash = command('sha256sum '+path).split()[0]
        capture = args.output/(name+'-before.img')
        with capture.open('xb') as f:
            for offset in range(0, spec['bytes'], 16*MIB):
                if identity() != before_id: raise ValueError('Boot changed')
                count = min(16*MIB, spec['bytes']-offset)//MIB
                data = command('dd if='+path+' bs=1048576 skip='+str(offset//MIB)+' count='+str(count)+' 2>/dev/null', binary=True)
                if len(data) != count*MIB: raise ValueError('Short capture')
                f.write(data)
                print('Captured', name, offset+len(data), 'of', spec['bytes'], flush=True)
        if digest(capture) != before_hash or command('sha256sum '+path).split()[0] != before_hash:
            raise ValueError('Capture hash mismatch')
        result['partitions'][name] = {'captured_sha256': before_hash, 'captured_bytes': spec['bytes']}
        save()
    if args.restore:
        if int(command('df -k /tmp').splitlines()[-1].split()[3])*1024 < 32*MIB: raise ValueError('Insufficient tmpfs')
        remote = '/tmp/kaidroid-data-'+uuid.uuid4().hex
        command('mkdir '+remote)
        for name in PARTS:
            spec = specs[name]
            path = '/dev/block/bootdevice/by-name/'+name
            if result['partitions'][name]['captured_sha256'] == spec['sha256']:
                result['partitions'][name]['unchanged_skipped'] = True
                save()
                continue
            with (args.backups/(name+'.img')).open('rb') as f:
                for offset in range(0, spec['bytes'], 16*MIB):
                    if identity() != before_id: raise ValueError('Boot changed')
                    data = f.read(min(16*MIB, spec['bytes']-offset))
                    local = args.output/'chunk.bin'
                    local.write_bytes(data)
                    subprocess.run(base+['push', str(local), remote+'/chunk.bin'], capture_output=True, check=True, timeout=120)
                    expected = hashlib.sha256(data).hexdigest()
                    if command('sha256sum '+remote+'/chunk.bin').split()[0] != expected: raise ValueError('Stage mismatch')
                    count = len(data)//MIB
                    command('dd if='+remote+'/chunk.bin of='+path+' bs=1048576 seek='+str(offset//MIB)+' count='+str(count)+' conv=notrunc && sync')
                    if command('dd if='+path+' bs=1048576 skip='+str(offset//MIB)+' count='+str(count)+' 2>/dev/null | sha256sum').split()[0] != expected:
                        raise ValueError('Readback mismatch; no reboot')
                    print('Restored', name, offset+len(data), 'of', spec['bytes'], flush=True)
            if command('sha256sum '+path).split()[0] != spec['sha256']: raise ValueError('Full partition mismatch')
            result['partitions'][name]['restored_sha256'] = spec['sha256']
            save()
    check_chain()
    if identity() != before_id: raise ValueError('Final boot changed')
    result['complete'] = True
    save()
    print(json.dumps(result))


if __name__ == '__main__':
    main()

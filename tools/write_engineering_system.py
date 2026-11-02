"""Write one reviewed system image to the identified engineering Nokia in recovery.

Preflight only unless --write. Install requires the verified original or an explicit
reviewed upgrade prestate and local rollback backups. Restore writes the pinned original regardless
of current system bytes, permitting recovery from a partial/failed installation.
Never reboots, formats, unlocks, retries, or writes another partition.
Default verification reads the complete partition once after writing. Optional
per-chunk readback is available for diagnosing unreliable writes.
"""
import argparse
import hashlib
import json
import subprocess
import shutil
import uuid
from pathlib import Path

SERIAL = 'DEVICE_SERIAL_REQUIRED'
FINGERPRINT = 'Nokia/N139DL/N139DL:10/QKQ1.200623.002/00.2211.12.01:eng/release-keys'
SYSTEM = '/dev/block/bootdevice/by-name/system'
ORIGINAL = 'f600f226fbbfa8ed357153e85d2149726c983cf59a1af576436496825e1b7db8'
ANDROID_BUILDS = {
    '02': '7471efa00514c45c5286869c392ea8b1ffb4dfb768f2dc47f2533cd7f014fc4e',
    '03': '371937028593cc0a62e2cc2eec97aa42afc64096843ee281ad03e2ac86cf6b10',
    '04': 'fa237f09ddcba92afa5819eef2f1ba8c359cc2c462a260c6464c7af413abe69e',
    '05': '825e148d7871d1bc952ea77c9c01fe9674d69f2eb3a8e08db670a8521826633e',
    '06': 'd1d9d5f0c9509b055decbf9c1ff02f596aff1f2f4d99132611bad289b421008f',
    '08': '3be9d25014e331df920d006333aca6ed40bbe38e74e4d6839026500a76af6599',
    '09': 'ba0ef4a117ba07634b1408bc8c0cc700e318d9f4a673a299b202e4d4fbb84e10',
    '11': '6c93c530b9c014d8dd6048bbe07e0cb1c1287f337bbb3b0cae4f25fe21fd80e3',
    '12': 'e5b30c8c830ce5392cbd29ed3a76415bdcf6e157d4dfe148f1b4c8c4f1702cf8',
    '13': '0d1010f350871a91435fbc6c55fd761c9c3a4a5ebb3c2607df4972801379a6f7',
    '14': 'a4b12430a87c673f3c9a7be75c352168a5a13fe36e7fc2384fad0fae9ad0fc67',
    '15': '9343bce02e8ab0309a75c2ef33c0224b810c92e2d58328f437ba4852d236f8c3',
    '16': '879743ea986a2800410abeb6c1b8ef62118702d3eded08e34b42e483b2d1dc2e',
    '18': '9682ca237e5c548da533ff3ee1730189b80af2231654abdfe305ebc449a45a98',
    '19': 'eafe2175dceb171d0d13891f1327d3246f911193161730b083721cb444574742',
    '21': 'd45810f4a0fed82b535315196a3f51fed3862a9b042f2396ce65b70e44930419',
    '22': '26e0a27732b9942c04dead22412a7fc859a6ab5926201b74e9e7b5d5d8a0a438',
    '23': '7a6d645488733cebb82e2acf3c876ae57ad2ca48034f94034c26f2ef0d266c60',
    '24': '0555b64aadd312bbc14a5e227513d456f70d6b3e24ef226a3ab72e55f9f04090',
    '25': '0f58cebada7b6d80ea942d8f2d3765d569948abea5045dcf88c7933117bb96b6',
    '26': 'b72ae0054f608e21b156feeaa63dc88c0a929dab036cf6bcf791e6ab732d48e4',
    '27': '5edab4e0f0353382d170fd1ab2de4f45e1cd8e67b0fb770bd289fe36cd1e1ea6',
    '28': 'abb062da07d3bd83b525cf8d6a169ae38e55841503d3d7a052f4d5bc8a60c2eb',
    '29': 'c3d456e9f1890692081788b2afbf5882c6b17ae148a81dd16ef1d3f6695d2ba0',
    '30': '2a590db52fb28747abb086f26e09c2c292d7070da5832cfd46d1ed015e12958c',
    '31': '346846ce150ac90ab9056fc2e5b82989ba9a4627873b9f759920ae4a7c5c8dea',
    '32': '89b28f08c71bf834d096bf7ed829be981eafc4149bd8325aa25da5226365be54',
    '33': '864284a5c7be2ff6ae74e13bc4578a323dd8fc53648a0ce6d4d409c14ba455e4',
    '34': '2f8bef040e48c028cf3386325ced4c9ece4e9eee18431d02a7c344541c730468',
    '35': 'd6d6366dac3b569dc7b5bb18c5e1187affb8899883f938e131d06959116db76e',
    '36': '9ae944d7c443482568a2de2b25faaf15e8bc927f4795c687116202210f7601b2',
    '37': 'bb3be338298e6d72e4fe40e367e5cd00c4ee0523d70139309834b776d3270259',
    '38': '02c99b62666d2da0dd155d342e177ab268f8f11c91d369bfb1eee83b53f2ffc6',
    '39': 'c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b',
    '40': '82ce8d6041effb571108704c2c51f6d039eabaeaf02cedb3a2e05dd7ae33c604',
    '41': '60d659580278bfe3dcc09ca92b1910d4f9d7af27ca8e62e87a67ff9e0d4ae5fe',
    '42': 'a2622f8cd59aeef409f7d316f5802dfe667298396b5c47c2da71700c69c10ceb',
    '43': 'e47b675475c4979b73aae7ef3f73561a5bf34f1ba530d1be00941534164954ee',
    '44': 'b9d55804123a82064e3e0c806767e119cf2d628929eeb9c9e1482d886a475471',
    '45': '77b523c3504700d1b05fdf5eb82c54715cb7e790675e52b01bc52dc1f53491e2',
    '46': '17fbb4ca99df1a1207ea006126ac92617ab8661d86e5a632fe48ee2138290b02',
    '47': '54d43eb8a7ebb408adf840d9d2611b0455e05d9ce5fde413d8b9a1abae9c37c4',
    '48': 'fc7f4cb0419aa445675c1516d560bb43945f620c9b269fa4a7942df874ce2e42',
    '49': '5b3a37a96408fe15d1b9bc256c279091f0ead792c31e8ef9b14728662c5a9842',
    '50': '4b876a7a4d1800fda46b43f96808125431ec72e2b6a2380e6ff209a42c30a1b9',
    '51': '2e9f11e0b5ddd2e91970ba32ac77109f7b786f607e28504244c4c3f9a8a4181e',
    '52': '61b58526f93d4c36294a52934e1cb45152abb91ff44fbc80762df45a99c66232',
    '53': 'f587f445ce66e397718110762c7e952fcb19c03feef4b1ae35c7638209c51f56',
    '54': 'b53162ebca3a11fd57e3d99ba7d4c9998130ddefdcf90be085995bcf9829fcd8',
    '55': 'c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88',
    '56': '31276ba89d9a82184ded209f4eed8e69d23029bba47ccc32b0885944339bd25f',
    '57': '8c635d5060196f6dd56290ab32c63e2ba1f16c22f7d82e33844030c83363fa97',
    '58': '807a0a5be41c4c6e1523e114588c9cd935fbcd49c0e4a3ab6d55781eb2dcb721',
    '59': 'ca8153c0d5f3165fa6b79b4f1b31663babef6a58d71590092edd5910ea723aad',
    '60': 'b2f83a0a1c8bee8adbf79be9ccb8a27b7de066d8495242d2ab16d872e18511f3',
}
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
    parser.add_argument('--mode', choices=('install','restore'), required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--data-backups', type=Path)
    parser.add_argument('--retained-prior', type=Path,
                        help='Explicit retained prior image path; the same exact size and SHA256 remain required')
    parser.add_argument('--android-build', choices=tuple(ANDROID_BUILDS))
    parser.add_argument('--from-android-build', choices=('04', '05', '06', '08', '09', '11', '12', '13', '14', '15', '16', '18', '19', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60'),
                        help='Reviewed upgrades through 59 to 60 and explicit rollback pairs; requires retained prior image')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--verify-each-chunk', action='store_true',
                        help='Optional diagnostic readback in addition to the final full hash')
    args = parser.parse_args()
    if args.mode == 'install' and args.android_build is None:
        parser.error('Installation requires an explicit reviewed --android-build')
    if args.mode == 'restore' and args.android_build is not None:
        parser.error('Android build selection is not used for restoration')
    if args.retained_prior is not None and args.from_android_build is None:
        parser.error('--retained-prior requires --from-android-build')
    expected_current = ORIGINAL
    if args.from_android_build is not None:
        if args.mode != 'install' or (args.from_android_build, args.android_build) not in {('04','05'), ('05','06'), ('06','08'), ('08','09'), ('09','11'), ('11','12'), ('12','13'), ('13','14'), ('14','15'), ('15','16'), ('16','18'), ('18','19'), ('19','21'), ('21','22'), ('22','23'), ('23','24'), ('24','25'), ('25','26'), ('26','27'), ('27','28'), ('28','29'), ('29','30'), ('30','31'), ('31','32'), ('32','33'), ('33','34'), ('34','35'), ('35','36'), ('36','37'), ('37','38'), ('38','39'), ('39','40'), ('40','39'), ('40','41'), ('41','40'), ('41','42'), ('42','41'), ('42','43'), ('43','42'), ('43','44'), ('44','43'), ('44','45'), ('45','44'), ('45','46'), ('46','45'), ('46','47'), ('47','46'), ('47','48'), ('48','47'), ('48','49'), ('49','48'), ('49','50'), ('50','49'), ('50','51'), ('51','50'), ('51','52'), ('52','51'), ('52','53'), ('53','52'), ('53','54'), ('54','53'), ('54','55'), ('55','54'), ('55','56'), ('56','55'), ('56','57'), ('57','56'), ('57','58'), ('58','57'), ('58','59'), ('59','58'), ('59','60'), ('60','59')}:
            parser.error('Only explicitly reviewed installation transitions are allowed')
        retained = args.retained_prior if args.retained_prior is not None else Path(__file__).resolve().parents[1]/('work/engineering-system-'+args.from_android_build+'.raw.img')
        expected_current = ANDROID_BUILDS[args.from_android_build]
        if retained.stat().st_size != SIZE or digest(retained) != expected_current:
            raise ValueError('Verified retained prior image required')
    target_hash = ANDROID_BUILDS[args.android_build] if args.mode == 'install' else ORIGINAL
    if args.image.stat().st_size != SIZE or digest(args.image) != target_hash:
        raise ValueError('Image does not match the reviewed mode-specific hash')
    if args.original.stat().st_size != SIZE or digest(args.original) != ORIGINAL:
        raise ValueError('Verified original-system backup required')
    if args.mode == 'install':
        if args.data_backups is None:
            raise ValueError('Verified writable-partition backups required for installation')
        backups = json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/n139dl-recovery-data-backup.json').read_text())['partitions']
        for name, spec in backups.items():
            path = args.data_backups/(name+'.img')
            if path.stat().st_size != spec['bytes'] or digest(path) != spec['sha256']:
                raise ValueError('Writable-partition backup mismatch: '+name)
    args.output.mkdir(parents=True, exist_ok=False)
    # Chunk staging and the operation journal must fit before any device write.
    if shutil.disk_usage(args.output).free < 256*MIB:
        raise ValueError('At least 256MiB host free space required for chunks and journal')
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
    current_hash = command('sha256sum '+SYSTEM).split()[0]
    if args.mode == 'install' and current_hash != expected_current:
        raise ValueError('Install prestate hash mismatch; use restoration for a partial/changed system')
    evidence = json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/n139dl-engineering-bootchain.json').read_text())
    chain = {x['partition']:x['sha256'] for x in evidence['partitions_verified_against_before_after_hashes']}
    def check_chain():
        for name, expected in chain.items():
            if command('sha256sum /dev/block/bootdevice/by-name/'+name).split()[0] != expected:
                raise ValueError('Boot-chain mismatch: '+name)
    check_chain()
    result = {'preflight_passed':True, 'write_requested':args.write, 'verified_chunks':0,
              'written_chunks':0, 'per_chunk_readback':args.verify_each_chunk,
              'mode':args.mode, 'serial':SERIAL, 'before_system_sha256':current_hash,
              'target_sha256':target_hash, 'android_build':args.android_build,
              'from_android_build':args.from_android_build}
    def save(): (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    save()
    if not args.write:
        print(json.dumps(result)); return
    # Refuse if less than 32MiB is free on recovery tmpfs.
    free = command('df -k /tmp').splitlines()[-1].split()
    if int(free[3])*1024 < 32*MIB: raise ValueError('Insufficient recovery tmpfs space')
    remote = '/tmp/kaidroid-system-'+uuid.uuid4().hex
    command('mkdir '+remote)
    try:
        with args.image.open('rb') as source:
            for index, offset in enumerate(range(0,SIZE,16*MIB)):
                if identity()!=before: raise ValueError('Recovery boot identity changed')
                if shutil.disk_usage(args.output).free < 64*MIB:
                    raise ValueError('Host space dropped below 64MiB; stop before next chunk')
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
                result['written_chunks']=index+1
                if args.verify_each_chunk:
                    actual=command('dd if='+SYSTEM+' bs=1048576 skip='+str(offset//MIB)+' count='+str(len(chunk)//MIB)+' 2>/dev/null | sha256sum').split()[0]
                    if actual!=expected: raise ValueError('Partition chunk readback mismatch')
                    result['verified_chunks']=index+1
                save()
                print(('Verified ' if args.verify_each_chunk else 'Wrote ')+args.mode+' chunk',index+1,'of 50',flush=True)
        if command('sha256sum '+SYSTEM).split()[0]!=target_hash:
            raise ValueError('Final partition hash mismatch')
        check_chain()
        if identity()!=before: raise ValueError('Final identity changed')
        result['full_readback_verified']=True;save()
    except Exception as e:
        result['error']=str(e);result['action']='Stop; remain in recovery. Do not reboot or automatically retry.';save()
        raise
    print(json.dumps(result))


if __name__=='__main__': main()

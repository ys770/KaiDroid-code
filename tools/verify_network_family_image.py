"""Inspect the complete Go network package family in a raw system image (read-only)."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

APKS = {
    'framework/framework-res.apk': [],
    'priv-app/InProcessNetworkStack/InProcessNetworkStack.apk': ['android.uid.system', 'android.net.INetworkStackConnector.InProcess'],
    'priv-app/PlatformNetworkPermissionConfig/PlatformNetworkPermissionConfig.apk': [],
    'app/PlatformCaptivePortalLogin/PlatformCaptivePortalLogin.apk': [],
    'apex/com.android.tethering.inprocess/priv-app/InProcessTethering/InProcessTethering.apk': ['android.uid.system', 'android.net.ITetheringConnector.InProcess'],
    'priv-app/CellBroadcastServiceModulePlatform/CellBroadcastServiceModulePlatform.apk': ['android.uid.phone', 'com.android.phone'],
    'system_ext/priv-app/CellBroadcastAppPlatform/CellBroadcastAppPlatform.apk': ['com.android.cellbroadcastreceiver'],
}
ABSENT = ['priv-app/NetworkStack', 'priv-app/NetworkStackNext', 'app/CaptivePortalLogin',
          'apex/com.android.tethering', 'apex/com.android.cellbroadcast']
EXTRA = ['system_ext/etc/permissions/com.android.cellbroadcastreceiver.xml',
         'apex/com.android.tethering.inprocess/javalib/framework-tethering.jar',
         'apex/com.android.tethering.inprocess/apex_manifest.pb']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('image', 'staging', 'output', 'aapt2', 'apksigner'):
        p.add_argument('--'+n, type=Path, required=True)
    p.add_argument('--java', default='java', help='Java executable when --apksigner names the JAR')
    a = p.parse_args()
    a.output.mkdir(exist_ok=False)
    report = {'files': [], 'absent': [], 'scope': 'Offline packaging and signature checks only; runtime validation required'}
    platform = None
    for name in list(APKS) + EXTRA:
        dest = a.output / Path(name).name
        q = subprocess.run(['debugfs', '-R', 'dump /system/'+name+' '+str(dest), str(a.image)], capture_output=True, check=True)
        if not dest.is_file():
            raise ValueError((name, q.stderr.decode()))
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        assert digest == hashlib.sha256((a.staging/name).read_bytes()).hexdigest(), name
        entry = {'path': '/system/'+name, 'sha256': digest}
        if name in APKS:
            signer = [a.java, '-jar', str(a.apksigner)] if a.apksigner.suffix == '.jar' else [str(a.apksigner)]
            signed = subprocess.run(signer + ['verify', '--print-certs', str(dest)], capture_output=True, text=True)
            (a.output/(dest.name+'.signer.stderr')).write_text(signed.stderr)
            (a.output/(dest.name+'.signer.txt')).write_text(signed.stdout)
            signed.check_returncode()
            sig = signed.stdout
            certs = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)$', sig, re.M)
            assert len(certs) == 1, (name, sig)
            if platform is None:
                platform = certs[0]
            assert certs[0] == platform, ('Platform signer mismatch', name)
            entry['signer_sha256'] = certs[0]
            manifest = subprocess.run([str(a.aapt2), 'dump', 'xmltree', str(dest), '--file', 'AndroidManifest.xml'], capture_output=True, text=True, check=True).stdout
            (a.output/(dest.name+'.manifest.txt')).write_text(manifest)
            for value in APKS[name]:
                assert '"'+value+'"' in manifest, (name, value)
        report['files'].append(entry)
    for name in ABSENT:
        q = subprocess.run(['debugfs', '-R', 'stat /system/'+name, str(a.image)], capture_output=True, check=True)
        assert b'File not found' in q.stderr and b'Inode:' not in q.stdout, name
        report['absent'].append('/system/'+name)
    (a.output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

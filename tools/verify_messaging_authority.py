"""Verify the signed Messaging authority migration without any device commands."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from audit_dex_references import read_dex
from prepare_messaging_authority import OLD, NEW, SOURCE_SHA
from verify_tcl_app_build import PLATFORM_CERT


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'source', 'existing', 'java', 'build-tools', 'resource-audit', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    if digest(a.source) != SOURCE_SHA:
        raise ValueError('Wrong source')
    def run(args):
        return subprocess.check_output([str(x) for x in args], encoding='utf-8', timeout=60)
    sig = run([a.java, '-jar', a.build_tools/'lib/apksigner.jar', 'verify', '--verbose', '--print-certs', a.apk])
    if re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', sig) != [PLATFORM_CERT]:
        raise ValueError('Wrong signer')
    run([a.build_tools/'zipalign.exe', '-c', '-p', '4', a.apk])
    def manifest(file):
        return run([a.build_tools/'aapt.exe', 'dump', 'xmltree', file, 'AndroidManifest.xml'])
    auth = lambda s: set(re.findall(r'android:authorities[^\n]*="([^"]+)"', s))
    tree = manifest(a.apk)
    authorities = auth(tree)
    if NEW not in authorities or authorities & auth(manifest(a.existing)):
        raise ValueError('Authority collision or missing new authority')
    if 'android:sharedUserId' in tree:
        raise ValueError('Unexpected shared UID')
    badging = run([a.build_tools/'aapt.exe', 'dump', 'badging', a.apk])
    if "package: name='com.android.mms'" not in badging or "launchable-activity: name='com.android.mms.ui.ConversationList'" not in badging:
        raise ValueError('Package/launcher identity changed')
    with zipfile.ZipFile(a.source) as old, zipfile.ZipFile(a.apk) as new:
        names = lambda z: {n for n in z.namelist() if not n.startswith('META-INF/') and not n.endswith('/')}
        if names(old) != names(new):
            raise ValueError('Payload entries changed')
        changed = [n for n in sorted(names(old)) if old.read(n) != new.read(n)]
        if changed != ['AndroidManifest.xml', 'classes.dex']:
            raise ValueError('Unexpected payload modifications')
        dex = new.read('classes.dex')
        if OLD.encode() in dex or NEW.encode() not in dex:
            raise ValueError('Wrong DEX authority strings')
        if read_dex(old.read('classes.dex'))[:3] != read_dex(dex)[:3]:
            raise ValueError('DEX type/class/method descriptors changed')
        if new.getinfo('resources.arsc').compress_type != 0:
            raise ValueError('Compressed resource table')
    resources = json.loads(a.resource_audit.read_text())
    if resources['apk_sha256'] != SOURCE_SHA or any(v for k, v in resources['counts'].items() if k != 'same-id'):
        raise ValueError('Wrong or incompatible resource audit')
    report = dict(candidate_sha256=digest(a.apk), source_sha256=SOURCE_SHA,
        package='com.android.mms', launch_component='com.android.mms/com.android.mms.ui.ConversationList',
        signer=PLATFORM_CERT, signature_verified=True, aligned=True, changed_payload=changed,
        dex_types_classes_methods_unchanged=True, old_authority=OLD, new_authority=NEW,
        authorities=sorted(authorities), existing_messaging_sha256=digest(a.existing),
        existing_messaging_authority_collision=False, resource_counts=resources['counts'],
        compiled_xml_files=resources['compiled_xml_files'], framework_sha256=resources['reference_sha256'],
        installed=False, runtime_verified=False, sms_role_changed=False)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

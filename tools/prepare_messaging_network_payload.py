"""Stage the audited image56 Messaging update for a future private system image.

Creates a fresh overlay only. Does not edit a build tree, install, or remove a
data-app override. Existing authority-isolated package layout is preserved.
"""
import argparse
import hashlib
import json
from pathlib import Path
from prepare_messaging_privapp import PERMISSIONS
from update_messaging_network import validate_artifacts

SIGNED = '0b366f5deb8bde6147a13fb4a51fa0646e71e54ce692d0603ca0f3e5f27565e4'


def stage(apk, audit, audit_pin, signing_report, output):
    if validate_artifacts(apk, audit, audit_pin, signing_report) != SIGNED:
        raise ValueError('Only the physically exercised signed image56 candidate is accepted')
    data = apk.read_bytes()
    if hashlib.sha256(data).hexdigest() != SIGNED:
        raise ValueError('Candidate changed after provenance validation')
    files = {
        'system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk': data,
        'system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml': (
            '<?xml version="1.0" encoding="utf-8"?>\n<permissions>\n'
            '    <privapp-permissions package="com.android.mms">\n'
            + ''.join('        <permission name="' + p + '" />\n' for p in PERMISSIONS)
            + '    </privapp-permissions>\n</permissions>\n').encode(),
    }
    output.mkdir(parents=True, exist_ok=False)
    for name, payload in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(payload)
    report = dict(package='com.android.mms', signed_apk_sha256=SIGNED,
        audit_sha256=audit_pin, files={n: hashlib.sha256(b).hexdigest() for n,b in files.items()},
        permissions=list(PERMISSIONS), installed=False, build_tree_changed=False,
        integration_requirements=[
            'Preserve schema68 TelephonyProvider and existing package UID, role and data.',
            'Select one Messaging implementation; reconcile old donor and AOSP modules explicitly.',
            'Verify the actual active APK path/hash after boot; a data-app update may mask the image payload.',
            'Do not uninstall updates or clear app/provider data merely to validate the payload.',
            'Fresh-product and integrated-image boots still require validation; this is only an overlay.',
        ])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'audit', 'signing-report', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--audit-sha256', required=True)
    a = p.parse_args()
    print(json.dumps(stage(a.apk, a.audit, a.audit_sha256, a.signing_report, a.output)))

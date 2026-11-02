"""Stage the verified Messaging APK as a privileged system_ext image payload.

This creates a new local bundle only. It does not install, change package data,
grant roles, modify SettingsProvider or touch a shared build tree.
"""
import argparse
import hashlib
import json
from pathlib import Path

APK_SHA = '210871a165dd08acafa3db9228ae840976e4e7496bb7997b49f1588e0ad241b9'
PERMISSIONS = (
    'android.permission.INTERACT_ACROSS_USERS',
    'android.permission.READ_PRIVILEGED_PHONE_STATE',
    'android.permission.WRITE_APN_SETTINGS',
)


def prepare(apk, output):
    data = apk.read_bytes()
    if hashlib.sha256(data).hexdigest() != APK_SHA:
        raise ValueError('Expected verified authority-isolated Messaging candidate')
    output.mkdir(parents=True, exist_ok=False)
    files = {
        'system_ext/priv-app/KaiDroidTclMessaging/KaiDroidTclMessaging.apk': data,
        'system_ext/etc/permissions/privapp-permissions-kaidroid-messaging.xml': (
            '<?xml version="1.0" encoding="utf-8"?>\n<permissions>\n'
            '    <privapp-permissions package="com.android.mms">\n'
            + ''.join('        <permission name="' + p + '" />\n' for p in PERMISSIONS)
            + '    </privapp-permissions>\n</permissions>\n').encode(),
    }
    for name, payload in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(payload)
    report = dict(package='com.android.mms', apk_sha256=APK_SHA,
        files={name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
        permissions=list(PERMISSIONS), installed=False,
        settings_provider_modified=False, application_code_modified=False,
        integration_requirements=[
            'Map system_ext paths to the existing image layout; retain app data and UID.',
            'Retain schema68 TelephonyProvider candidate704; never package old schema67 provider.',
            'Verify platform signature, privileged flag and granted permissions after boot.',
            'Verify original default SMS holder unchanged before any compose test.',
            'Compare mmsrecipientchip setting before, during and after blank editor cancellation.',
            'Check installed APK hash and detect stale data-app overrides without uninstalling.',
        ])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.apk, args.output)))

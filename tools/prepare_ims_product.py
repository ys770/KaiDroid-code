"""Prepare an inactive private IMS prebuilt bundle; never edits a build tree."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

APK = '496fbafce3cb817106ac4d1e7f7931e79064f8ca163ef3da7a0da9f46f1aab6b'
CERT = 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'java', 'apksigner', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    data = a.apk.read_bytes()
    if sha(data) != APK:
        raise ValueError('Unrecognized IMS APK')
    verified = subprocess.run([str(a.java), '-jar', str(a.apksigner), 'verify',
                               '--print-certs', str(a.apk)], capture_output=True,
                              check=True, timeout=60)
    certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)',
                       verified.stdout.decode())
    if certs != [CERT]:
        raise ValueError('Unexpected verified signer')
    with zipfile.ZipFile(a.apk) as z:
        names = sorted(n for n in z.namelist()
                       if n.startswith('lib/armeabi-v7a/') and n.endswith('.so'))
        if len(names) != 38 or len(set(names)) != 38:
            raise ValueError('Unexpected ARM32 native inventory')
        libs = {Path(n).name: z.read(n) for n in names}
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'lib').mkdir()
    (a.output / 'Ims.apk').write_bytes(data)
    for name, value in libs.items():
        (a.output / 'lib' / name).write_bytes(value)
    mk = '''# Inactive private IMS experiment. Enable only with reviewed framework adapter.
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := KaiDroidQualcommIms
LOCAL_MODULE_CLASS := APPS
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)
LOCAL_SRC_FILES := Ims.apk
LOCAL_CERTIFICATE := PRESIGNED
LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/Ims.apk
LOCAL_PRIVILEGED_MODULE := true
LOCAL_MULTILIB := 32
LOCAL_DEX_PREOPT := false
LOCAL_REQUIRED_MODULES := kaidroid-ims-permissions
LOCAL_PREBUILT_JNI_LIBS := ''' + ' '.join('lib/' + n for n in sorted(libs)) + '''
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := kaidroid-ims-permissions
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := privapp-permissions-kaidroid-ims.xml
LOCAL_MODULE_STEM := privapp-permissions-kaidroid-ims.xml
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/permissions
include $(BUILD_PREBUILT)
'''
    xml = '''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="org.codeaurora.ims">
        <permission name="android.permission.READ_PRECISE_PHONE_STATE" />
        <permission name="android.permission.INTERACT_ACROSS_USERS" />
        <permission name="android.permission.SUBSTITUTE_NOTIFICATION_APP_NAME" />
    </privapp-permissions>
</permissions>
'''
    (a.output / 'Android.mk').write_bytes(mk.encode())
    (a.output / 'privapp-permissions-kaidroid-ims.xml').write_bytes(xml.encode())
    (a.output / 'signature.log').write_bytes(verified.stdout + verified.stderr)
    report = {'scope': 'inactive private prebuilt source bundle', 'apk_sha256': APK,
              'verified_signer': CERT, 'native_library_count': len(libs),
              'native_install_location': 'system/priv-app/KaiDroidQualcommIms/lib/arm',
              'global_native_libraries_replaced': False, 'product_enabled': False,
              'built': False, 'installed': False,
              'files': {str(x.relative_to(a.output)).replace('\\', '/'): sha(x.read_bytes())
                        for x in sorted(a.output.rglob('*')) if x.is_file()},
              'required_next': ['Review actual module graph and installed paths',
                                'Build and audit framework RTT adapter separately',
                                'Integrate reviewed Telephony/framework resource overlays',
                                'Preserve rollback and phone shared-UID data',
                                'Verify final permissions, AppOps, native namespace and IMS binding',
                                'Test registration, media and calls on actual handset']}
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

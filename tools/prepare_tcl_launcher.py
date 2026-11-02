"""Stage the verified private TCL launcher as an AOSP platform-signed prebuilt.

Creates a new directory only. Does not install, flash, or change existing files.
Place output at vendor/kaidroid/tcl-launcher in the private AOSP checkout.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

DONOR_SHA256 = '603f00d40b5ab03bd171f7307d94a838274bdd266575d513a48ac7c7c3586204'
ROTATED_SHA256 = '199a38aa8e94d3bdafe2f5c87dafbc41bb9a1c4cd22052281172804651b0037e'

MODULE = '''LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := KaiDroidTclLauncher
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := APPS
LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)
LOCAL_SRC_FILES := Launcher3.apk
LOCAL_CERTIFICATE := platform
LOCAL_PRIVILEGED_MODULE := true
LOCAL_SYSTEM_EXT_MODULE := true
LOCAL_OVERRIDES_PACKAGES := Launcher3 Launcher3QuickStep Launcher3Go Launcher3QuickStepGo
LOCAL_DEX_PREOPT := false
include $(BUILD_PREBUILT)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rotated-apk', type=Path,
                        help='Verified lab lineage APK, preserved byte-for-byte')
    args = parser.parse_args()
    data = args.apk.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DONOR_SHA256:
        raise ValueError('Unrecognized donor APK; refusing to stage')
    module = MODULE
    certificate = 'platform'
    if args.rotated_apk:
        rotated = args.rotated_apk.read_bytes()
        if hashlib.sha256(rotated).hexdigest() != ROTATED_SHA256:
            raise ValueError('Unrecognized rotated APK; refusing to stage')
        with zipfile.ZipFile(args.apk) as original, zipfile.ZipFile(args.rotated_apk) as candidate:
            entries = lambda z: {n for n in z.namelist() if not n.startswith('META-INF/')}
            if entries(original) != entries(candidate) or any(
                    original.read(n) != candidate.read(n) for n in entries(original)):
                raise ValueError('Rotated APK payload differs from donor')
        data = rotated
        certificate = 'PRESIGNED'
        # Android 11 otherwise aligns/uncompresses PRESIGNED APKs, which can
        # invalidate their v3 signatures. This path copies the verified APK.
        module = module.replace('LOCAL_CERTIFICATE := platform',
            'LOCAL_CERTIFICATE := PRESIGNED\n'
            'LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/Launcher3.apk')
    # mkdir without exist_ok rejects existing directories and symlinks.
    args.output.mkdir(parents=True)
    (args.output / 'Launcher3.apk').write_bytes(data)
    (args.output / 'Android.mk').write_text(module, encoding='utf-8', newline='\n')
    (args.output / 'provenance.json').write_text(json.dumps({
        'donor_sha256': digest,
        'source': str(args.apk.resolve()),
        'module': 'KaiDroidTclLauncher',
        'certificate': certificate,
        'staged_apk_sha256': hashlib.sha256(data).hexdigest(),
        'reason': 'STATUS_BAR_SERVICE is signature-only in the pinned AOSP Android 11 source',
        'built': False,
        'installed': False,
        'warning': 'Different signer from existing testkey launcher; preserve data and plan migration before installing',
    }, indent=2) + '\n', encoding='utf-8')
    print(args.output)


if __name__ == '__main__':
    main()

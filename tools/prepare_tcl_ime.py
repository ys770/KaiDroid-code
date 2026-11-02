"""Stage the pinned TCL IME and tested Nokia model config for a private AOSP build.

Preserves the signed APK; stages system-library resources for the donor's
preinstalled-app lookup. Creates a new output directory, never installs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from prepare_ime_model_config import APK_SHA

CONFIG_SHA = '4b6708df6e5b7ce14f813cf6a3c832f2d26cd0a8eb81caf94232a300f82b1466'
ELF_NAMES = {'libIQQILib.so', 'libIQQI-jni-Resource.so'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sha = lambda data: hashlib.sha256(data).hexdigest()
    apk = args.apk.read_bytes()
    if sha(apk) != APK_SHA:
        raise ValueError('Unrecognized donor APK')
    with zipfile.ZipFile(args.apk) as archive:
        entries = [n for n in archive.namelist() if n.startswith('lib/armeabi/') and n.endswith('.so')]
        if len(entries) != 12 or len(set(entries)) != 12:
            raise ValueError('Unexpected native/resource entries')
        files = {Path(n).name: archive.read(n) for n in entries}
    if {n for n, data in files.items() if data.startswith(b'\x7fELF')} != ELF_NAMES:
        raise ValueError('Unexpected ELF/data classification')
    args.output.mkdir(parents=True)
    subprocess.run([sys.executable, str(Path(__file__).with_name('prepare_ime_model_config.py')),
                    '--apk', str(args.apk), '--output', str(args.output / 'model-config')], check=True)
    candidate = (args.output / 'model-config/libiqqijni.so').read_bytes()
    if sha(candidate) != CONFIG_SHA:
        raise ValueError('Model configuration differs from tested candidate')
    files['libiqqijni.so'] = candidate
    (args.output / 'lib').mkdir()
    (args.output / 'KikaIME.apk').write_bytes(apk)
    modules = []
    chunks = ['LOCAL_PATH := $(call my-dir)\n']
    provenance = {}
    for name, data in sorted(files.items()):
        (args.output / 'lib' / name).write_bytes(data)
        elf = name in ELF_NAMES
        module = name[:-3] if elf else 'kaidroid-ime-data-' + name[:-3]
        modules.append(module)
        lines = ['include $(CLEAR_VARS)', 'LOCAL_MODULE := ' + module,
                 'LOCAL_MODULE_TAGS := optional', 'LOCAL_SRC_FILES := lib/' + name]
        if elf:
            lines += ['LOCAL_MODULE_CLASS := SHARED_LIBRARIES',
                      'LOCAL_MODULE_SUFFIX := .so', 'LOCAL_MULTILIB := 32',
                      'LOCAL_STRIP_MODULE := false',
                      'LOCAL_SHARED_LIBRARIES := libc libdl liblog libm libstdc++']
        else:
            lines += ['LOCAL_MODULE_CLASS := ETC', 'LOCAL_MODULE_STEM := ' + name,
                      'LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)']
        lines += ['include $(BUILD_PREBUILT)', '']
        chunks.append('\n'.join(lines))
        provenance[name] = {'sha256': sha(data), 'kind': 'ELF' if elf else 'data',
                            'module': module, 'destination': 'system/lib/' + name}
    chunks.append('''include $(CLEAR_VARS)
LOCAL_MODULE := KaiDroidTclIme
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := APPS
LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)
LOCAL_SRC_FILES := KikaIME.apk
LOCAL_CERTIFICATE := PRESIGNED
LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/KikaIME.apk
LOCAL_MULTILIB := 32
LOCAL_DEX_PREOPT := false
LOCAL_JNI_SHARED_LIBRARIES := libIQQILib libIQQI-jni-Resource
LOCAL_REQUIRED_MODULES := ''' + ' '.join(modules) + '\ninclude $(BUILD_PREBUILT)\n')
    (args.output / 'Android.mk').write_text('\n'.join(chunks), encoding='utf-8', newline='\n')
    (args.output / 'provenance.json').write_text(json.dumps({
        'donor_apk_sha256': APK_SHA, 'staged_apk_sha256': sha(apk),
        'model_config_sha256': CONFIG_SHA, 'files': provenance,
        'built': False, 'installed': False,
        'limitations': ['System-app resource path needs live validation',
                        'Existing data update may supersede system APK/config lookup',
                        'No default-IME selection or fallback removal'],
    }, indent=2) + '\n', encoding='utf-8')
    print(args.output)


if __name__ == '__main__':
    main()

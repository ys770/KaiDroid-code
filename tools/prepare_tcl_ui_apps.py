"""Prepare private, offline TCL app modules; never stage into a live build tree.

No PRODUCT_PACKAGES or overrides are emitted. Selecting replacements, signing
migration and closing compatibility gates are separate integration decisions.
"""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

from audit_dex_references import archive_dex, OEM_PREFIXES


APPS = {
    'FPContacts': ('com.android.contacts', 'c54b7805d4eb2440660c0f683010edeeb2035f7cb76e4bc18a48319d5fa666b3'),
    'FPMessaging': ('com.android.mms', '501a7a872dd8bd6bd800fe2f59b68b6b28c70b608cdb3d38051479e42f9f5c0e'),
    'GcsDialer': ('com.android.dialer', '46f4280db7bb2191ef4f3ddc562ae363889634aa9dae3e1e6988d5743dbeacac'),
    'TctSettings': ('com.android.settings', 'a01566501a51d34487a63c1e2610d2915a014a46d5ec5b86dd713b3abe7389db'),
}

# Original system/app placement is intentional: do not silently promote these
# packages to privileged apps while preparing their offline modules.
STOCK_APPS = {
    'FPCalendar': ('com.android.calendar', 'bb2c27d93c666a548f84d388c57b70551821fdf72404c1756d221c219ee95168'),
    'FPDeskClock': ('com.android.deskclock', 'a72b3e2f36e7bd6f96d860ba3dac4a2f936efeef0d872b420af0071113153e0b'),
    'JrdGallery': ('com.android.gallery3d', '6c51c324fafe260a278a28c3a6f4563fc378c15e5742a7012ea800edcea39081'),
    'Calculator': ('com.android.calculator2', '41b7bd9e503d6f999999b16048faf5bf50b6175f71e80f6f68bc526c5a9ff447'),
    'Note': ('com.android.note', '13bb553f1341cca973ce35156b7fff2eb8210273e5c976970955dde803f448b5'),
    'FileManager': ('com.jrdcom.filemanager', '7adbffc6e4cb5a007b6b577bf9c79080dd521d4617d429a792cc923ace9c1386'),
}

MEDIA_APPS = {
    'TclMusic': ('com.android.music', '9cdb23dd2a4a8943d41bb8a09e09f5adce58e43fc0af074398ada6562552e9dc'),
    'TctSoundRecorder': ('com.android.soundrecorder', '5aaf31358f97122f02273f5f79fe02c2c4f2a993a6720395b4f43540e763987a'),
    'TctCamera': ('com.tcl.camera', '1fbd1f82b0226e56d08089763c4b6f06ddb84019fd4b4246736d4b90bdb7c6e1'),
}

# Exact outputs of the separately recorded callback/resource transformations.
# These pins select payloads, not a claim that runtime integration has passed.
CANDIDATES = {
    'FPContacts': ('tcl-contacts-callback-candidate01/FPContacts.apk',
                   'c31045c93317a5e1bbe43fd492573f445e57b08e44d425278fbafc113020c610'),
    'TctSettings': ('tcl-settings-resource-candidate02/TctSettings.apk',
                    '5c598de6f2814331cbcafaf64619c92e1f3ab43fd636670309b1c5a5acbe4271'),
}

STOCK_CANDIDATES = {
    'FPDeskClock': ('tcl-clock-title-candidate02/FPDeskClock.apk',
                    '1af8bacfc45b05c0ca35ffd18b5e7fd7b54161d20f443b66e95c943c33dd5b08'),
}


def libraries(badging):
    required = re.findall(r"^uses-library:'([^']+)'$", badging, re.M)
    optional = re.findall(r"^uses-library-not-required:'([^']+)'$", badging, re.M)
    if set(required) & set(optional):
        raise ValueError('Conflicting required/optional library declarations')
    for name in required + optional:
        if not re.fullmatch(r'[A-Za-z0-9_.]+', name):
            raise ValueError('Unsafe library module name')
    return required, optional


def module(name, required, optional, privileged=True):
    lines = [
        'LOCAL_PATH := $(call my-dir)', 'include $(CLEAR_VARS)',
        f'LOCAL_MODULE := KaiDroidTcl{name}', 'LOCAL_MODULE_TAGS := optional',
        'LOCAL_MODULE_CLASS := APPS',
        'LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)',
        f'LOCAL_SRC_FILES := {name}.apk', 'LOCAL_CERTIFICATE := platform',
        'LOCAL_PRIVILEGED_MODULE := ' + ('true' if privileged else 'false'),
        'LOCAL_SYSTEM_EXT_MODULE := true',
        'LOCAL_DEX_PREOPT := false',
    ]
    if required:
        lines.append('LOCAL_USES_LIBRARIES := ' + ' '.join(required))
    if optional:
        lines.append('LOCAL_OPTIONAL_USES_LIBRARIES := ' + ' '.join(optional))
    return '\n'.join(lines + ['include $(BUILD_PREBUILT)', ''])


def prepare(root, aapt, output, candidate_root=None, stock_apps=False, media_apps=False):
    if stock_apps and media_apps:
        raise ValueError('Select one app set')
    candidate_specs = {} if media_apps else STOCK_CANDIDATES if stock_apps else CANDIDATES
    selected_apps = MEDIA_APPS if media_apps else STOCK_APPS if stock_apps else APPS
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    # Complete input validation before creating any output, including later APKs.
    prepared = []
    for name, (package, expected) in selected_apps.items():
        placement = 'app' if stock_apps else 'priv-app'
        relative = f'system/{placement}/{name}/{name}.apk'
        apk = root / relative
        data = apk.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ValueError(f'{name}: unrecognized donor SHA-256')
        payload_source = relative
        if candidate_root is not None and name in candidate_specs:
            payload_source, candidate_expected = candidate_specs[name]
            apk = candidate_root / payload_source
            data = apk.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != candidate_expected:
                raise ValueError(f'{name}: unrecognized candidate SHA-256')
        with zipfile.ZipFile(apk) as archive:
            if archive.testzip() is not None:
                raise ValueError(f'{name}: corrupt ZIP entry')
            native_libraries = [
                {'entry': entry.filename, 'bytes': entry.file_size,
                 'sha256': hashlib.sha256(archive.read(entry)).hexdigest()}
                for entry in archive.infolist()
                if entry.filename.startswith('lib/') and entry.filename.endswith('.so')
            ]
        result = subprocess.run([str(aapt), 'dump', 'badging', str(apk)],
                                check=True, capture_output=True, encoding='utf-8', errors='strict')
        badging = result.stdout.replace('\r\n', '\n')
        if not re.search(r"^package: name='" + re.escape(package) + r"'", badging, re.M):
            raise ValueError(f'{name}: unexpected package')
        required, optional = libraries(badging)
        tree = subprocess.run([str(aapt), 'dump', 'xmltree', str(apk), 'AndroidManifest.xml'],
                              check=True, capture_output=True, encoding='utf-8', errors='strict').stdout
        shared_uid = re.search(r'android:sharedUserId[^=]*="([^"]+)"', tree)
        _, defined, methods, dex_count, errors, warnings = archive_dex(apk, True)
        if errors or not dex_count:
            raise ValueError(f'{name}: DEX audit failed: {errors}')
        external_oem = [dict(owner=o, name=n, descriptor=d) for o, n, d in sorted(methods)
                        if o.startswith(OEM_PREFIXES) and o not in defined]
        prepared.append((name, data, badging, tree, {
            'name': name, 'package': package, 'source': relative,
            'privileged_module': not stock_apps,
            'donor_sha256': expected, 'payload_source': payload_source,
            'payload_kind': 'derived_candidate' if digest != expected else 'original_donor',
            'sha256': digest, 'bytes': len(data), 'dex_entries': dex_count,
            'packaged_native_libraries': native_libraries,
            'required_libraries': required, 'optional_libraries': optional,
            'shared_user_id': shared_uid.group(1) if shared_uid else None,
            'requested_permissions': sorted(set(re.findall(r"^uses-permission[^:]*: name='([^']+)'", badging, re.M))),
            'external_oem_method_references': external_oem, 'dex_warnings': warnings,
            'candidate_certificate': 'platform',
            'gates': {key: 'unverified' for key in (
                'target_framework_api_and_hiddenapi', 'target_resources_and_layout',
                'signing_uid_permissions_and_data_migration', 'library_runtime_paths',
                'qualcomm_telephony_semantics', 'physical_side_by_side_behavior')},
        }))
    report = {
        'schema': 2, 'donor': 'modified live TCL 4058L1/PJEP capture, 2026-10-22',
        'aapt_sha256': hashlib.sha256(aapt.read_bytes()).hexdigest(),
        'built': False, 'installed': False, 'parity_verified': False,
        'scope': 'Pinned APK payloads and standalone research modules only. Native ZIP entries do not cover dynamically loaded libraries. OEM method-table references are not executed call paths or an exhaustive API audit.',
        'apps': [item[4] for item in prepared],
    }
    output.mkdir(parents=True)
    for name, data, badging, tree, entry in prepared:
        directory = output / name
        directory.mkdir()
        (directory / f'{name}.apk').write_bytes(data)
        (directory / 'badging.txt').write_text(badging, encoding='utf-8')
        (directory / 'manifest-tree.txt').write_text(tree, encoding='utf-8')
        (directory / 'Android.mk').write_text(module(name, entry['required_libraries'],
                                                    entry['optional_libraries'],
                                                    entry['privileged_module']), encoding='utf-8', newline='\n')
    (output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--aapt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate-root', type=Path,
                        help='Root containing the pinned Contacts/Settings candidate directories; otherwise use original APKs')
    parser.add_argument('--stock-apps', action='store_true',
                        help='Prepare Calendar, Clock, Gallery, Calculator, Notes and File Manager')
    parser.add_argument('--media-apps', action='store_true',
                        help='Prepare original Music, Sound Recorder and Camera modules')
    args = parser.parse_args()
    report = prepare(args.root, args.aapt, args.output, args.candidate_root, args.stock_apps, args.media_apps)
    print(json.dumps({'output': str(args.output), 'apps': len(report['apps']),
                      'built': False, 'installed': False}))


if __name__ == '__main__':
    main()

"""Isolate TCL Messaging scratch-provider authority, preserving package and SMS role."""
import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from rewrite_clock_identity_smali import rewrite
from rewrite_manifest_identity import rewrite_manifest

SOURCE_SHA = '501a7a872dd8bd6bd800fe2f59b68b6b28c70b608cdb3d38051479e42f9f5c0e'
OLD = 'com.android.messaging.datamodel.MediaScratchFileProvider'
NEW = 'com.kaidroid.messages.datamodel.MediaScratchFileProvider'
SITES = {'smali/com/android/mms/MediaScratchFileProvider.smali': 5,
         'smali/com/android/mms/util/UriUtil.smali': 1}


def transform(source, relative):
    count = source.count('"' + OLD + '"')
    if count != SITES.get(relative, 0):
        raise ValueError('Unexpected authority sites: ' + relative)
    changed, hashes = rewrite(source, {OLD: NEW})
    if hashes or OLD in changed:
        raise ValueError('Unexpected authority/hash reference: ' + relative)
    restored, reverse_hashes = rewrite(changed, {NEW: OLD})
    if restored != source or reverse_hashes:
        raise ValueError('Authority rewrite does not reverse exactly')
    return changed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'decoded', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    if hashlib.sha256(a.apk.read_bytes()).hexdigest() != SOURCE_SHA:
        raise ValueError('Wrong donor APK')
    if a.output.exists():
        raise FileExistsError(a.output)
    with zipfile.ZipFile(a.apk) as apk:
        manifest = apk.read('AndroidManifest.xml')
    if (a.decoded / 'AndroidManifest.xml').read_bytes() != manifest:
        raise ValueError('Expected raw unchanged manifest from apktool decode -r')
    updated_manifest, changes = rewrite_manifest(manifest, {OLD: NEW})
    if len(changes) != 1:
        raise ValueError('Expected exactly one authority manifest string')
    payload = {}
    for file in a.decoded.rglob('*.smali'):
        relative = file.relative_to(a.decoded).as_posix()
        source = file.read_text(encoding='utf-8')
        if NEW in source:
            raise ValueError('New authority already present')
        payload[relative] = transform(source, relative)
    if not SITES.keys() <= payload.keys():
        raise ValueError('Missing reviewed provider classes')
    shutil.copytree(a.decoded, a.output)
    for relative in SITES:
        (a.output / relative).write_text(payload[relative], encoding='utf-8', newline='\n')
    (a.output / 'AndroidManifest.xml').write_bytes(updated_manifest)
    report = dict(source_sha256=SOURCE_SHA, old_authority=OLD, new_authority=NEW,
                  sites=SITES, manifest_changes=changes, smali_files=len(payload),
                  reverse_text_exact=True, apk_built=False, installed=False,
                  package_changed=False, sms_role_changed=False)
    (a.output / 'authority-rewrite.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

"""Port the captured TCL Settings menu presentation, without changing radio policy."""
import argparse
import copy
import hashlib
import json
import zipfile
from pathlib import Path
from compress_apk_dex import is_signature

SOURCE = '63adc2029e3263660232b3dbd279cb3fc04b718f58765116ee710f63c6ba73fb'
APK = '45a3a8b9d7239ecc3d56de9b56b8be3e579c6eb59b7705db168cb9403bb3151d'
FILE = 'smali/com/android/settings/network/TctNetworkDashboardFragment.smali'


def prepare(decoded):
    path = decoded / FILE
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE:
        raise ValueError('Expected untouched candidate03 primary-DEX source')
    text = raw.decode().replace('\r\n', '\n')
    start = text.index('.method public onCreatePreferences(Landroid/os/Bundle;Ljava/lang/String;)V')
    end = text.index('.end method', start)
    method = text[start:end]
    old = '''    invoke-static {}, Lcom/tct/CarrierConfigUtils;->isUsccProduct()Z

    move-result v1'''
    if method.count(old) != 1:
        raise ValueError('Unexpected USCC menu presentation branch')
    method = method.replace(old, '    const/4 v1, 0x1')
    path.write_text(text[:start]+method+text[end:], encoding='utf-8', newline='\n')
    return dict(source_sha256=SOURCE, changed_file=FILE,
        changed_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        behavior='Use donor4058L1 menu rule: remove tether_settings row',
        radio_and_tether_services_changed=False, installed=False)


def package(apk, rebuilt, output):
    if hashlib.sha256(apk.read_bytes()).hexdigest() != APK:
        raise ValueError('Unexpected resource-corrected Settings candidate')
    with zipfile.ZipFile(apk) as src, zipfile.ZipFile(rebuilt) as patch:
        dex = patch.read('classes.dex')
        if dex == src.read('classes.dex'):
            raise ValueError('DEX not changed')
        with zipfile.ZipFile(output, 'x') as dst:
            for info in src.infolist():
                if not is_signature(info.filename):
                    dst.writestr(copy.copy(info), dex if info.filename == 'classes.dex' else src.read(info.filename))
        with zipfile.ZipFile(output) as dst:
            names = {n for n in src.namelist() if not is_signature(n)}
            assert names == set(dst.namelist())
            assert {n for n in names if src.read(n) != dst.read(n)} == {'classes.dex'}
            assert all(src.getinfo(n).compress_type == dst.getinfo(n).compress_type for n in names)
            assert dst.testzip() is None
    return dict(sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                changed_payload=['classes.dex'], resource_mapping_preserved=True,
                unsigned=True, installed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--decoded', type=Path)
    p.add_argument('--apk', type=Path)
    p.add_argument('--rebuilt', type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    if a.decoded and not (a.apk or a.rebuilt or a.output):
        result = prepare(a.decoded)
    elif a.apk and a.rebuilt and a.output and not a.decoded:
        result = package(a.apk, a.rebuilt, a.output)
    else:
        p.error('Use --decoded, or --apk/--rebuilt/--output')
    print(json.dumps(result))

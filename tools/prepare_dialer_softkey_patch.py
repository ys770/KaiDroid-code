"""Reproduce the failed Activity-only Dialpad attempt; do not deploy as a fix."""
import argparse
import copy
import hashlib
import json
import zipfile
from pathlib import Path
from compress_apk_dex import is_signature

APK_SHA = '6ba27affd236fa752e7445c1f0d1591174f2c98352d160ca09ff670f489c14c2'
SOURCE_SHA = 'ac0824bc789eef0a0eeee3d8fd54136b5ebb13df5d366383df082df24702f0e3'
FILE = 'smali/com/android/dialer/app/DialpadActivity.smali'
FORWARD = '''    # The legacy fragment consumes down but forwards only up to MenuBar.
    # Arm only the two soft keys, leaving center/call and digit paths intact.
    const/4 v1, 0x1
    if-eq p1, v1, :kaidroid_forward_soft_down
    const/4 v1, 0x2
    if-ne p1, v1, :kaidroid_soft_down_done
    :kaidroid_forward_soft_down
    invoke-virtual {p0}, Landroid/app/Activity;->getMenuBar()Landroid/widget/MenuBar;
    move-result-object v1
    if-eqz v1, :kaidroid_soft_down_done
    invoke-virtual {v1, p1, p2}, Landroid/widget/MenuBar;->onKeyDown(ILandroid/view/KeyEvent;)Z
    :kaidroid_soft_down_done

'''


def prepare(decoded):
    path = decoded / FILE
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('Unexpected DialpadActivity source')
    text = raw.decode().replace('\r\n', '\n')
    start = text.index('.method public onKeyDown(ILandroid/view/KeyEvent;)Z')
    end = text.index('.end method', start)
    method = text[start:end]
    anchor = '    .line 213\n    invoke-virtual {v0, p1, p2}, Lcom/android/dialer/app/dialpad/DialpadFragment;->onKeyDown(ILandroid/view/KeyEvent;)Z'
    if method.count('    .locals 1') != 1 or method.count(anchor) != 1:
        raise ValueError('Unexpected down-dispatch method')
    method = method.replace('    .locals 1', '    .locals 2').replace(anchor, FORWARD+anchor)
    path.write_text(text[:start]+method+text[end:], encoding='utf-8', newline='\n')
    return dict(source_sha256=SOURCE_SHA, changed_file=FILE,
        changed_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        scope='Existing nonrepeat, nonvolume, nonnull-fragment down path: SOFT_LEFT/RIGHT only',
        call_digit_center_handlers_changed=False, schema_cache_adapters_retained=True, installed=False)


def package(apk, rebuilt, output):
    if hashlib.sha256(apk.read_bytes()).hexdigest() != APK_SHA:
        raise ValueError('Expected reviewed schema/cache-isolated candidate')
    with zipfile.ZipFile(apk) as src, zipfile.ZipFile(rebuilt) as patch:
        dex = patch.read('classes.dex')
        if dex == src.read('classes.dex'):
            raise ValueError('No DEX change')
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
                changed_payload=['classes.dex'], unsigned=True, installed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('decoded', 'apk', 'rebuilt', 'output'):
        p.add_argument('--'+name, type=Path)
    a = p.parse_args()
    if a.decoded and not (a.apk or a.rebuilt or a.output):
        result = prepare(a.decoded)
    elif a.apk and a.rebuilt and a.output and not a.decoded:
        result = package(a.apk, a.rebuilt, a.output)
    else:
        p.error('Use --decoded or --apk/--rebuilt/--output')
    print(json.dumps(result))

"""Set TCL's preview buffer to its declared Camera2 size; no layout/vendor edits.

This is an unverified preview candidate. Video/orientation/capture acceptance is
separate: the shared SurfaceView will also supply 320x240 in video mode.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import zipfile
from compress_apk_dex import is_signature

APK_SHA = 'f8ea9baef449c8e658ac61e4af9b2167040045f339708275b1e34e4735af121e'
SOURCE = '176d397093b2faebd340bd7eda33cbbfaaed11e8ce4028d24343e27bfc002e31'
FILE = 'smali/com/tcl/camera/ui/surface/SurfaceManager.smali'


def prepare(decoded):
    p = decoded / FILE
    raw = p.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE
    text = raw.decode().replace('\r\n', '\n')
    start = text.index('.method public constructor <init>(Landroid/app/Activity;)V')
    end = text.index('.end method', start)
    method = text[start:end]
    anchor = '    invoke-interface {p1, p0}, Landroid/view/SurfaceHolder;->addCallback(Landroid/view/SurfaceHolder$Callback;)V'
    assert method.count(anchor) == 1 and method.count('    .locals 1') == 1
    method = method.replace('    .locals 1', '    .locals 2').replace(anchor, anchor + '''

    # Camera2 deferred OutputConfiguration declares landscape buffer 320x240.
    # Keep portrait SurfaceView bounds; set only the producer buffer dimensions.
    const/16 v0, 0x140
    const/16 v1, 0xf0
    invoke-interface {p1, v0, v1}, Landroid/view/SurfaceHolder;->setFixedSize(II)V
''')
    p.write_text(text[:start] + method + text[end:], encoding='utf-8', newline='\n')
    return dict(changed_file=FILE, source_sha256=SOURCE,
                changed_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                buffer=[320, 240], layout_unchanged=True, vendor_unchanged=True,
                runtime_verified=False, video_verified=False)


def package(apk, rebuilt, output):
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == APK_SHA
    with zipfile.ZipFile(apk) as src, zipfile.ZipFile(rebuilt) as patch:
        dex = patch.read('classes.dex')
        assert dex != src.read('classes.dex')
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
    return dict(sha256=hashlib.sha256(output.read_bytes()).hexdigest(), changed_payload=['classes.dex'], installed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('decoded', 'apk', 'rebuilt', 'output'):
        p.add_argument('--' + name, type=Path)
    a = p.parse_args()
    if a.decoded and not (a.apk or a.rebuilt or a.output):
        r = prepare(a.decoded)
    elif a.apk and a.rebuilt and a.output and not a.decoded:
        r = package(a.apk, a.rebuilt, a.output)
    else:
        p.error('Use --decoded or --apk/--rebuilt/--output')
    print(json.dumps(r))

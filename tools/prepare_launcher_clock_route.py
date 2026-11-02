"""Route the existing TCL Tools Clock slot to the retained-data parallel port."""
import argparse
import copy
import hashlib
import json
import zipfile
from pathlib import Path
from rewrite_manifest_identity import rewrite_resource_strings
from compress_apk_dex import is_signature

SOURCE = '199a38aa8e94d3bdafe2f5c87dafbc41bb9a1c4cd22052281172804651b0037e'
ICON_MAP = 'smali/com/android/launcher3/allapps/ToolsNewActivity.smali'
ICON_SHA = '4f6f33bc0da33a280b377230abdb2772dc7c3357d9266b235dd17194b97ff3e7'


def prepare_icon_map(decoded):
    path=decoded/ICON_MAP;raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ICON_SHA:raise ValueError('Unexpected Tools source')
    text=raw.decode().replace('\r\n','\n')
    start=text.index('.method public initToolsAppIconList()V');end=text.index('.end method',start)
    method=text[start:end]
    if method.count('"com.android.deskclock"')!=1:raise ValueError('Unexpected icon-map site')
    method=method.replace('"com.android.deskclock"','"com.kaidroid.tclclock"')
    path.write_text(text[:start]+method+text[end:],encoding='utf-8',newline='\n')
    return dict(changed_file=ICON_MAP,source_sha256=ICON_SHA,
                changed_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def prepare(apk, output, rebuilt=None):
    if hashlib.sha256(apk.read_bytes()).hexdigest()!=SOURCE:
        raise ValueError('Expected installed rotation-corrected TCL Launcher')
    with zipfile.ZipFile(apk) as src:
        original=src.read('resources.arsc')
        rewritten,changes=rewrite_resource_strings(original,{'com.android.deskclock':'com.kaidroid.tclclock'})
        if len(changes)!=1:
            raise ValueError('Expected one shared global Clock package string')
        reverse,_=rewrite_resource_strings(rewritten,{'com.kaidroid.tclclock':'com.android.deskclock'})
        # The original pool is not sorted; exact reverse equality is required here.
        if reverse!=original:
            raise ValueError('Resource rewrite changed bytes beyond the reviewed string')
        dex=None
        if rebuilt:
            with zipfile.ZipFile(rebuilt) as patch:dex=patch.read('classes.dex')
            if dex==src.read('classes.dex'):raise ValueError('Icon-map DEX unchanged')
        with zipfile.ZipFile(output,'x') as dst:
            for info in src.infolist():
                if not is_signature(info.filename):
                    data=rewritten if info.filename=='resources.arsc' else dex if info.filename=='classes.dex' and dex else src.read(info.filename)
                    dst.writestr(copy.copy(info),data)
        with zipfile.ZipFile(output) as dst:
            names={n for n in src.namelist() if not is_signature(n)}
            assert names==set(dst.namelist())
            assert {n for n in names if src.read(n)!=dst.read(n)}==({'resources.arsc','classes.dex'} if dex else {'resources.arsc'})
            assert all(src.getinfo(n).compress_type==dst.getinfo(n).compress_type for n in names)
            assert dst.testzip() is None
    report=dict(sha256=hashlib.sha256(output.read_bytes()).hexdigest(),source_sha256=SOURCE,
        changes=changes,changed_payload=['resources.arsc','classes.dex'] if dex else ['resources.arsc'],
        manifest_layouts_unchanged=True,icon_map_adapted=bool(dex),
        resource_indexes_ids_offsets_preserved=True,reverse_resource_bytes_equal=True,
        original_clock_package_data_untouched=True,unsigned=True,installed=False)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('apk','output','rebuilt','decoded'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    if a.decoded and not(a.apk or a.output or a.rebuilt):result=prepare_icon_map(a.decoded)
    elif a.apk and a.output and not a.decoded:result=prepare(a.apk,a.output,a.rebuilt)
    else:p.error('Use --decoded, or --apk/--output and optional --rebuilt')
    print(json.dumps(result))

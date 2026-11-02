"""Arm soft keys on the Fragment path verified by the Nokia key trace."""
import argparse
import hashlib
import json
from pathlib import Path
from prepare_dialer_softkey_patch import package

FILE='smali/com/android/dialer/app/dialpad/DialpadFragment.smali'
SOURCE='bd8d6b6b7e9e993fa9ff80ac3d7446824d5c9ba79780a6c68900a7d41af3c78e'
FORWARD='''
    # View.OnKeyListener calls this before Activity.onKeyDown. p2 still holds
    # the real event here; the legacy body later reuses p2 for a log String.
    iget-boolean v0, p0, Lcom/android/dialer/app/dialpad/DialpadFragment;->mDialogIsShow:Z
    if-nez v0, :kaidroid_soft_down_done
    const/4 v0, 0x1
    if-eq p1, v0, :kaidroid_soft_down
    const/4 v0, 0x2
    if-ne p1, v0, :kaidroid_soft_down_done
    :kaidroid_soft_down
    invoke-virtual {p2}, Landroid/view/KeyEvent;->getRepeatCount()I
    move-result v0
    if-nez v0, :kaidroid_soft_down_done
    sget-object v0, Lcom/android/dialer/app/dialpad/DialpadFragment;->mMenuBar:Landroid/widget/MenuBar;
    if-eqz v0, :kaidroid_soft_down_done
    invoke-virtual {v0, p1, p2}, Landroid/widget/MenuBar;->onKeyDown(ILandroid/view/KeyEvent;)Z
    :kaidroid_soft_down_done
'''


def prepare(decoded):
    p=decoded/FILE;raw=p.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE:raise ValueError('Unexpected baseline Fragment')
    text=raw.decode().replace('\r\n','\n')
    start=text.index('.method public onKeyDown(ILandroid/view/KeyEvent;)Z')
    end=text.index('.end method',start);method=text[start:end]
    if method.count('    .locals 7\n')!=1:raise ValueError('Unexpected key handler')
    method=method.replace('    .locals 7\n','    .locals 7\n'+FORWARD)
    p.write_text(text[:start]+method+text[end:],encoding='utf-8',newline='\n')
    return dict(source_sha256=SOURCE,changed_file=FILE,changed_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
        scope='Nonrepeated SOFT_LEFT/RIGHT down on real Fragment path, outside active dialogs',
        activity_handler_original=True,logging_removed=True,call_digit_center_logic_unchanged=True,installed=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('decoded','apk','rebuilt','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    if a.decoded and not(a.apk or a.rebuilt or a.output):r=prepare(a.decoded)
    elif a.apk and a.rebuilt and a.output and not a.decoded:r=package(a.apk,a.rebuilt,a.output)
    else:p.error('Use --decoded or --apk/--rebuilt/--output')
    print(json.dumps(r))

"""Record original Kika Symbols/Back bytecode evidence offline; never contact ADB."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

APK='f80ddc5b461d1d23cc05f9c212f43629991766f9630466b89fbdec8b34ea8e7f'
SERVICE='com/iqqijni/dvt912key/keyboard_service/view/HDKeyboardService'
SYMBOL='com/iqqijni/dvt912key/candidate_view/symbol_view/SymbolView'


def sha(data):return hashlib.sha256(data).hexdigest()


def method(folder,owner,signature):
    text=(folder/'smali'/(owner+'.smali')).read_text(encoding='utf-8')
    matches=[m.group() for m in re.finditer(r'(?ms)^\.method[^\n]*\n.*?^\.end method\s*$',text)
             if m.group().splitlines()[0].endswith(' '+signature)]
    if len(matches)!=1:raise ValueError('Missing/ambiguous original method: '+signature)
    return matches[0].rstrip()+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--decoded',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();apk=a.apk.read_bytes()
    if sha(apk)!=APK:raise ValueError('Not exact captured TCL Kika APK')
    with zipfile.ZipFile(a.apk) as z:
        dex={n:sha(z.read(n)) for n in z.namelist() if re.fullmatch(r'classes[0-9]*\.dex',n)}
    definitions={
        'keydown':(SERVICE,'onKeyDown(ILandroid/view/KeyEvent;)Z'),
        'keyup':(SERVICE,'onKeyUp(ILandroid/view/KeyEvent;)Z'),
        'back_policy':(SERVICE,'isJustDoBack()Z'),
        'hide_symbols':(SERVICE,'hideSymbolList()V'),
        'hide_view':(SYMBOL,'hide()V'),
    }
    blocks={n:method(a.decoded,*item) for n,item in definitions.items()}
    required={
        'keydown':['->requestShowSelf(I)V','const/16 v1, 0x1c','const/4 v1, 0x4',
                   '->isJustDoBack()Z','->isSymbolListShown()Z','->hideSymbolList()V','->mOnKeyDownReturnResult:Z'],
        'keyup':['->isJustDoBack()Z','->mOnKeyDownReturnResult:Z'],
        'back_policy':['->getKeyBackToDoDefaultAction()Ljava/lang/Boolean;',
                       '->getKeyBackToDoDefaultActionDefault()Ljava/lang/Boolean;'],
        'hide_symbols':['->hide()V','->pageTo(I)V'],
        'hide_view':['const/16 v1, 0x8','->setVisibility(I)V'],
    }
    for name,markers in required.items():
        if any(marker not in blocks[name] for marker in markers):raise ValueError('Original bytecode shape changed: '+name)
    for name in ('hide_symbols','hide_view'):
        if any(marker in blocks[name] for marker in ('->requestHideSelf(', '->hideWindow(')):
            raise ValueError('Reviewed hide path changed')
    a.output.mkdir(parents=True,exist_ok=False)
    files={}
    for name,text in blocks.items():
        data=text.encode();(a.output/(name+'.smali')).write_bytes(data);files[name+'.smali']=sha(data)
    report=dict(scope='Offline original APK bytecode/body review; no runtime or physical equivalence claim',
        donor_apk_sha256=APK,donor_dex=dex,decoder='Apktool2.12.1, fresh decode without resources',
        methods={n:dict(owner=definitions[n][0],signature=definitions[n][1],sha256=files[n+'.smali']) for n in definitions},
        findings=[
            'With input allowed and SDK>=28, onKeyDown requests IME show before dispatching the key.',
            'In the isJustDoBack branch, Back with Symbols visible hides its view, records handled Down and consumes it.',
            'The matching Back Up returns handled from the recorded flag.',
            'hideSymbolList calls SymbolView.hide and restores candidate page2 when input is allowed.',
            'SymbolView.hide only sets its layout visibility to GONE(8). Neither reviewed hide method requests IME service hide.',
            'isJustDoBack depends on two external-configuration booleans; their current live values were not read.',
        ],
        interpretation='A visually dismissed Symbols panel can coexist with service mInputShown=true. Requiring mInputShown=false alone is not a justified panel-cancellation oracle.',
        limits=['Marker checks supplement the recorded manual body review; they do not execute the app.',
                'Framework dispatch, external config, focused editor and live IME state still require a matched donor trial.',
                'No source, APK, settings, phone or host build state changed.'],
        live_tcl_comparison=False,full_parity=False)
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()

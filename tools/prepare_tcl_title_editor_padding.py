"""Isolate donor-background padding semantics; never modifies production sources."""
import argparse
import hashlib
import json
from pathlib import Path

BASE='5238bbf6f092587b7c756d6248b0976c9c53b94e13485262e9dd54ce1cf018e3'


def patch(data):
    if hashlib.sha256(data).hexdigest()!=BASE:raise ValueError('Wrong original TitleEditText source')
    text=data.decode('utf-8').replace('\r\n','\n')
    old='''        editor.setPadding(dp(8), editor.getPaddingTop(), editor.getPaddingRight(),
                editor.getPaddingBottom());'''
    new='''        // XML inflation uses this background's padding, not the previous Material
        // EditText underline padding. Retaining that padding clips the28px editor.
        android.graphics.Rect editorPadding = new android.graphics.Rect();
        background.getPadding(editorPadding);
        editor.setPadding(dp(8), editorPadding.top, editorPadding.right, editorPadding.bottom);'''
    if text.count(old)!=1:raise ValueError('Unexpected editor constructor shape')
    return text.replace(old,new).encode('utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();data=patch(a.source.read_bytes());a.output.mkdir(exist_ok=False,parents=True)
    target=a.output/'core/java/android/widget/TitleEditText.java';target.parent.mkdir(parents=True);target.write_bytes(data)
    d=dict(scope='Only TitleEditText constructor padding follows original XML background',baseline_source_sha256=BASE,
        candidate_source_sha256=hashlib.sha256(data).hexdigest(),source_root_modified=False,public_api_changed=False,
        sdk_runtime_verified=False,native_built=False,installed=False,full_parity=False)
    (a.output/'contract.json').write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8');print(json.dumps(d))


if __name__=='__main__':main()

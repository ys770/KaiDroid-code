"""Prepare isolated original-checkbox binding over accepted image49; never edit active source."""
import argparse
import hashlib
import json
from pathlib import Path

BASE='e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6'
OLD='''                // Keep the native check artwork until the separate original
                // donor artwork port; match its measured18dp slot and spacing.
                Drawable icon = checkbox.getButtonDrawable();'''
NEW='''                // The separately audited original four-state selector keeps
                // its donor pixels; older resource images retain native art.
                int donorIcon = getContext().getResources().getIdentifier(
                        "zz_kaidroid_tcl_dialog_checkbox", "drawable", "android");
                Drawable icon = donorIcon == 0 ? checkbox.getButtonDrawable()
                        : getContext().getDrawable(donorIcon);'''


def bind(data):
    if hashlib.sha256(data).hexdigest()!=BASE:
        raise ValueError('Binding requires exact accepted49 source with dialog IME ownership')
    text=data.decode('utf-8')
    if text.count('        bar.setImeModeEnabled(false);') != 1:
        raise ValueError('Accepted49 Cancel ownership must be retained')
    newline='\r\n' if '\r\n' in text else '\n'
    old=OLD.replace('\n',newline);new=NEW.replace('\n',newline)
    if text.count(old)!=1 or text.count('                    icon.setTintList(colors);')!=1:
        raise ValueError('Unreviewed checkbox source shape')
    text=text.replace(old,new).replace('                    icon.setTintList(colors);',
        '                    icon.setTintList(donorIcon == 0 ? colors : null);'+newline+
        '                    checkbox.setCompoundDrawableTintList(null);')
    return text.encode('utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    data=bind(a.source.read_bytes());a.output.mkdir(parents=True)
    dest=a.output/'core/java/android/app/TctDialog.java';dest.parent.mkdir(parents=True);dest.write_bytes(data)
    report=dict(baseline_source_sha256=BASE,candidate_source_sha256=hashlib.sha256(data).hexdigest(),
        source_file='core/java/android/app/TctDialog.java',resource_contract='docs/contracts/tcl-checkbox-overlay01.json',
        new_resource_lookup='android:drawable/zz_kaidroid_tcl_dialog_checkbox',
        original_artwork_tinted=False,native_fallback_only_if_selector_missing=True,
        active_framework_source_modified=False,platform_built=False,installed=False,
        dialog_ime_ownership_retained=True,scope='Isolated future checkbox binding over accepted49; no production resource build or installation')
    (a.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()

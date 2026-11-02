"""Prepare isolated original Calendar adapter API support; never install."""
import argparse
import hashlib
import json
from pathlib import Path

BASE = 'e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6'


def patch(data, version=1):
    if version not in (1,2):raise ValueError('Unreviewed adapter variant')
    if hashlib.sha256(data).hexdigest() != BASE:
        raise ValueError('Requires exact accepted49 dialog with Cancel ownership')
    text = data.decode('utf-8').replace('\r\n', '\n')
    edits = {
        'import android.widget.ListView;': 'import android.widget.ListView;\nimport android.widget.ListAdapter;',
        '    private CharSequence[] listItems;': '    private CharSequence[] listItems;\n    private ListAdapter suppliedAdapter;',
        '} else if (listItems != null) {': '} else if (listItems != null || suppliedAdapter != null) {',
        'list.setAdapter(new ArrayAdapter<CharSequence>': 'list.setAdapter(suppliedAdapter != null ? suppliedAdapter : new ArrayAdapter<CharSequence>',
        '                && list != null && list.hasFocus();': '''                && list != null && list.hasFocus()
                && !(suppliedAdapter != null && buttons[1] != null);''',
        '    public TctDialog setCheckedItems(': '''    /** Original setter stores the adapter; a visible list is not rebound. */
    public TctDialog setListAdapter(ListAdapter adapter, DialogInterface.OnClickListener listener) {
        suppliedAdapter = adapter;
        listListener = listener;
        return this;
    }
    /** Original public API spelling is intentional. */
    public int getListSelectedPoistion() {
        return list == null ? -1 : list.getSelectedItemPosition();
    }
    public TctDialog setCheckedItems(''',
    }
    for old, new in edits.items():
        if text.count(old) != 1:
            raise ValueError('Unreviewed adapter source shape: ' + old)
        text = text.replace(old, new)
    if version==2:
        old='''        boolean contentCenter = code == KeyEvent.KEYCODE_DPAD_CENTER
                && list != null && list.hasFocus()
                && !(suppliedAdapter != null && buttons[1] != null);
        if (contentCenter) bar.clearSoftKeyState();'''
        new='''        boolean contentCenter = code == KeyEvent.KEYCODE_DPAD_CENTER
                && list != null && list.hasFocus();
        if (contentCenter && buttons[1] != null) {
            // Original dialog invokes its explicit center action before letting
            // the focused list consume the same event. Keep paired bar state.
            boolean buttonHandled = false;
            if (event.getAction() == KeyEvent.ACTION_DOWN) buttonHandled = bar.onKeyDown(code, event);
            if (event.getAction() == KeyEvent.ACTION_UP) buttonHandled = bar.onKeyUp(code, event);
            boolean listHandled = super.dispatchKeyEvent(event);
            return buttonHandled || listHandled;
        }
        if (contentCenter) bar.clearSoftKeyState();'''
        if text.count(old)!=1:raise ValueError('Unreviewed list/center dispatch source')
        text=text.replace(old,new)
    return text.encode('utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version',type=int,choices=(1,2),default=1)
    p.add_argument('--build-inputs',action='store_true',help='Include exact retained native08 policy inputs; never prepare a host job')
    p.add_argument('--retained-overlay',type=Path,help='Frozen native08 input overlay, required with --build-inputs')
    a = p.parse_args()
    if a.build_inputs!=bool(a.retained_overlay):p.error('--build-inputs and --retained-overlay must be supplied together')
    a.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    name = 'core/java/android/app/TctDialog.java'
    original=(a.retained_overlay/name) if a.build_inputs else (root/'framework'/name)
    data = patch(original.read_bytes(),a.version)
    files={name:data}
    if a.build_inputs:
        for relative,pin in {
            'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
            'core/java/android/widget/KeypadImeController.java':'d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd',
            'core/java/android/widget/KeypadImeModeState.java':'cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806',
        }.items():
            source=a.retained_overlay/relative
            if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest()!=pin:
                raise ValueError('Retained native08 input changed: '+relative)
            files[relative]=source.read_bytes()
    for relative,content in files.items():
        target=a.output/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
    report = dict(baseline_source_sha256=BASE, files={n: hashlib.sha256(b).hexdigest() for n,b in files.items()},
                  production_root_modified=False, original_adapter8_reference_passed=True,
                  adapter_version=a.version,composite_reference_required=a.version==2,
                  original_adapter_fixture_sha256='03d0979ba1eb9b7c851e7cd31ed4a90c3dbeac213141e9358b49167dcda2cde8',
                  composite_reference_fixture_sha256='901f6750711cc141856d85b96a20f59bc698a95a79e21b713c918610d71b8711' if a.version==2 else None,
                  build_inputs=bool(a.build_inputs),native_audit_baseline='78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2' if a.build_inputs else None,
                  future_image_baseline_selected=False,host_preparation=False,
                  platform_built=False, installed=False)
    (a.output/'contract.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

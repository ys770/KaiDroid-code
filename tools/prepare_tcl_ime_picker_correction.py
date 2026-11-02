"""Isolated correction of native51 picker policy/touch-mode painting. Never install."""
import argparse
import hashlib
import json
from pathlib import Path
from prepare_tcl_ime_picker import sources as original_picker_sources

CONTROLLER51='027507c72249681c2eabd5b4fb47a65e613dfb62a81a9c3ecf84e91d1998077b'
STATE='00cf41fe1e0d8452d7d829db2bd1cee5ba40938830e36f8f5fd394109335d5a1'


def patch_state(data):
    if hashlib.sha256(data).hexdigest()!=STATE:raise ValueError('Unreviewed original mode policy')
    text=data.decode('utf-8').replace('\r\n','\n')
    marker='    /** Only explicit supported selections produce actions; this method sends nothing. */'
    if text.count(marker)!=1 or text.count('!available.contains(mode)')!=1:raise ValueError('Unexpected policy shape')
    menu='''    /** Original MenuBar appends its Symbols command to a multi-mode menu. */
    public List<String> pickerModes() {
        if (!displayEligible || editor == null || label == null) return Collections.emptyList();
        List<String> choices = new ArrayList<>(available);
        if (choices.size() > 1 && !choices.contains("Symbols")) choices.add("Symbols");
        return Collections.unmodifiableList(choices);
    }

    /** Explicit Symbols selection retains the donor's previous-mode/action order. */
    public List<String> selectionActions(String requested) {
        String action = selectionAction(requested);
        if (action == null) return Collections.emptyList();
        List<String> actions = new ArrayList<>();
        if ("Symbols".equals(commandMode(requested))) {
            // The original suffix match is case-sensitive, independently of
            // availability. Do not replay another editor's cached mode.
            for (String previous : new String[]{"Kt9", "abc", "Abc", "ABC", "123", "Symbols"}) {
                if (previous.equals(label)) { actions.add("kika.ime.change.to." + previous); break; }
            }
        }
        actions.add(action);
        return Collections.unmodifiableList(actions);
    }

'''
    text=text.replace(marker,menu+marker).replace('!available.contains(mode)','!pickerModes().contains(mode)')
    return text.encode('utf-8')


def patch_controller(data):
    if hashlib.sha256(data).hexdigest()!=CONTROLLER51:raise ValueError('Unreviewed installed51 source unit')
    text=data.decode('utf-8')
    old='''                    String action = state.selectionAction(choices.get(index));
                    if (action != null) context.sendBroadcast(new Intent(action).setPackage(PACKAGE));'''
    new='''                    String choice = choices.get(index);
                    for (String action : state.selectionActions(choice)) {
                        refreshOwner();
                        if (editor != owner || state.generation() != generation || !pickerFocused()) return;
                        context.sendBroadcast(new Intent(action).setPackage(PACKAGE));
                    }
                    if ("Symbols".equals(choice)) {
                        // Donor showIme uses SHOW_IMPLICIT only for an active,
                        // not-yet-visible served editor. Revalidate our owner too.
                        refreshOwner();
                        if (editor == owner && state.generation() == generation && pickerFocused() && imm != null) {
                            int visible = status();
                            if (visible >= 1 && visible < 3) imm.showSoftInput(owner, InputMethodManager.SHOW_IMPLICIT);
                        }
                    }'''
    selector='''        StateListDrawable focus = new StateListDrawable();
        focus.addState(new int[]{android.R.attr.state_focused}, new ColorDrawable(0xff4484cc));
        focus.addState(new int[]{}, new ColorDrawable(Color.WHITE));
        list.setSelector(focus);'''
    row='row.setTextColor(active ? Color.WHITE : Color.BLACK); row.setSelected(active);'
    if text.count(old)!=1 or text.count(selector)!=1 or text.count(row)!=2:
        raise ValueError('Unreviewed controller/picker shape')
    text=text.replace('new ArrayList<>(state.availableModes())','new ArrayList<>(state.pickerModes())')
    text=text.replace('if (choices.isEmpty()) return;','if (choices.size() < 2) return;')
    text=text.replace(old,new).replace(selector,'''        list.setSelector(new ColorDrawable(Color.TRANSPARENT));
        list.setDefaultFocusHighlightEnabled(false);''')
    text=text.replace('                row.setBackgroundColor(Color.TRANSPARENT);\n','')
    text=text.replace(row,row+'\n                row.setBackgroundColor(active ? 0xff4484cc : Color.WHITE);')
    anchor='        setContentView(content);'
    if text.count(anchor)!=1:raise ValueError('Unexpected picker content binding')
    text=text.replace(anchor,anchor+'''
        // A touch-mode ListView otherwise spends the first arrow resurrecting
        // selection. Route keypad navigation before its default dispatcher.
        setOnKeyListener((dialog, code, event) -> {
            if (code == KeyEvent.KEYCODE_DPAD_DOWN || code == KeyEvent.KEYCODE_DPAD_UP) {
                if (event.getAction() == KeyEvent.ACTION_DOWN && !event.isCanceled()
                        && isShowing() && getWindow().getDecorView().hasWindowFocus()) {
                    int next = selection + (code == KeyEvent.KEYCODE_DPAD_DOWN ? 1 : -1);
                    selection = (next + list.getCount()) % list.getCount();
                    list.setSelection(selection);
                    updateRows();
                }
                return true;
            }
            if (code == KeyEvent.KEYCODE_DPAD_CENTER || code == KeyEvent.KEYCODE_ENTER) {
                if (event.getAction() == KeyEvent.ACTION_DOWN) footer.onKeyDown(code, event);
                else if (event.getAction() == KeyEvent.ACTION_UP) footer.onKeyUp(code, event);
                return true;
            }
            return false;
        });''')
    return text.encode('utf-8')


def sources(root, version=4):
    if version not in (4,5):raise ValueError('Unreviewed correction version')
    base=original_picker_sources(root,2)['core/java/android/widget/KeypadImeController.java']
    controller=patch_controller(base)
    if version==5:
        old='                    for (String action : state.selectionActions(choice)) {'
        new='''                    List<String> actions = state.selectionActions(choice);
                    if (actions.isEmpty()) return;
                    for (String action : actions) {'''
        text=controller.decode('utf-8')
        if text.count(old)!=1:raise ValueError('Unreviewed source for empty-action guard')
        controller=text.replace(old,new).encode('utf-8')
    return {'core/java/android/widget/KeypadImeController.java':controller,
            'core/java/android/widget/KeypadImeModeState.java':patch_state(
                (root/'framework/core/java/android/widget/KeypadImeModeState.java').read_bytes())}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--build-inputs',action='store_true',help='Include exact retained49 MenuBar/Dialog for the preserved48 compile cache')
    p.add_argument('--version',type=int,choices=(4,5),default=4)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    files=sources(root,args.version)
    if args.build_inputs:
        for name,digest in {
            'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
            'core/java/android/app/TctDialog.java':'e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6',
        }.items():
            data=(root/'framework'/name).read_bytes()
            if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Retained49 source changed: '+name)
            files[name]=data
    for name,data in files.items():
        path=args.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    report=dict(baseline_framework_sha256='efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb',
        files={name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
        raw_availability_preserved=True,original_symbols_menu_rule=True,global_touch_mode_changed=False,
        source_root_modified=False,build_inputs=bool(args.build_inputs),
        extra_readonly_bind='core/java/android/widget/KeypadImeModeState.java' if args.build_inputs else None,
        future_image_baseline_selected=False,platform_built=False,installed=False)
    if args.version==5:report.update(correction_version=5,empty_actions_stop_before_broadcast_and_show_ime=True)
    (args.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()

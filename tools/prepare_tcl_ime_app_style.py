"""Preserve the original app-configured mode-row selector over exact native11 sources.

Isolated source candidate only. Never writes production sources or operates a device.
"""
import argparse
import hashlib
import json
from pathlib import Path

PINS={'MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
      'KeypadImeController.java':'d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd'}


def replace_once(text,old,new):
    if text.count(old)!=1:raise ValueError('Unreviewed source shape: '+old[:80])
    return text.replace(old,new)


def sources(inputs):
    data={n:(inputs/n).read_bytes() for n in PINS}
    for name,pin in PINS.items():
        if hashlib.sha256(data[name]).hexdigest()!=pin:raise ValueError('Wrong native11 input: '+name)
    menu=data['MenuBar.java'].decode('utf-8').replace('\r\n','\n')
    menu=replace_once(menu,'    public void setOptionMenuItemBackground(int resource) { optionBackground = resource; }',
        '    public void setOptionMenuItemBackground(int resource) { optionBackground = resource; }\n'
        '    int getInputMethodItemBackground() { return optionBackground; }')
    controller=data['KeypadImeController.java'].decode('utf-8').replace('\r\n','\n')
    controller=replace_once(controller,'new KeypadImePicker(context, choices, index -> {',
        'new KeypadImePicker(context, choices, bar.getInputMethodItemBackground(), index -> {')
    controller=replace_once(controller,'    private boolean dispatched;\n',
        '    private boolean dispatched;\n    private final int itemBackground;\n')
    signature='    KeypadImePicker(Context context, List<String> choices, IntConsumer selected) {\n'
    controller=replace_once(controller,signature,signature+
        '        this(context, choices, 0, selected);\n    }\n\n'
        '    KeypadImePicker(Context context, List<String> choices, int itemBackground, IntConsumer selected) {\n')
    controller=replace_once(controller,'        this.selected = selected;\n',
        '        this.selected = selected;\n        this.itemBackground = itemBackground;\n')
    controller=replace_once(controller,
        'TextView row = convert instanceof TextView ? (TextView) convert : new TextView(getContext());',
        'TextView row = convert instanceof StyledImeRow ? (TextView) convert : new StyledImeRow(getContext());')
    pair='''row.setTextColor(active ? Color.WHITE : Color.BLACK); row.setSelected(active);
                row.setBackgroundColor(active ? 0xff4484cc : Color.WHITE);'''
    if controller.count(pair)!=2:raise ValueError('Expected both row paint sites')
    controller=controller.replace(pair,'styleRow(row, active);')
    controller=replace_once(controller,'        list.setDividerHeight(dp(1));',
        '''        if (itemBackground > 0) {
            android.graphics.drawable.Drawable selector = context.getDrawable(itemBackground).mutate();
            selector.setState(new int[]{android.R.attr.state_enabled});
            android.graphics.drawable.Drawable normal = selector.getCurrent();
            if (normal instanceof ColorDrawable) {
                int color = ((ColorDrawable) normal).getColor();
                background.setColor(color);
                list.setDivider(new ColorDrawable(color));
            }
        }
        list.setDividerHeight(dp(1));''')
    marker='    private int dp(int value)'
    if controller.count(marker)!=1:raise ValueError('Expected picker dp helper')
    helper='''    /** Original input rows use the owning MenuBar's app selector. */
    void styleRow(TextView row, boolean active) {
        row.setTextColor(active ? Color.WHITE : Color.BLACK);
        ((StyledImeRow) row).setImeActive(active);
        if (itemBackground > 0) row.setBackgroundResource(itemBackground);
        else row.setBackgroundColor(active ? 0xff4484cc : Color.WHITE);
    }

    /** ListView owns focus; mirror its active row into focused-state drawables. */
    private static final class StyledImeRow extends TextView {
        private boolean imeActive;
        StyledImeRow(Context context) { super(context); setDefaultFocusHighlightEnabled(false); }
        void setImeActive(boolean active) {
            imeActive = active;
            setSelected(active);
            refreshDrawableState();
        }
        @Override protected int[] onCreateDrawableState(int extraSpace) {
            int[] state = super.onCreateDrawableState(extraSpace + 1);
            if (imeActive) mergeDrawableStates(state, new int[]{android.R.attr.state_focused});
            return state;
        }
    }

'''
    controller=controller.replace(marker,helper+marker)
    return {'core/java/android/widget/MenuBar.java':menu.encode('utf-8'),
            'core/java/android/widget/KeypadImeController.java':controller.encode('utf-8')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();files=sources(a.inputs);a.output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        target=a.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    report=dict(scope='Original app-configured IME row selector over exact native11',
        source_inputs=PINS,files={n:hashlib.sha256(d).hexdigest() for n,d in files.items()},
        app_specific_package_or_color_added=False,default_notes_colors_retained=True,
        callback_owner_and_generation_guards_unchanged=True,source_root_modified=False,
        sdk_runtime_verified=False,native_built=False,installed=False,full_parity=False)
    (a.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()

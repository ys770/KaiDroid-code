"""Generate isolated dialog soft-key ownership fix over exact accepted48 sources."""
import argparse
import hashlib
import json
from pathlib import Path
PINS={'MenuBar.java':'4480147f9a82e04518df0ec4791bc63adbfc35bf00325ae25f25cc0ca8b020f7',
      'TctDialog.java':'a2c00d7728281cd5876674573466a3da2e8ebc9ab56a882351b9e752949c86c6'}


def patch(name,data):
    if name not in PINS or hashlib.sha256(data).hexdigest()!=PINS[name]:
        raise ValueError('Not the exact accepted48 source: '+name)
    text=data.decode('utf-8');newline='\r\n' if '\r\n' in text else '\n'
    text=text.replace('\r\n','\n')
    if name=='TctDialog.java':
        old='        bar = new MenuBar(getContext());'
        new=old+'\n        // This dialog owns explicit callback slots, including editor Cancel.\n        bar.setImeModeEnabled(false);'
        if text.count(old)!=1:raise ValueError('Dialog constructor shape changed')
        text=text.replace(old,new)
    else:
        field='    private KeypadImeController imeController;'
        attach='''        if (imeController == null) imeController = new KeypadImeController(this);
        imeController.attach();'''
        mode='''        resetPresses();
        imeModeLabel = label;'''
        marker='    void clearImeMode() {'
        if any(text.count(x)!=1 for x in (field,attach,mode,marker)):
            raise ValueError('MenuBar source shape changed')
        text=text.replace(field,field+'\n    private boolean imeModeEnabled = true;')
        text=text.replace(attach,'''        if (imeModeEnabled) {
            if (imeController == null) imeController = new KeypadImeController(this);
            imeController.attach();
        }''')
        text=text.replace(mode,'''        if (!imeModeEnabled) return;  // Ignore stale callbacks after an owner opts out.
        resetPresses();
        imeModeLabel = label;''')
        policy='''    /** Reserve an owned dialog's explicit app actions; ordinary windows default on. @hide */
    public void setImeModeEnabled(boolean enabled) {
        if (imeModeEnabled == enabled) return;
        resetPresses();
        imeModeEnabled = enabled;
        if (!enabled) {
            if (imeController != null) imeController.detach();
            clearImeMode();
        } else if (isAttachedToWindow()) {
            if (imeController == null) imeController = new KeypadImeController(this);
            imeController.attach();
        }
    }

'''
        text=text.replace(marker,policy+marker)
    return text.replace('\n',newline).encode('utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    payload={}
    for name,relative in [('MenuBar.java','core/java/android/widget/MenuBar.java'),('TctDialog.java','core/java/android/app/TctDialog.java')]:
        payload[relative]=patch(name,(a.source_root/relative).read_bytes())
    a.output.mkdir(parents=True)
    for relative,data in payload.items():
        target=a.output/'overlay'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    report=dict(baseline_image=48,baseline_source_sha256=PINS,
        files={n:hashlib.sha256(b).hexdigest() for n,b in payload.items()},
        scope='Reserve TctDialog owned callback bar from IME takeover; normal window policy stays enabled',
        active48_sources_modified=False,checkbox_resources_included=False,platform_built=False,installed=False)
    (a.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()

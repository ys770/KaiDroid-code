"""Stage temporary key-path logs on the original Dialer behavior, offline only."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

ACTIVITY = 'smali/com/android/dialer/app/DialpadActivity.smali'
FRAGMENT = 'smali/com/android/dialer/app/dialpad/DialpadFragment.smali'
LISTENER = 'smali/com/android/dialer/app/dialpad/DialpadFragment$1.smali'
PINS = {ACTIVITY:'ac0824bc789eef0a0eeee3d8fd54136b5ebb13df5d366383df082df24702f0e3',
        FRAGMENT:'11efde07ee13ff0ec4af1184e6c6ba35243c869cb02344d669bfaa7453a22db1',
        LISTENER:'a76e9ac160b7c9c082bbd92a8ca547c3e6d75c4c6ea2a12e6609d6348880adbe'}


def log_integer(tag, register):
    return f'''    invoke-static {{{register}}}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    move-result-object v0
    const-string v1, "[KD-DPAD01] {tag}"
    invoke-static {{v1, v0}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
'''


def inject(text, signature, locals_count, logs, new_locals=None):
    start = text.index('.method '+signature+'\n')
    end = text.index('.end method', start)
    method = text[start:end]
    anchor = '    .locals '+str(locals_count)+'\n'
    if method.count(anchor) != 1:
        raise ValueError('Unexpected locals in '+signature)
    method = method.replace(anchor, '    .locals '+str(new_locals or locals_count)+'\n\n'+logs)
    return text[:start]+method+text[end:]


def prepare(decoded, donor, output):
    originals = {}
    for name, pin in PINS.items():
        raw = (donor/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('Unexpected donor class '+name)
        originals[name] = raw.decode().replace('\r\n', '\n')
    # Restore these three unmodified classes first, dropping the failed Activity adapter.
    # All existing cache/schema adapter classes come from the reviewed decoded tree.
    activity = inject(originals[ACTIVITY], 'public onKeyDown(ILandroid/view/KeyEvent;)Z',
                      1, log_integer('A.down.key', 'p1'), 2)
    fragment = originals[FRAGMENT]
    for action, count in [('Down',7),('Up',5)]:
        logs = log_integer('F.'+action.lower()+'.key','p1')+'''    sget-object v0, Lcom/android/dialer/app/dialpad/DialpadFragment;->mMenuBar:Landroid/widget/MenuBar;
    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I
    move-result v0
'''+log_integer('F.'+action.lower()+'.bar','v0')
        fragment = inject(fragment, 'public onKey'+action+'(ILandroid/view/KeyEvent;)Z', count, logs)
    logs = log_integer('V.key','p2')+'''    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I
    move-result v0
'''+log_integer('V.action','v0')
    listener = inject(originals[LISTENER], 'public onKey(Landroid/view/View;ILandroid/view/KeyEvent;)Z',6,logs)
    if output.exists():
        raise ValueError('Use a fresh output directory')
    shutil.copytree(decoded, output, ignore=shutil.ignore_patterns('build'))
    for name, data in [(ACTIVITY,activity),(FRAGMENT,fragment),(LISTENER,listener)]:
        (output/name).write_text(data, encoding='utf-8', newline='\n')
    report = dict(tag='[KD-DPAD01]', changed_methods=4, diagnostic_only=True,
                  original_activity_behavior_restored=True, call_and_digit_behavior_modified=False,
                  cache_schema_adapter_files_unchanged=True, installed=False)
    (output/'trace-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('decoded','donor','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.decoded,a.donor,a.output)))

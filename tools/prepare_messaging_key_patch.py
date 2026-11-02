"""Prepare a pinned Messaging key-consumption fix in a fresh decoded copy."""
import argparse
import copy
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from compress_apk_dex import is_signature

FILE = 'smali/com/android/mms/ui/ConversationList.smali'
SHA = 'f9b4eb8ee10887d927eeaeb183f85cb342f2addaf41b04986fdb4b60525719b9'
OLD = '''    invoke-virtual {p0}, Lcom/android/mms/ui/ConversationList;->onClickLSK()Z

    move-result p0

    return p0'''
NEW = '''    invoke-virtual {p0}, Lcom/android/mms/ui/ConversationList;->onClickLSK()Z

    # The action already ran. Prevent DecorView fallback from invoking it again.
    const/4 p0, 0x1

    return p0'''
COMPOSE = 'smali/com/android/mms/ui/ComposeMessageActivity.smali'
COMPOSE_SHA = '44aa10feacfc50a0c1ebe268708a09b7f8a1d5dda45879dafb033dace8502ee5'


def donor_counter(source):
    data = (source / COMPOSE).read_bytes()
    if hashlib.sha256(data).hexdigest() != COMPOSE_SHA:
        raise ValueError('Unexpected Compose source')
    text = data.decode('utf-8').replace('\r\n', '\n')
    start = text.index('.method private updateCounter(Ljava/lang/CharSequence;III)V')
    end = text.index('.end method', start)
    old = '''    invoke-static {}, Lcom/android/mms/util/BuildProperties;->isUSCC()Z

    move-result p4'''
    method = text[start:end]
    if method.count(old) != 1:
        raise ValueError('Unexpected donor counter-profile branch')
    # Use the reference model's presentation rule only here. Leave carrier
    # selection, SIM detection, length calculation and all send logic intact.
    method = method.replace(old, '    const/4 p4, 0x1')
    return text[:start] + method + text[end:]


def prepare(source, output, counter=False):
    data = (source / FILE).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Unexpected ConversationList source')
    text = data.decode('utf-8').replace('\r\n', '\n')
    start = text.index('.method public onKeyUp(ILandroid/view/KeyEvent;)Z')
    end = text.index('.end method', start)
    method = text[start:end]
    if method.count(OLD) != 1:
        raise ValueError('Unexpected left-key handler')
    changed = text[:start] + method.replace(OLD, NEW) + text[end:]
    counter_text = donor_counter(source) if counter else None
    if output.exists():
        raise ValueError('Use a fresh output directory')
    shutil.copytree(source, output)
    (output / FILE).write_text(changed, encoding='utf-8', newline='\n')
    if counter_text is not None:
        (output / COMPOSE).write_text(counter_text, encoding='utf-8', newline='\n')
    report = dict(source_sha256=SHA, changed_file=FILE,
                  changed_sha256=hashlib.sha256((output / FILE).read_bytes()).hexdigest(),
                  behavior='Consume left key release after the existing action executes once',
                  framework_changed=False, installed=False)
    if counter:
        report['counter'] = dict(source_sha256=COMPOSE_SHA,
            changed_sha256=hashlib.sha256((output / COMPOSE).read_bytes()).hexdigest(),
            reference_profile='4058L1 USCC counter presentation',
            scope='Single-part remaining-character display; other carrier and send behavior unchanged')
    (output / 'key-patch-report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def package(apk, rebuilt, output):
    if hashlib.sha256(apk.read_bytes()).hexdigest() != '210871a165dd08acafa3db9228ae840976e4e7496bb7997b49f1588e0ad241b9':
        raise ValueError('Unexpected authority-isolated APK')
    with zipfile.ZipFile(apk) as src, zipfile.ZipFile(rebuilt) as patch:
        dex = patch.read('classes.dex')
        if dex == src.read('classes.dex'):
            raise ValueError('DEX has not changed')
        with zipfile.ZipFile(output, 'x') as dst:
            for info in src.infolist():
                if not is_signature(info.filename):
                    dst.writestr(copy.copy(info), dex if info.filename == 'classes.dex' else src.read(info.filename))
        with zipfile.ZipFile(output) as dst:
            names = {n for n in src.namelist() if not is_signature(n)}
            assert names == set(dst.namelist())
            assert [n for n in names if src.read(n) != dst.read(n)] == ['classes.dex']
            assert dst.testzip() is None
    return dict(sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                changed_payload=['classes.dex'], unsigned=True, installed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path)
    p.add_argument('--apk', type=Path)
    p.add_argument('--rebuilt', type=Path)
    p.add_argument('--donor-counter', action='store_true')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.source and not (a.apk or a.rebuilt):
        report = prepare(a.source, a.output, a.donor_counter)
    elif a.apk and a.rebuilt and not (a.source or a.donor_counter):
        report = package(a.apk, a.rebuilt, a.output)
    else:
        p.error('Use --source or both --apk and --rebuilt')
    print(json.dumps(report))

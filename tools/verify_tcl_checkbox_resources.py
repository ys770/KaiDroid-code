"""Audit an append-only compiled framework checkbox resource candidate; never install."""
import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile
from PIL import Image
from prepare_tcl_checkbox_overlay import ART, DONOR
from verify_tcl_scrollbar_resources import BASE, parse_dump, sha

PREFIX = 'zz_kaidroid_tcl_'
SELECTOR = 'drawable/'+PREFIX+'dialog_checkbox'
NEW = {SELECTOR, *('drawable/'+PREFIX+name for name in ART)}
STATES = [(False, True, 'checkbox_checked_nofocus'),
          (True, True, 'checkbox_checked_focused'),
          (True, False, 'checkbox_unchecked_focus'),
          (False, False, 'checkbox_unchecked_nofocus')]


def compare_tables(before, after):
    if set(after)-set(before) != NEW or set(before)-set(after):
        raise ValueError('Unexpected added/removed resource names')
    for name, entry in before.items():
        if after[name] != entry:
            raise ValueError('Existing ID/visibility/qualified value changed: '+name)
    old_ids = [int(v['id'], 16) for k, v in before.items() if k.startswith('drawable/')]
    if not old_ids:
        raise ValueError('Missing old drawable type')
    added_ids = [int(after[name]['id'], 16) for name in NEW]
    if len(set(added_ids)) != 5 or any(n <= max(old_ids) or n >> 16 != old_ids[0] >> 16 for n in added_ids):
        raise ValueError('New drawables must append existing type without collisions')
    for name in NEW:
        entry = after[name]
        path = name.split('/')[1]
        pattern = (r'      \(\) \(file\) res/drawable/'+path+r'\.xml type=XML' if name == SELECTOR else
                   r'      \(mdpi(?:-v4)?\) \(file\) res/drawable-mdpi-v4/'+path+r'\.png type=PNG')
        if entry['flags'] or len(entry['values']) != 1 or not re.fullmatch(pattern, entry['values'][0]):
            raise ValueError('Unexpected new drawable configuration/visibility/path: '+name)
    return len(before)


def verify_selector(text, table):
    # Only a selector with exactly four items and the original Android attribute
    # IDs is accepted. Ignore source line numbers, not predicates/references/order.
    lines = text.splitlines()
    if len(lines) != 18 or not re.fullmatch(r'N: android=http://schemas.android.com/apk/res/android \(line=\d+\)', lines[0]) or \
            not re.fullmatch(r'  E: selector \(line=\d+\)', lines[1]):
        raise ValueError('Unexpected compiled selector root/structure')
    for i, (focused, checked, name) in enumerate(STATES):
        part = lines[2+i*4:6+i*4]
        if not re.fullmatch(r'      E: item \(line=\d+\)', part[0]):
            raise ValueError('Unexpected selector item')
        expected = [
            '        A: http://schemas.android.com/apk/res/android:state_focused(0x0101009c)='+str(focused).lower(),
            '        A: http://schemas.android.com/apk/res/android:state_checked(0x010100a0)='+str(checked).lower(),
            '        A: http://schemas.android.com/apk/res/android:drawable(0x01010199)=@'+table['drawable/'+PREFIX+name]['id']]
        if part[1:] != expected:
            raise ValueError('Compiled selector predicate/reference/order changed')
    return 4


def entries(path):
    with zipfile.ZipFile(path) as archive:
        names = [n.filename for n in archive.infolist() if not n.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP entry')
        return {n: archive.read(n) for n in names}


def compare_archives(base, candidate, donor):
    old, new, original = map(entries, (base, candidate, donor))
    signing = lambda n: bool(re.fullmatch(r'META-INF/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))', n))
    payload = lambda files: {n: b for n, b in files.items() if n != 'resources.arsc' and not signing(n)}
    old, new = payload(old), payload(new)
    added = {'res/drawable/'+PREFIX+'dialog_checkbox.xml'} | {
        'res/drawable-mdpi-v4/'+PREFIX+n+'.png' for n in ART}
    if set(new)-set(old) != added or set(old)-set(new):
        raise ValueError('Unexpected APK payload additions/removals')
    for name, data in old.items():
        if new[name] != data:
            raise ValueError('Existing APK payload changed: '+name)
    for name, digest in ART.items():
        reference = original['res/drawable-mdpi-v4/'+name+'.png']
        if sha(reference) != digest:
            raise ValueError('Wrong original artwork')
        left = Image.open(io.BytesIO(reference)).convert('RGBA')
        right = Image.open(io.BytesIO(new['res/drawable-mdpi-v4/'+PREFIX+name+'.png'])).convert('RGBA')
        if left.size != (18, 18) or right.size != left.size or right.tobytes() != left.tobytes():
            raise ValueError('Compiled artwork RGBA/geometry changed')
    return len(old)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('aapt2', 'base', 'candidate', 'donor', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    if sha(args.base.read_bytes()) != BASE or sha(args.donor.read_bytes()) != DONOR:
        raise ValueError('Unreviewed baseline/donor APK')
    def dump(*arguments):
        return subprocess.run([str(args.aapt2), 'dump', *map(str, arguments)], check=True,
                              capture_output=True, text=True, encoding='utf-8', timeout=60).stdout
    before = parse_dump(dump('resources', args.base))
    after = parse_dump(dump('resources', args.candidate))
    count = compare_tables(before, after)
    states = verify_selector(dump('xmltree', '--file', 'res/drawable/'+PREFIX+'dialog_checkbox.xml', args.candidate), after)
    files = compare_archives(args.base, args.candidate, args.donor)
    report = dict(status='PASS', old_resource_ids_and_qualified_values=count,
        unchanged_old_payloads=files, added_drawables=sorted(NEW), selector_states=states,
        artwork_rgba_exact=True, inputs={n:dict(path=str(getattr(args,n)),
        sha256=sha(getattr(args,n).read_bytes())) for n in ('aapt2','base','candidate','donor')},
        scope='Compiled append-only resources only; source binding, signature and native runtime acceptance pending')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(status='PASS', preserved_resources=count, preserved_payloads=files)))


if __name__ == '__main__':
    main()

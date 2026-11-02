"""Fail closed on a compiled scrollbar framework delta; never changes an APK.

All old IDs, qualified values and archive payloads must survive. Only the two
default style bags, two new drawable resources and APK signing records may vary.
This gate does not establish runtime or pixel parity.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import zipfile

from PIL import Image

BASE = '42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
NEW = {f'drawable/zz_kaidroid_tcl_{name}': name for name in
       ('listview_scrollbar_img', 'listview_track_img')}
STYLES = {'style/Widget.ListView', 'style/Widget.ScrollView'}
ATTRS = {'scrollbarThumbVertical': '@drawable/zz_kaidroid_tcl_listview_scrollbar_img',
         'scrollbarTrackVertical': '@drawable/zz_kaidroid_tcl_listview_track_img',
         'fadeScrollbars': 'false'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_dump(text):
    if not text.startswith('Binary APK\nPackage name=android id=01\n'):
        raise ValueError('Expected one android framework package')
    result = {}
    current = None
    ids = set()
    for line in text.splitlines()[2:]:
        match = re.fullmatch(r'    resource (0x[0-9a-f]+) (\S+)(.*)', line)
        if match:
            number, name, flags = match.groups()
            if name in result or number in ids:
                raise ValueError('Duplicate resource identity')
            ids.add(number)
            current = result[name] = {'id': number, 'flags': flags, 'values': []}
        elif line.startswith('  type '):
            current = None
        elif current is not None and line.strip():
            current['values'].append(line)
        elif line.strip():
            raise ValueError('Unrecognized resource dump structure: '+line)
    if not result:
        raise ValueError('Empty resource table')
    return result


def strip_style_additions(lines):
    """Validate all three additions occur only in the default configuration."""
    output = []
    in_default = False
    seen = set()
    for line in lines:
        config = re.fullmatch(r'      \(([^)]*)\) \(style\) size=(\d+)(.*)', line)
        if config:
            in_default = config[1] == ''
            size = int(config[2]) - (3 if in_default else 0)
            if size < 0:
                raise ValueError('Invalid default style size')
            output.append(f'      ({config[1]}) (style) size={size}{config[3]}')
            continue
        item = re.fullmatch(r'        (\w+)\(0x[0-9a-f]+\)=(.*)', line)
        if in_default and item and item[1] in ATTRS:
            if item[1] in seen or item[2] != ATTRS[item[1]]:
                raise ValueError('Wrong or duplicate scrollbar style addition')
            seen.add(item[1])
        else:
            output.append(line)
    if seen != ATTRS.keys():
        raise ValueError('Missing default scrollbar additions')
    return output


def compare_tables(before, after):
    if set(after) - set(before) != NEW.keys() or set(before) - set(after):
        raise ValueError('Unexpected added/removed resource names')
    for name, old in before.items():
        new = after[name]
        if old['id'] != new['id'] or old['flags'] != new['flags']:
            raise ValueError('Old resource ID/visibility changed: '+name)
        values = strip_style_additions(new['values']) if name in STYLES else new['values']
        if values != old['values']:
            raise ValueError('Unrelated qualified value or parent changed: '+name)
    drawable_ids = [int(v['id'], 16) for k, v in before.items() if k.startswith('drawable/')]
    for name in NEW:
        entry = after[name]
        number = int(entry['id'], 16)
        if number <= max(drawable_ids) or number >> 16 != drawable_ids[0] >> 16:
            raise ValueError('New drawable does not append the existing drawable type')
        if entry['flags']:
            raise ValueError('Unexpected new drawable visibility')
        if len(entry['values']) != 1 or not re.fullmatch(
                r'      \(mdpi(?:-v4)?\) \(file\) res/drawable-mdpi-v4/'+
                re.escape(name.split('/')[1])+r'\.9\.png type=PNG', entry['values'][0]):
            raise ValueError('Unexpected new drawable configuration/path: '+name)
    return len(before)


def chunks(data):
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Not a PNG')
    offset = 8
    result = {}
    while offset < len(data):
        size = struct.unpack('>I', data[offset:offset+4])[0]
        kind = data[offset+4:offset+8]
        if offset+size+12 > len(data):
            raise ValueError('Truncated PNG')
        if kind == b'npTc':
            if kind in result:
                raise ValueError('Duplicate nine-patch metadata')
            result[kind] = data[offset+8:offset+8+size]
        offset += size+12
    if b'npTc' not in result:
        raise ValueError('Missing compiled nine-patch metadata')
    return result


def compare_archives(base, candidate, donor, contract):
    def entries(path):
        with zipfile.ZipFile(path) as archive:
            names = [i.filename for i in archive.infolist() if not i.is_dir()]
            if len(names) != len(set(names)):
                raise ValueError('Duplicate ZIP entry')
            return {name: archive.read(name) for name in names}
    old, new, original = map(entries, (base, candidate, donor))
    paths = {'res/drawable-mdpi-v4/'+n.split('/')[1]+'.9.png' for n in NEW}
    # Only APK v1 signing records are excluded; unrelated META-INF is retained.
    signing = lambda n: bool(re.fullmatch(r'META-INF/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))', n))
    old_payload = {n: v for n, v in old.items() if n != 'resources.arsc' and not signing(n)}
    new_payload = {n: v for n, v in new.items() if n != 'resources.arsc' and not signing(n)}
    if set(new_payload)-set(old_payload) != paths or set(old_payload)-set(new_payload):
        raise ValueError('Unexpected APK payload additions/removals')
    for name, data in old_payload.items():
        if new_payload[name] != data:
            raise ValueError('Existing APK payload changed: '+name)
    for name, donor_name in NEW.items():
        path = 'res/drawable-mdpi-v4/'+name.split('/')[1]+'.9.png'
        art = contract['artwork'][donor_name]
        ref = original[art['compiled_entry']]
        if sha(ref) != art['compiled_sha256']:
            raise ValueError('Wrong original artwork')
        actual = new_payload[path]
        if chunks(ref) != chunks(actual):
            raise ValueError('Nine-patch stretch/padding metadata changed')
        left = Image.open(io.BytesIO(ref)).convert('RGBA')
        right = Image.open(io.BytesIO(actual)).convert('RGBA')
        if left.size != right.size or left.tobytes() != right.tobytes():
            raise ValueError('Compiled artwork pixels changed')
    return len(old_payload)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('aapt2', 'base', 'candidate', 'donor', 'contract', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise FileExistsError(a.output)
    contract = json.loads(a.contract.read_text())
    if sha(a.base.read_bytes()) != BASE or sha(a.donor.read_bytes()) != contract['donor_sha256']:
        raise ValueError('Unreviewed baseline/donor APK')
    def dump(path):
        return subprocess.run([str(a.aapt2), 'dump', 'resources', str(path)], check=True,
                              capture_output=True, text=True, encoding='utf-8', timeout=60).stdout
    count = compare_tables(parse_dump(dump(a.base)), parse_dump(dump(a.candidate)))
    files = compare_archives(a.base, a.candidate, a.donor, contract)
    report = dict(status='PASS', old_resource_ids_and_values=count,
                  unchanged_old_payloads=files, changed_default_styles=sorted(STYLES),
                  added_drawables=sorted(NEW), artwork_rgba_and_ninepatch_exact=True,
                  inputs={n: dict(path=str(getattr(a, n)), sha256=sha(getattr(a, n).read_bytes()))
                          for n in ('aapt2', 'base', 'candidate', 'donor', 'contract')},
                  scope='Compiled resource delta only; APK signature, runtime and pixel parity require separate gates')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('status','old_resource_ids_and_values','unchanged_old_payloads')}))


if __name__ == '__main__':
    main()

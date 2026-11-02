"""Stage only the reviewed original battery resource closure into a fresh module."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

APK = 'b7fdb3ef88ed5e3d096ad59aca713a34223268117c020b7cb53638ef6a395188'
CONTRACT = 'f48a90d5b469ceeefc47a10e972d5add3b09d16b10711b7ed97c8767c2e3ab8f'
PREFIX = 'kaidroid_tcl_'
ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
REF = re.compile(r'@\+?(\w+)/(\w+)')
DRAWABLES = '''ic_battery_normal_white ic_battery_charging_percentage_white
ic_battery_fast_charging_white ic_battery_charging_white ic_percentage_red
ic_percentage_foldable ic_percentage_black_ext ic_percentage_black
ic_percentage_white_ext ic_percentage_white ic_battery_saving_yellow
ic_percentage_green_black ic_battery_fast_green_black ic_percentage_green
ic_battery_fast_green ic_battery_green_black ic_battery_green
ic_percentage_fast_bolt ic_percentage_bolt'''.split()
DIMENSIONS = '''battery_container_width battery_container_height
battery_container_margin_left battery_container_margin_top battery_container_margin_top_ext
battery_text battery_text_solo tct_status_bar_battery_icon_width
tct_status_bar_battery_icon_height'''.split()


def digest(data):
    return hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()


def collect(decoded):
    files, values = {}, {}
    public_ids = set()
    for p in sorted(decoded.glob('*/*')):
        if not p.is_file():
            continue
        kind = p.parent.name.split('-')[0]
        if kind == 'values' and p.suffix == '.xml':
            for node in ET.parse(p).getroot():
                if node.tag == 'public':
                    if node.attrib.get('type') == 'id':
                        public_ids.add(node.attrib['name'])
                    continue
                name = node.attrib.get('name')
                if name:
                    typ = node.attrib.get('type') if node.tag == 'item' else node.tag
                    values.setdefault((typ, name), []).append((p, node))
        else:
            files.setdefault((kind, p.name.split('.')[0]), []).append(p)
    needed = {('drawable', name) for name in DRAWABLES}
    needed.update(('dimen', name) for name in DIMENSIONS)
    needed.update({('layout', 'battery_container'), ('anim', 'battery_flash'),
                   ('integer', 'low_battery_level'), ('color', 'light_mode_icon_color_single_tone'),
                   ('color', 'dark_mode_icon_color_single_tone')})
    needed.update({('integer','config_chargingSlowlyThreshold'),('integer','config_chargingFastThreshold')})
    done, chosen_files, chosen_values, inputs = set(), {}, {}, {}
    while needed - done:
        key = sorted(needed - done)[0]
        done.add(key)
        paths = files.get(key, [])
        rows = values.get(key, [])
        if not paths and not rows:
            if key[0] == 'id' and key[1] in public_ids:
                chosen_values.setdefault('values', []).append(ET.Element('item', type='id', name=key[1]))
                continue
            raise ValueError('Missing original resource ' + str(key))
        for p in paths:
            if p.suffix != '.xml':
                raise ValueError('Expected reviewed XML artwork: ' + str(p))
            raw = p.read_bytes()
            inputs[p.relative_to(decoded).as_posix()] = digest(raw)
            node = ET.fromstring(raw)
            chosen_files[p.relative_to(decoded).as_posix()] = node
            needed.update(REF.findall(ET.tostring(node, encoding='unicode')))
        for p, node in rows:
            inputs[p.relative_to(decoded).as_posix()] = digest(p.read_bytes())
            chosen_values.setdefault(p.parent.name, []).append(deepcopy(node))
            needed.update(REF.findall(ET.tostring(node, encoding='unicode')))
    return chosen_files, chosen_values, inputs


def rewritten(node):
    node = deepcopy(node)
    for child in node.iter():
        for name, value in list(child.attrib.items()):
            child.set(name, REF.sub(lambda m: '@' + m[1] + '/' + PREFIX + m[2], value))
        if child.text:
            child.text = REF.sub(lambda m: '@' + m[1] + '/' + PREFIX + m[2], child.text)
    return node


def stage(apk, decoded, contract, output):
    if hashlib.sha256(apk.read_bytes()).hexdigest() != APK:
        raise ValueError('Wrong original SystemUI APK')
    if output.exists():
        raise FileExistsError(output)
    if digest(contract.read_bytes()) != CONTRACT:
        raise ValueError('Unreviewed battery asset contract')
    files, values, inputs = collect(decoded)
    expected = json.loads(contract.read_text())
    if expected['apk_sha256'] != APK or expected['decoded_inputs'] != inputs:
        raise ValueError('Decoded battery resources differ from reviewed contract')
    output.mkdir(parents=True)
    for name, node in files.items():
        source = Path(name)
        dst = output / source.parent / (PREFIX + source.name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(rewritten(node)).write(dst, encoding='utf-8', xml_declaration=True)
    for qualifier, nodes in values.items():
        root = ET.Element('resources')
        for node in nodes:
            node = rewritten(node)
            node.set('name', PREFIX + node.attrib['name'])
            root.append(node)
        p = output / qualifier / 'kaidroid_tcl_battery.xml'
        p.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(root).write(p, encoding='utf-8', xml_declaration=True)
    return dict(apk_sha256=APK, files=len(files), values=sum(map(len, values.values())),
                output=str(output), installed=False, decoded_inputs=inputs)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'decoded', 'contract', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(stage(a.apk, a.decoded, a.contract, a.output)))

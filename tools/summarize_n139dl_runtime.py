"""Produce a sanitized hardware summary from a verified passive capture."""
import argparse
import hashlib
import json
import re
import struct
import tarfile
from pathlib import Path


def bitmap(text):
    return [word * 32 + bit for word, value in enumerate(reversed(text.split()))
            for bit in range(32) if int(value, 16) & (1 << bit)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture did not pass postflight')
    for entry in manifest['reads']:
        data = (args.capture / entry['file']).read_bytes()
        if entry.get('returncode') != 0 or entry['stderr_bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('Incomplete or changed read: ' + entry['file'])
    devices = []
    for block in (args.capture / 'input-devices.txt').read_text().split('\n\n'):
        match = re.search(r'N: Name="(.*)"', block)
        if match:
            item = {'name': match[1]}
            for kind in ('EV', 'KEY', 'SW'):
                bits = re.search(r'^B: ' + kind + r'=(.*)$', block, re.M)
                item[kind] = bitmap(bits[1]) if bits else []
            devices.append(item)
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        properties = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
        handles = {int.from_bytes(data, 'big'): path.rsplit('/', 1)[0]
                   for path, data in properties.items()
                   if path.endswith('/phandle') and len(data) == 4}
        hall_node = './soc/hall_sensor'
        hall = {'node': hall_node, 'runtime_transition_tested': False}
        for prop in ('compatible', 'hall,input_name', 'hall,irq_name'):
            hall[prop] = properties[hall_node + '/' + prop].rstrip(b'\0').decode().split('\0')
        for prop in ('vddio-supply', 'pinctrl-0', 'interrupt-parent'):
            raw = properties[hall_node + '/' + prop]
            if len(raw) != 4 or int.from_bytes(raw, 'big') not in handles:
                raise ValueError('Unresolved hall reference: ' + prop)
            hall[prop] = handles[int.from_bytes(raw, 'big')]
        for prop in ('linux,min-uv', 'linux,max-uv', 'interrupts'):
            raw = properties[hall_node + '/' + prop]
            if len(raw) % 4:
                raise ValueError('Invalid hall cell width')
            hall[prop] = [n[0] for n in struct.iter_unpack('>I', raw)]
        for prop in ('linux,gpio-int', 'qcom,platform-spi-switch-gpio'):
            cells = [n[0] for n in struct.iter_unpack('>I', properties[hall_node + '/' + prop])]
            controller = handles.get(cells[0])
            if not controller or properties.get(controller + '/#gpio-cells') != b'\0\0\0\2' or len(cells) != 3:
                raise ValueError('Unsupported hall GPIO binding: ' + prop)
            hall[prop] = {'controller': controller, 'gpio': cells[1], 'flags_raw': cells[2]}
        hall['wakeup_property_present'] = hall_node + '/linux,wakeup' in properties
        displays = []
        for path, data in properties.items():
            if not path.endswith('/qcom,spi-pref-prim-pan'):
                continue
            if len(data) != 4 or int.from_bytes(data, 'big') not in handles:
                raise ValueError('Unresolved display panel reference: ' + path)
            panel = handles[int.from_bytes(data, 'big')]
            values = {}
            for prop in ('panel-width', 'panel-height', 'bpp', 'panel-framerate'):
                raw = properties.get(panel + '/qcom,mdss-spi-' + prop)
                if raw is not None:
                    if len(raw) != 4:
                        raise ValueError('Unexpected display cell width')
                    values[prop] = int.from_bytes(raw, 'big')
            displays.append({'controller': path.rsplit('/', 1)[0],
                             'preferred_panel_node': panel,
                             'configured_values': values})
        model = tree.extractfile('./model').read().rstrip(b'\0').decode()
        compatible = tree.extractfile('./compatible').read().rstrip(b'\0').decode()
        keymap = tree.extractfile('./soc/matrix_keypad@0/linux,keymap_0').read()
        keys = [{'row': n >> 24, 'column': (n >> 16) & 255, 'code': n & 65535}
                for (n,) in struct.iter_unpack('>I', keymap)]
    props = dict(re.findall(r'^\[(.*?)\]: \[(.*?)\]$',
                           (args.capture / 'properties.txt').read_text(), re.M))
    result = {'fingerprint': manifest['before']['fingerprint'],
              'captured_utc': manifest['finished_utc'],
              'scope': 'Engineering phone 3 only; registration is not functional validation',
              'active_tree_model': model, 'active_tree_compatible': compatible,
              'spi_display_references': displays,
              'hall_binding': hall,
              'display_boot_tokens': [word for word in
                  (args.capture / 'cmdline.txt').read_text().split()
                  if word.startswith('mdss_mdp.panel=')],
              'matrix_keymap': keys, 'input_devices': devices,
              'properties': {k: props.get(k) for k in (
                  'ro.baseband', 'ro.boot.cuid', 'ro.boot.flash.locked',
                  'ro.boot.verifiedbootstate', 'init.svc.vendor.qcrild',
                  'init.svc.vendor.ril-daemon', 'persist.radio.multisim.config')},
              'memory_total_kib': int(re.search(r'MemTotal:\s+(\d+)',
                  (args.capture / 'memory.txt').read_text())[1]),
              'framebuffer': (args.capture / 'display.txt').read_text().splitlines(),
              'source_hashes': {r['file']: r['sha256'] for r in manifest['reads']}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

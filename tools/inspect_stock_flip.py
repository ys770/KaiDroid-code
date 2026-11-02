"""Record bounded static flip/outer-display references in the captured stock B2G library."""
import argparse
import hashlib
import json
import re
from pathlib import Path

LIBRARY_SHA = '26e8ce99d1218a79488e24aba80abf4eb1e726e38a2244d5ace3214df7b58a29'
TOKENS = ('ro.kaios.flipstatus', '/sys/class/leds/sublcd-backlight/brightness',
          'EngmodeManager.setSubLCD', 'EngmodeManager.getFlipState',
          'PHal::Msg_NotifyFlipState', 'PHal::Msg_EnableFlipNotifications',
          'PHal::Msg_DisableFlipNotifications', 'dom.flip.enabled', 'flipOpened')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--vendor-properties', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    data = args.library.read_bytes()
    if hashlib.sha256(data).hexdigest() != LIBRARY_SHA:
        raise ValueError('Unexpected stock library hash')
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    entry = next(e for e in manifest['reads'] if e['file'] == 'properties.txt')
    properties = (args.capture / 'properties.txt').read_bytes()
    if not manifest.get('same_identity_and_boot') or entry['returncode'] or entry['stderr_bytes'] or hashlib.sha256(properties).hexdigest() != entry['sha256']:
        raise ValueError('Invalid captured properties')
    vendor = args.vendor_properties.read_bytes()
    key = 'ro.kaios.flipstatus'
    live = dict(re.findall(r'^\[(.*?)\]: \[(.*?)\]$', properties.decode(), re.M))
    stock = dict(s.split('=', 1) for s in vendor.decode().splitlines() if '=' in s and not s.startswith('#'))
    offsets = {}
    for token in TOKENS:
        values = [m.start() for m in re.finditer(re.escape(token.encode() + b'\0'), data)]
        if not values:
            raise ValueError('Missing expected terminated string: ' + token)
        offsets[token] = values
    result = {'library_sha256': LIBRARY_SHA, 'captured_properties_sha256': entry['sha256'],
              'vendor_properties_sha256': hashlib.sha256(vendor).hexdigest(),
              'terminated_string_file_offsets': offsets,
              'engineering_flipstatus_path': live.get(key), 'retail_flipstatus_path': stock.get(key),
              'scope': 'Static strings and configured property path only; no call-site trace, hall-status read or open/closed polarity test'}
    with args.output.open('x', encoding='utf-8') as f:
        f.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'references': len(offsets), 'engineering_path': live.get(key), 'retail_path': stock.get(key)}))


if __name__ == '__main__':
    main()

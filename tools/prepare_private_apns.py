"""Stage the pinned TCL carrier configuration for a private AOSP build.

Only creates a new output directory. No provider/database or device operations.
Copy the output to vendor/kaidroid/apns in the build checkout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

SOURCE_SHA256 = 'c66c73d3862cb4bc112e39948aa7f9dc6523a23d40b2fb4061ff180767f09068'


def stage(source, output):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unrecognized APN source; output not created')
    root = ET.fromstring(data)
    if root.tag != 'apns' or root.get('version') != '8':
        raise ValueError('Unexpected APN document')
    rows = root.findall('apn')
    if not any(r.get('mcc') == '310' and r.get('mnc') == '240'
               and r.get('apn') == 'fast.t-mobile.com'
               and 'default' in r.get('type', '').split(',') for r in rows):
        raise ValueError('Measured operator APN missing')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'apns-conf.xml').write_bytes(data)
    report = dict(source_sha256=SOURCE_SHA256, source=str(source),
                  entries=len(rows), xml_version=8,
                  destination='system/etc/apns-conf.xml',
                  bytes_preserved=True, device_tested=False,
                  limits=['Private donor configuration; no redistribution permission implied.',
                          'Provider loading and carrier behavior require a new image test.',
                          'Does not migrate or reset an existing APN database.'])
    (output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.source, args.output), indent=2))

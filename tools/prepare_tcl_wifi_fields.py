"""Prepare donor-backed WifiEnterpriseConfig field accessors offline.

These aliases preserve the existing field map and quoting behavior. They do
not establish SIM-slot support in the Wi-Fi service/HAL or connection success.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

SOURCE = '628c1a0e83af9c096f983a7a753c7c2486c38a06dde45e0a2af6b9f082e43674'


def prepare(data):
    if hashlib.sha256(data).hexdigest() != SOURCE:
        raise ValueError('Unexpected WifiEnterpriseConfig source')
    text = data.decode()
    anchor = '    public int getEapMethod() {\n        return mEapMethod;\n    }\n'
    if text.count(anchor) != 1:
        raise ValueError('Nonunique insertion anchor')
    methods = ''
    for name in ('SimSlot', 'IsPresetAp'):
        methods += '\n    /** @hide */\n    public String get' + name + '(String key) {\n'
        methods += '        return getFieldValue(key, "");\n    }\n'
        methods += '\n    /** @hide */\n    public void set' + name + '(String key, String value) {\n'
        methods += '        setFieldValue(key, value, "");\n    }\n'
    return text.replace(anchor, anchor + methods, 1).encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    source = a.source.read_bytes()
    result = prepare(source)
    a.output.mkdir(parents=True)
    (a.output / 'WifiEnterpriseConfig.java').write_bytes(result)
    path = 'wifi/java/android/net/wifi/WifiEnterpriseConfig.java'
    patch = ''.join(difflib.unified_diff(source.decode().splitlines(True),
                    result.decode().splitlines(True), fromfile='a/' + path, tofile='b/' + path))
    (a.output / 'wifi-fields.patch').write_text(patch, newline='\n')
    signatures = []
    for name in ('SimSlot', 'IsPresetAp'):
        signatures += ['Landroid/net/wifi/WifiEnterpriseConfig;->get' + name + '(Ljava/lang/String;)Ljava/lang/String;',
                       'Landroid/net/wifi/WifiEnterpriseConfig;->set' + name + '(Ljava/lang/String;Ljava/lang/String;)V']
    report = dict(source_sha256=SOURCE, candidate_sha256=hashlib.sha256(result).hexdigest(),
                  hiddenapi_additions=signatures, platform_compiled=False, installed=False,
                  physical_parity=False, wifi_service_field_support_verified=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

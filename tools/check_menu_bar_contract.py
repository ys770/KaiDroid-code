"""Compare compiled MenuBar public descriptors with observed donor references.

This verifies method availability only, never behavior or resource compatibility.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--javap', required=True)
    parser.add_argument('--classes', required=True, type=Path)
    parser.add_argument('--android-jar', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target', choices=('MenuBar', 'TctDialog', 'TctDialogMessage', 'TitleEditText'), default='MenuBar')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    methods = {}
    # The original implementation's explicit inheritance chain.
    chains = {
        'TitleEditText': ('android.widget.TitleEditText', 'android.widget.LinearLayout', 'android.view.ViewGroup', 'android.view.View'),
        'MenuBar': ('android.widget.MenuBar', 'android.widget.FrameLayout', 'android.view.ViewGroup', 'android.view.View'),
        'TctDialog': ('android.app.TctDialog', 'android.app.Dialog'),
        'TctDialogMessage': ('android.widget.TctDialogMessage', 'android.widget.TextView', 'android.view.View'),
    }
    chain = chains[args.target]
    for owner in chain:
        proc = subprocess.run([args.javap, '-public', '-s', '-classpath',
                               str(args.classes) + os.pathsep + str(args.android_jar), owner],
                              capture_output=True, text=True, check=True, timeout=30)
        previous = ''
        for line in proc.stdout.splitlines():
            match = re.search(r'descriptor: (\(.*)', line)
            if match and '(' in previous:
                name = previous.split('(')[0].split()[-1]
                if name == owner:
                    if owner != chain[0]:
                        continue  # Constructors are never inherited.
                    name = '<init>'
                methods.setdefault((name, match[1]), owner)
            previous = line.strip()
    contract_name = 'tcl-title-editor.json' if args.target == 'TitleEditText' else 'tcl-ui-methods.json'
    contract = json.loads((root / 'docs/contracts' / contract_name).read_text())
    rows = []
    for method in contract['methods']:
        if method['owner'] == 'L' + chain[0].replace('.', '/') + ';':
            provider = methods.get((method['name'], method['descriptor']))
            rows.append({'name': method['name'], 'descriptor': method['descriptor'],
                         'provider': provider, 'available': provider is not None})
    result = {'scope': 'Public descriptor availability only; no runtime behavior test',
              'target': chain[0],
              'available': sum(row['available'] for row in rows),
              'required': len(rows), 'methods': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('available', 'required')}))


if __name__ == '__main__':
    main()

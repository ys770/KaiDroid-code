"""Extract exact stock-only CIL mapping assignments for an offline compatibility probe.

No rule or mapping is dropped to make compilation pass. This output is not
automatically installed; all newly activated permissions require validation.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from separate_legacy_assertions import forms


def assignments(data):
    text = data.decode()
    found = {}
    for start, end in forms(text):
        form = text[start:end]
        match = re.match(r'\(typeattributeset\s+(\S+)\s', form)
        if match:
            if match[1] in found:
                raise ValueError('Repeated mapping assignment: ' + match[1])
            found[match[1]] = form
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'upstream', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    stock, upstream = args.stock.read_bytes(), args.upstream.read_bytes()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    if sha(stock) != 'c59db461d29abff36b88c3ef3a8f76bd72c834c67ea8f63e268084d19ceb6b60':
        raise ValueError('Unrecognized engineering stock mapping')
    if sha(upstream.replace(b'\r\n', b'\n')) != '71327621085b31d500e909ce5ee16c178c5b52afc28d9b894b98b88e6ea4a3e1':
        raise ValueError('Unrecognized Android11 mapping')
    s, u = assignments(stock), assignments(upstream)
    extra = {name: value for name, value in s.items() if name not in u}
    changed = {name: {'stock': value, 'upstream': u[name]}
               for name, value in s.items() if name in u and value != u[name]}
    args.output.mkdir(parents=True, exist_ok=False)
    data = ('\n'.join(extra.values()) + '\n').encode()
    (args.output / 'stock-only-mapping.cil').write_bytes(data)
    (args.output / 'result.json').write_text(json.dumps({
        'stock_sha256': sha(stock), 'upstream_sha256': sha(upstream),
        'output_sha256': sha(data), 'added_assignments': extra,
        'shared_assignments_with_different_text': changed,
        'scope': 'Offline probe; upstream assignments retained. Requires strict compile and context/permission checks.',
    }, indent=2) + '\n')
    print(json.dumps({'stock_only_assignments': len(extra), 'changed_shared_assignments': len(changed)}))


if __name__ == '__main__':
    main()

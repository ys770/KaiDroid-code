"""Offline original Calculator arithmetic/clear/error route and body comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'com.android.calculator2'
PREFIX = PACKAGE + ':id/'
RECEIPT = ROOT / 'docs/evidence/tcl-calculator-reference01.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def inventory(xml):
    tree = ET.fromstring(xml)
    require(tree.tag == 'hierarchy', 'Complete hierarchy required')
    nodes = list(tree.iter('node'))
    require(nodes and all(n.get('package') == PACKAGE for n in nodes), 'Calculator owner required')
    rows = [{key: n.get(key, '') for key in ('resource-id', 'class', 'text', 'bounds', 'enabled')}
            for n in nodes if n.get('resource-id', '').startswith(PREFIX)]
    require(sum(row['resource-id'] == PREFIX + 'formula_one' for row in rows) == 1, 'One first operand required')
    return rows


def values(xml):
    return {row['resource-id'][len(PREFIX):]: row['text'] for row in inventory(xml) if row['text']}


def references():
    receipt = json.loads(RECEIPT.read_text(encoding='utf-8'))
    require(receipt['apk_sha256'] == '41b7bd9e503d6f999999b16048faf5bf50b6175f71e80f6f68bc526c5a9ff447', 'Original APK binding changed')
    captures = {row['capture']: row for row in receipt['captures']}
    corpus = {}
    for state in receipt['states']:
        name = state['capture']
        row = captures[name]
        for kind in ('xml', 'png'):
            path = ROOT / row[kind]
            path.resolve().relative_to((ROOT / 'docs/screenshots').resolve())
            require(hashlib.sha256(path.read_bytes()).hexdigest() == row[kind + '_sha256'], 'Donor capture changed')
        corpus[name] = (ROOT / row['xml']).read_text(encoding='utf-8')
        require(values(corpus[name]) == state['values'], 'Recorded expression differs from original hierarchy')
    require(len(corpus) == 12 and len(receipt['states']) == 12, 'Exact twelve arithmetic states required')
    return receipt, corpus


def plan():
    receipt, unused = references()
    return [(receipt['states'][i - 1]['capture'], state['key'], state['capture'])
            for i, state in enumerate(receipt['states']) if i]


def compare(reference, candidate):
    a, b = inventory(reference), inventory(candidate)
    def without_bounds(rows):
        return [{k: v for k, v in row.items() if k != 'bounds'} for row in rows]
    return dict(app_body_nodes_exact=a == b, expression_and_structure_exact=without_bounds(a) == without_bounds(b),
                donor_values=values(reference), candidate_values=values(candidate),
                footer_compared=False, footer_exception='Kyocera soft keys',
                pixels_compared=False, physical_keys=False, full_parity=False)


def authorize(source, key, target, current):
    unused, corpus = references()
    require((source, key, target) in plan(), 'Action outside the observed arithmetic route')
    require(compare(corpus[source], current)['expression_and_structure_exact'],
            'Expression/app structure differs; do not overwrite another calculation')
    return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True)
    parser.add_argument('--candidate', required=True, type=Path)
    args = parser.parse_args()
    unused, corpus = references()
    require(args.capture in corpus, 'Unknown donor capture')
    print(json.dumps(compare(corpus[args.capture], args.candidate.read_text(encoding='utf-8')), indent=2))


if __name__ == '__main__':
    main()

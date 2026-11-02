"""Resolve the 15 recorded IMS direct-declaration gaps against image58 classes.

Declaration resolution only: no hidden-API, access, dispatch or runtime claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
from audit_tcl_target_api import archive, resolve

PINS = {
    'framework': 'a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054',
    'core': '6e7721e9665c7f4dd29a4b10edcf75ea2fa80f18d98b840d8e65c6a18bd0ebfa',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('framework', 'core', 'prior', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    prior = json.loads(a.prior.read_text())
    assert prior['candidate_sha256'] == '496fbafce3cb817106ac4d1e7f7931e79064f8ca163ef3da7a0da9f46f1aab6b'
    refs = prior['method_references_without_direct_declaration']
    assert len(refs) == 15 and len(set(map(tuple, refs))) == 15
    classes, inputs = {}, []
    for name, pin in PINS.items():
        path = getattr(a, name)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == pin
        parsed, _, _, warnings = archive(path)
        assert not classes.keys() & parsed.keys()
        classes.update(parsed)
        inputs.append(dict(role=name, sha256=pin, warnings=warnings))
    rows = []
    for owner, name, descriptor in refs:
        provider, missing = resolve(classes, owner, name, descriptor, 'methods')
        rows.append(dict(owner=owner, name=name, descriptor=descriptor,
                         declaring_class=provider, missing_hierarchy=sorted(missing)))
    unresolved = [r for r in rows if r['declaring_class'] is None]
    assert len(unresolved) == 1
    assert unresolved[0]['owner'] == 'Landroid/telephony/ims/ImsCallSessionListener;'
    assert unresolved[0]['name'] == 'callSessionPropertyChanged'
    assert unresolved[0]['descriptor'] == '(I)V'
    assert unresolved[0]['missing_hierarchy'] == []
    report = dict(image=58, candidate_sha256=prior['candidate_sha256'],
                  prior_receipt_sha256=hashlib.sha256(a.prior.read_bytes()).hexdigest(),
                  inputs=inputs, references=rows, inherited_declarations_found=14,
                  missing_declarations=unresolved, installed=False,
                  limitations=['Only the 15 recorded direct-declaration gaps',
                               'No field, visibility, hidden-API or invocation-kind acceptance',
                               'No installed IMS service or call test'])
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(inherited=14, missing=1, output=str(a.output))))


if __name__ == '__main__':
    main()

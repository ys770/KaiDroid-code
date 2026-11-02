"""Update only the two reviewed policy hashes in a new init guard candidate."""
import argparse
import hashlib
import json
from pathlib import Path

HEADER_SHA = '77b20ffd7a16595a6d2131aa705be468194d390e89b88dff289ebbafc91cbef7'
REPLACEMENTS = {
    'f1ed711433c6af43a1d49980ca3a37dc8d80258b41ac33bccdd1b2b401f2ca42':
        '0ca8bbca68b0b6c052ef76047c1885c89b4488f7605e3c9f11d78578f9799a27',
    '31aae0cd7759cce5ea8728e19f9c682ba81f371ffe547daf051d4a9a5e8992c5':
        'f57d2d9bb34fa7f2dcc0e2fc3499b98067c174343c736b0d3a5a631cdb4dbbb9',
}


def prepare(source, output):
    data = (source / 'kaidroid_precompiled_policy.h').read_bytes()
    if hashlib.sha256(data).hexdigest() != HEADER_SHA:
        raise ValueError('Unexpected baseline guard')
    manifest = json.loads((source / 'manifest.json').read_text())
    text = data.decode('utf-8')
    for old, new in REPLACEMENTS.items():
        if text.count(old) != 1:
            raise ValueError('Guard hash missing or ambiguous')
        text = text.replace(old, new)
    reverse = text
    for old, new in REPLACEMENTS.items():
        reverse = reverse.replace(new, old)
    assert reverse.encode('utf-8') == data
    key = '/system_ext/etc/selinux/system_ext_sepolicy.cil'
    manifest['inputs'][key] = REPLACEMENTS[manifest['inputs'][key]]
    manifest['policy_sha256'] = REPLACEMENTS[manifest['policy_sha256']]
    # Old compiler arguments describe baseline31, not this candidate.
    manifest.pop('compiler_arguments', None)
    manifest['compilation_receipt'] = 'docs/evidence/display-resume-candidate-build02.json'
    manifest['installed'] = False
    manifest['init_integrated'] = False
    manifest['guard_source_sha256'] = HEADER_SHA
    manifest['guard_candidate_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'kaidroid_precompiled_policy.h').write_text(text, encoding='utf-8', newline='\n')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.source, a.output), indent=2))

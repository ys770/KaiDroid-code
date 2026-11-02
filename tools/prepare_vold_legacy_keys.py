"""Prepare pinned vold sources preserving original DE/CE blobs in eng builds.

No active checkout or device is modified. Does not disable encryption, skip key
authentication, or promise rollback of secure-world state.
"""
import argparse
import hashlib
import json
from pathlib import Path
from prepare_init_policy_selection import replace_once

PINS = {
    'FsCrypt.cpp': 'ff6429e69c40dcde87e02d58f8bdc47e10826b38b7f65085d371ec9d40acf4d8',
    'Android.bp': 'b4b21eba98984f3be90e1e814cabe6caf5fb9b96bc10611e446e058872977b84',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources = {}
    for name, expected in PINS.items():
        data = (args.source/name).read_bytes().replace(b'\r\n', b'\n')
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Unrecognized source: '+name)
        sources[name] = data.decode()
    source = replace_once(sources['FsCrypt.cpp'], 'using android::vold::retrieveKey;', '''using android::vold::retrieveKey;
#if defined(KAIDROID_ENG_PRESERVE_LEGACY_KEYS)
static constexpr bool kKaiDroidKeepOriginalUserKeys = true;
#else
static constexpr bool kKaiDroidKeepOriginalUserKeys = false;
#endif''')
    calls = [
        'retrieveKey(ce_key_path, auth, ce_key)',
        'retrieveKey(key_path, kEmptyAuthentication, &de_key)',
        'retrieveKey(ce_key_current_path, retrieve_auth, &ce_key)',
        'retrieveKey(ce_key_current_path, kEmptyAuthentication, &ce_key)',
    ]
    for call in calls:
        source = replace_once(source, call, call[:-1]+', kKaiDroidKeepOriginalUserKeys)')
    bp = replace_once(sources['Android.bp'], '    name: "vold_default_flags",', '''    name: "vold_default_flags",
    product_variables: {
        eng: {
            cflags: ["-DKAIDROID_ENG_PRESERVE_LEGACY_KEYS=1"],
        },
    },''')
    args.output.mkdir(parents=True, exist_ok=False)
    outputs = {'FsCrypt.cpp': source, 'Android.bp': bp}
    for name, data in outputs.items():
        (args.output/name).write_text(data, newline='\n')
    result = {'source_sha256': PINS, 'output_sha256': {
        name: hashlib.sha256(data.encode()).hexdigest() for name, data in outputs.items()},
        'changed_calls': calls,
        'scope': 'Eng DE/CE retrieval keeps original blob; upgrade still possible; no secure-world rollback guarantee'}
    (args.output/'selection.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

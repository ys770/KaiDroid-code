"""Check prepared legacy-directory guard against positive and exclusion cases."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = (args.prepared/'builtins.cpp').read_text()
    start = source.index('static Result<void> do_mkdir(')
    body = source[start:source.index('/* umount', start)]
    assert 'lstat(options->target.c_str(), &legacy_state) == 0 &&' in body
    assert 'S_ISDIR(legacy_state.st_mode)' in body
    assert body.count('options->fscrypt_action = FscryptAction::kNone;') == 1
    bp = (args.prepared/'Android.bp').read_text()
    flag = '"-DKAIDROID_ENG_LEGACY_DATA_OWNER=1"'
    assert bp.count(flag) == 1 and bp.index('        eng: {') < bp.index(flag) < bp.index('        uml: {')
    args.output.mkdir(parents=True, exist_ok=False)
    probe = args.output/'probe.cpp'
    header = (args.prepared/'kaidroid_legacy_data.h').resolve().as_posix()
    probe.write_text('#include "'+header+'"\n'+r'''
#include <cassert>
int main() {
#if defined(KAIDROID_ENG_LEGACY_DATA_OWNER)
    const bool eng = true;
#else
    const bool eng = false;
#endif
    auto check = KaiDroidPreservePlatformDirectoryPolicy;
    assert(check("u:r:vendor_init:s0", "/data/hostapd", 5, true) == eng);
    assert(check("u:r:vendor_init:s0", "/data/fota", 3, true) == eng);
    assert(check("u:r:vendor_init:s0", "/data/usbmsc", 5, true) == eng);
    assert(!check("u:r:init:s0", "/data/hostapd", 5, true));
    assert(!check("u:r:su:s0", "/data/hostapd", 5, true));
    assert(!check("u:r:vendor_init:s0", "/data/hostapd", 5, false));
    assert(!check("u:r:vendor_init:s0", "/data/hostapd", 6, true));
    assert(!check("u:r:vendor_init:s0", "/data/hostapd", 1, true));
    assert(!check("u:r:vendor_init:s0", "/data/hostapdx", 5, true));
    assert(!check("u:r:vendor_init:s0", "/data/hostapd/", 5, true));
    assert(!check("u:r:vendor_init:s0", "/data/vendor/wifi", 5, true));
    assert(!check("u:r:vendor_init:s0", "/data/misc", 5, true));
}
''')
    results = {}
    for name, flags in [('eng', ['-DKAIDROID_ENG_LEGACY_DATA_OWNER=1']), ('other', [])]:
        binary = args.output/name
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', *flags,
                        str(probe), '-o', str(binary)], check=True)
        subprocess.run([str(binary.resolve())], check=True)
        results[name] = '12 cases passed'
    results['scope'] = 'Compiled exact guard plus call-site checks; no Android runtime or SELinux execution'
    (args.output/'result.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()

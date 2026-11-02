"""Compile the actual generated path inference in eng and other configurations."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bp = (args.prepared/'Android.bp').read_text()
    flag = '"-DKAIDROID_ENG_LEGACY_FOTA=1"'
    assert bp.count(flag) == 1
    assert bp.index('        eng: {') < bp.index(flag) < bp.index('        uml: {')
    text = (args.prepared/'util.cpp').read_text()
    start = text.index('static FscryptAction FscryptInferAction(')
    end = text.index('Result<MkdirOptions> ParseMkdir', start)
    function = text[start:end]
    args.output.mkdir(parents=True, exist_ok=False)
    probe = args.output/'probe.cpp'
    probe.write_text('''#include <string>
#include <vector>
#include <iostream>
namespace android { namespace base {
bool StartsWith(const std::string& s, const std::string& prefix) { return s.rfind(prefix, 0)==0; }
}}
enum class FscryptAction { kNone, kAttempt, kRequire, kDeleteIfNecessary };
'''+function+'''
int main(int argc, char** argv) {
  for(int i=1;i<argc;++i) std::cout << static_cast<int>(FscryptInferAction(argv[i])) << " ";
}
''')
    paths = ['/data/fota', '/data/fotax', '/data/fota/', '/data/hostapd',
             '/data/usbmsc', '/data/misc/dts', '/data/user', '/data/media/obb',
             '/data/rollback', '/vendor/fota']
    results = {}
    for name, flags, first in [('eng', ['-DKAIDROID_ENG_LEGACY_FOTA=1'], 0), ('other', [], 2)]:
        binary = args.output/name
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', *flags,
                        str(probe), '-o', str(binary)], check=True)
        actual = list(map(int, subprocess.check_output([str(binary.resolve()), *paths]).split()))
        assert actual == [first, 2, 0, 2, 2, 0, 0, 1, 3, 0], (name, actual)
        results[name] = dict(zip(paths, actual))
    results['scope'] = 'Actual inference function; excludes full parser, SELinux and device runtime'
    (args.output/'result.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()

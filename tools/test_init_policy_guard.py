"""Host test of the init guard's hash/path logic, using a mocked Android file API.

Run on Linux with g++ and OpenSSL development headers. This is not an Android
link/boot test. Requires the private captured and generated CIL fixtures.
"""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixtures = [args.stock / 'vendor_sepolicy.cil', args.stock / 'plat_pub_versioned.cil',
                args.candidate / 'vendor_sepolicy.cil', args.candidate / 'plat_pub_versioned.cil',
                args.candidate / '29.0.compat.cil']
    for path in fixtures:
        if not path.is_file():
            raise ValueError('Missing fixture: ' + str(path))
    args.output.mkdir(parents=True, exist_ok=False)
    headers = args.output / 'android-base'
    headers.mkdir()
    (headers / 'file.h').write_text('''#pragma once
#include <map>
#include <string>
extern std::map<std::string, std::string> files;
namespace android { namespace base {
inline bool ReadFileToString(const char* path, std::string* output) {
    auto it = files.find(path);
    if (it == files.end()) return false;
    *output = it->second;
    return true;
}
}}
''')
    (headers / 'logging.h').write_text('#pragma once\n#include <iostream>\n#define LOG(x) std::cerr\n')
    (args.output / 'guard_test.cpp').write_text('''#include "kaidroid_policy.h"
#include <fstream>
#include <iterator>
#include <map>
std::map<std::string, std::string> files;
int main(int argc, char** argv) {
    if (argc != 6) return 2;
    const char* paths[] = {
        "/vendor/etc/selinux/vendor_sepolicy.cil",
        "/vendor/etc/selinux/plat_pub_versioned.cil",
        "/system/etc/selinux/kaidroid/vendor_sepolicy.cil",
        "/system/etc/selinux/kaidroid/plat_pub_versioned.cil",
        "/system/etc/selinux/kaidroid/29.0.compat.cil",
    };
    for (int i = 0; i < 5; ++i) {
        std::ifstream stream(argv[i+1], std::ios::binary);
        if (!stream) return 3;
        files[paths[i]] = std::string(std::istreambuf_iterator<char>(stream), {});
    }
    if (!KaiDroidEngineeringPolicyMatches()) return 4;
    for (const auto* path : paths) {
        const auto original = files[path];
        files[path].push_back('!');
        if (KaiDroidEngineeringPolicyMatches()) return 5;
        files.erase(path);
        if (KaiDroidEngineeringPolicyMatches()) return 6;
        files[path] = original;
    }
    if (!KaiDroidEngineeringPolicyMatches()) return 7;
    return 0;
}
''')
    binary = args.output / 'guard_test'
    command = ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
               '-I' + str(args.output.resolve()),
               '-I' + str(root / 'device/nokia/n139dl/init'),
               str(args.output / 'guard_test.cpp'), '-lcrypto', '-o', str(binary)]
    subprocess.run(command, check=True)
    result = subprocess.run([str(binary.resolve())] + [str(p.resolve()) for p in fixtures],
                            capture_output=True)
    (args.output / 'stderr.txt').write_bytes(result.stderr)
    (args.output / 'result.json').write_text(json.dumps({
        'compile_argv': command, 'exit_code': result.returncode,
        'cases': 'Exact fixture accepted; each of five inputs rejected when changed or absent; restored set accepted.',
        'limitations': 'Host OpenSSL and mocked Android file/log APIs; no Android linkage or device boot.',
    }, indent=2) + '\n')
    print('Guard test exit:', result.returncode)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()

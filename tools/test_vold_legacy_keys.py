"""Exercise pinned KeyStorage upgrade control flow with mocked file/Keymaster IO."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    key_source = (args.source/'KeyStorage.cpp').read_bytes().replace(b'\r\n', b'\n')
    assert hashlib.sha256(key_source).hexdigest() == '3c0030fc75bc6a948852d1ebb534ebf295b4debf2d7dacf8f19dccb63dab3a8e'
    key_source = key_source.decode()
    start = key_source.index('static KeymasterOperation begin(')
    end = key_source.index('static bool encryptWithKeymasterKey(', start)
    function = key_source[start:end]
    prepared = (args.prepared/'FsCrypt.cpp').read_text()
    start = prepared.index('#if defined(KAIDROID_ENG_PRESERVE_LEGACY_KEYS)')
    end = prepared.index('#endif', start)+len('#endif')
    declaration = prepared[start:end]
    calls = re.findall(r'\bretrieveKey\(([^;]*?)\)', prepared)
    assert len(calls) == 4 and all(c.endswith(', kKaiDroidKeepOriginalUserKeys') for c in calls)
    bp = (args.prepared/'Android.bp').read_text()
    assert bp.count('"-DKAIDROID_ENG_PRESERVE_LEGACY_KEYS=1"') == 1
    assert 'eng: {\n            cflags: ["-DKAIDROID_ENG_PRESERVE_LEGACY_KEYS=1"]' in bp
    prefix = r'''
#include <string>
#include <iostream>
#include <cassert>
#define LOG(x) std::cerr
#define PLOG(x) std::cerr
namespace km {
enum class KeyPurpose { DECRYPT };
enum class ErrorCode { OK, KEY_REQUIRES_UPGRADE, OTHER };
struct AuthorizationSet { int begin() const {return 0;} int end() const {return 0;} void append(int, int) {} };
struct HardwareAuthToken {};
}
struct KeymasterOperation {
  km::ErrorCode code = km::ErrorCode::OTHER;
  explicit operator bool() const { return code == km::ErrorCode::OK; }
  km::ErrorCode errorCode() const { return code; }
};
static int upgrades, writes, renames, deletions;
static bool failure, upgrade_failure;
struct Keymaster {
  KeymasterOperation begin(km::KeyPurpose, const std::string& key,
      const km::AuthorizationSet&, const km::HardwareAuthToken&, km::AuthorizationSet*) {
    return {failure ? km::ErrorCode::OTHER : key == "old" ? km::ErrorCode::KEY_REQUIRES_UPGRADE : km::ErrorCode::OK};
  }
  bool upgradeKey(const std::string&, const km::AuthorizationSet&, std::string* output) {
    ++upgrades; *output="new"; return !upgrade_failure;
  }
};
const char* kFn_keymaster_key_blob="keymaster_key_blob";
const char* kFn_keymaster_key_blob_upgraded="keymaster_key_blob_upgraded";
bool readFileToString(const std::string&, std::string* output) { *output="old"; return true; }
bool writeStringToFile(const std::string&, const std::string&) { ++writes; return true; }
int mock_rename(const char*, const char*) { ++renames; return 0; }
#define rename mock_rename
namespace android { namespace vold { bool FsyncDirectory(const std::string&) {return true;} }}
bool kmDeleteKey(Keymaster&, const std::string&) { ++deletions; return true; }
'''
    main = r'''
int main() {
  Keymaster k; km::AuthorizationSet params; km::HardwareAuthToken auth;
  auto result=begin(k,"/data/test",km::KeyPurpose::DECRYPT,params,params,auth,nullptr,kKaiDroidKeepOriginalUserKeys);
  assert(result && upgrades==1 && writes==1);
  assert(renames==(kKaiDroidKeepOriginalUserKeys?0:1));
  assert(deletions==(kKaiDroidKeepOriginalUserKeys?0:1));
  upgrades=writes=renames=deletions=0; failure=true;
  result=begin(k,"/data/test",km::KeyPurpose::DECRYPT,params,params,auth,nullptr,kKaiDroidKeepOriginalUserKeys);
  assert(!result && upgrades==0 && writes==0 && renames==0 && deletions==0);
  failure=false; upgrade_failure=true;
  result=begin(k,"/data/test",km::KeyPurpose::DECRYPT,params,params,auth,nullptr,kKaiDroidKeepOriginalUserKeys);
  assert(!result && upgrades==1 && writes==0 && renames==0 && deletions==0);
  std::cout << (kKaiDroidKeepOriginalUserKeys?"preserved":"upstream");
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    probe = args.output/'probe.cpp'
    probe.write_text(prefix+declaration+'\n'+function+main)
    results = {}
    for name, flags, expected in [('eng', ['-DKAIDROID_ENG_PRESERVE_LEGACY_KEYS=1'], 'preserved'), ('other', [], 'upstream')]:
        binary = args.output/name
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', *flags,
                        str(probe), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True)
        assert result.stdout == expected
        results[name] = result.stdout
    results['scope'] = 'Pinned real upgrade branch with mocked IO; not a TEE or handset test'
    (args.output/'result.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()

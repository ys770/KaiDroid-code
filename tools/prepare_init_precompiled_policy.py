"""Prepare, but do not install, an exact-input policy fast path for engineering init."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', required=True, type=Path)
p.add_argument('--bundle', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
data = a.source.read_bytes()
assert hashlib.sha256(data).hexdigest() == '04c05989b6b5dbd9e3d992fd7944cc9122e6cd95f57be3c794a014afe6a148d9'
manifest = json.loads((a.bundle/'manifest.json').read_text())
assert manifest['policy_version'] == 30 and manifest['vendor_mapping_version'] == '29.0'
assert manifest['neverallow_checks'] is True
assert manifest['policy_sha256'] == '31aae0cd7759cce5ea8728e19f9c682ba81f371ffe547daf051d4a9a5e8992c5'
header = (a.bundle/'kaidroid_precompiled_policy.h').read_text()
for path, digest in manifest['inputs'].items():
    assert header.count('KaiDroidPolicyFileMatches("'+path+'", "'+digest+'")') == 1
assert header.count(manifest['policy_sha256']) == 1
text = data.decode()
anchor = '#include "kaidroid_policy.h"'
assert text.count(anchor) == 1
text = text.replace(anchor, anchor+'\n#include "kaidroid_precompiled_policy.h"')
anchor = '    // Load precompiled policy from vendor image, if a matching policy is found there.'
assert text.count(anchor) == 1
fast_path = '''    // Preserve the engineering vendor mapping gate even when compilation is skipped.
    std::string kaidroid_mapping_version;
    if (!GetVendorMappingVersion(&kaidroid_mapping_version) ||
        kaidroid_mapping_version != "29.0") {
        LOG(ERROR) << "Unsupported KaiDroid vendor policy version";
        return false;
    }
    // The existing engineering identity/ODM gates above remain mandatory.
    // A debug ramdisk or any changed/missing input uses the original compiler path.
    if (!use_userdebug_policy && KaiDroidPrecompiledPolicyMatches(SEPOLICY_VERSION)) {
        constexpr const char* candidate =
                "/system/etc/selinux/kaidroid/precompiled_sepolicy";
        unique_fd fd(open(candidate, O_RDONLY | O_CLOEXEC | O_BINARY));
        if (fd != -1) {
            if (selinux_android_load_policy_from_fd(fd, candidate) < 0) {
                LOG(ERROR) << "Failed to load matched KaiDroid precompiled policy";
                return false;
            }
            LOG(INFO) << "Loaded input-matched KaiDroid precompiled policy";
            return true;
        }
    }

'''
text = text.replace(anchor, fast_path+anchor)
# No alteration to compiler arguments, identity gates or existing fallback body.
assert text.replace(fast_path, '').replace('\n#include "kaidroid_precompiled_policy.h"','') == data.decode()
a.output.mkdir(parents=True, exist_ok=False)
(a.output/'selinux.cpp').write_text(text)
shutil.copyfile(a.bundle/'kaidroid_precompiled_policy.h', a.output/'kaidroid_precompiled_policy.h')
report = {'source_sha256':hashlib.sha256(data).hexdigest(),
          'output_sha256':hashlib.sha256((a.output/'selinux.cpp').read_bytes()).hexdigest(),
          'compiled':False, 'installed':False,
          'fallback':'Existing compiler for missing/mismatched bundle or debug ramdisk; failed matched-policy load remains fatal.'}
(a.output/'preparation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

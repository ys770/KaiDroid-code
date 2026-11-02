"""Compile exact staged init policy inputs; emit a hash-bound fast-path candidate.

Does not modify the AOSP tree, install policy or alter init. Integration must keep
the existing vendor/ODM/version checks and use runtime compilation on mismatch.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-root', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
system = root/'engineering-hall-stage-31/compact-system'
assert sha(system/'build.prop') == '58f9806811838c64cbd47bfe784a6bc9e317c0b1ba546b6100182e9feab4720e'
# Match compile_args ordering in the installed adapted AOSP init.
specs = [
    ('/system/etc/selinux/plat_sepolicy.cil', 'etc/selinux/plat_sepolicy.cil', True),
    ('/system/etc/selinux/mapping/29.0.cil', 'etc/selinux/mapping/29.0.cil', True),
    ('/system/etc/selinux/kaidroid/29.0.compat.cil', 'etc/selinux/kaidroid/29.0.compat.cil', True),
    ('/system_ext/etc/selinux/system_ext_sepolicy.cil', 'system_ext/etc/selinux/system_ext_sepolicy.cil', False),
    ('/system_ext/etc/selinux/mapping/29.0.cil', 'system_ext/etc/selinux/mapping/29.0.cil', False),
    ('/product/etc/selinux/product_sepolicy.cil', 'product/etc/selinux/product_sepolicy.cil', False),
    ('/product/etc/selinux/mapping/29.0.cil', 'product/etc/selinux/mapping/29.0.cil', False),
    ('/system/etc/selinux/kaidroid/plat_pub_versioned.cil', 'etc/selinux/kaidroid/plat_pub_versioned.cil', True),
    ('/system/etc/selinux/kaidroid/vendor_sepolicy.cil', 'etc/selinux/kaidroid/vendor_sepolicy.cil', True),
]
inputs, absent = [], []
for runtime, relative, required in specs:
    path = system/relative
    if not path.exists():
        assert not required, runtime
        absent.append(runtime)
    else:
        assert path.is_file(), runtime
        inputs.append((runtime, path, sha(path)))
compiler = root/'out-eng-02/host/linux-x86/bin/secilc'
a.output.mkdir(parents=True, exist_ok=False)
policy = a.output/'precompiled_sepolicy'
command = [str(compiler), str(inputs[0][1]), '-m', '-M', 'true', '-G', '-c', '30',
           *[str(x[1]) for x in inputs[1:]], '-o', str(policy), '-f', str(a.output/'file_contexts')]
r = subprocess.run(command, capture_output=True)
(a.output/'stdout.txt').write_bytes(r.stdout)
(a.output/'stderr.txt').write_bytes(r.stderr)
r.check_returncode()
manifest = dict(policy_version=30, vendor_mapping_version='29.0', neverallow_checks=True,
                inputs={x[0]:x[2] for x in inputs}, absent=absent,
                policy_sha256=sha(policy), compiler_sha256=sha(compiler),
                compiler_arguments=command, installed=False, init_integrated=False)
(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
lines = ['// Generated from exact staged inputs; candidate only, not integrated.',
         '#pragma once', '#include <cerrno>', '#include <unistd.h>',
         '// Include after kaidroid_policy.h. Caller must retain vendor/ODM/version gates.',
         'static bool KaiDroidPrecompiledPolicyMatches(unsigned policy_version) {',
         '    if (policy_version != 30) return false;']
for runtime, _, digest in inputs:
    lines.append('    if (!KaiDroidPolicyFileMatches("'+runtime+'", "'+digest+'")) return false;')
for runtime in absent:
    lines.append('    errno = 0;')
    lines.append('    if (access("'+runtime+'", F_OK) == 0 || errno != ENOENT) return false;')
lines += ['    return KaiDroidPolicyFileMatches("/system/etc/selinux/kaidroid/precompiled_sepolicy",',
          '        "'+manifest['policy_sha256']+'");', '}']
(a.output/'kaidroid_precompiled_policy.h').write_text('\n'.join(lines)+'\n')
print(json.dumps(manifest))

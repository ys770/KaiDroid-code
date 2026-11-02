"""Compile and execute the generated guard with controlled filesystem outcomes."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--bundle', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
m = json.loads((a.bundle/'manifest.json').read_text())
a.output.mkdir(parents=True, exist_ok=False)
shutil.copyfile(a.bundle/'kaidroid_precompiled_policy.h', a.output/'guard.h')
pairs = dict(m['inputs'])
pairs['/system/etc/selinux/kaidroid/precompiled_sepolicy'] = m['policy_sha256']
entries = ',\n'.join('{'+json.dumps(k)+','+json.dumps(v)+'}' for k,v in pairs.items())
absent = ','.join(json.dumps(k) for k in m['absent'])
source = '''#include <unistd.h>
#include <cerrno>
#include <cassert>
#include <map>
#include <string>
#include <vector>
#include <iostream>
static std::map<std::string,std::string> files = {ENTRIES};
static std::map<std::string,int> presence;
static bool KaiDroidPolicyFileMatches(const char* path, const char* digest) {
    auto i=files.find(path); return i!=files.end() && i->second==digest;
}
static int TestAccess(const char* path, int) {
    int e=presence.count(path)?presence[path]:ENOENT;
    if (!e) return 0;
    errno=e; return -1;
}
#define access TestAccess
#include "guard.h"
#undef access
int main() {
    int checks=0;
    auto expect=[&](bool wanted, unsigned version=30) {
        assert(KaiDroidPrecompiledPolicyMatches(version)==wanted); ++checks;
    };
    expect(true); expect(false,29); expect(false,31);
    auto original=files;
    for(const auto& row:original) {
        files[row.first]="wrong"; expect(false);
        files.erase(row.first); expect(false);
        files=original; expect(true);
    }
    for(const std::string& path:std::vector<std::string>{ABSENT}) {
        presence[path]=0; expect(false);
        presence[path]=EACCES; expect(false);
        presence[path]=EIO; expect(false);
        presence.erase(path); expect(true);
    }
    std::cout<<checks<<" checks passed\\n";
}
'''.replace('ENTRIES', entries).replace('ABSENT', absent)
(a.output/'test.cpp').write_text(source)
binary = a.output/'guard-test'
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror',str(a.output/'test.cpp'),'-o',str(binary)],check=True)
r = subprocess.run([str(binary.resolve())],capture_output=True,check=True)
(a.output/'stdout.txt').write_bytes(r.stdout)
report={'passed':True,'output':r.stdout.decode().strip(),
        'scope':'Actual generated C++ guard; hash-match/access functions mocked. Init and kernel policy loader not exercised.'}
(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))

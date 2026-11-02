"""Check the generated fatal-reboot default in both compile-time configurations.
This isolates the actual declaration; it does not execute a reboot or prove boot recovery.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = (args.prepared/'reboot_utils.cpp').read_text()
    bp = (args.prepared/'Android.bp').read_text()
    flag = '"-DKAIDROID_ENG_RECOVERY_FALLBACK=1"'
    assert bp.count(flag)==1
    assert bp.index('        eng: {') < bp.index(flag) < bp.index('        uml: {')
    start = source.index('#if defined(KAIDROID_ENG_RECOVERY_FALLBACK)')
    end = source.index('#endif',start)+len('#endif')
    args.output.mkdir(parents=True,exist_ok=False)
    probe = args.output/'probe.cpp'
    probe.write_text('#include <string>\n#include <iostream>\n'+source[start:end]+
                     '\nint main(){std::cout << init_fatal_reboot_target;}\n')
    result = {}
    for name, flags, expected in [('eng',['-DKAIDROID_ENG_RECOVERY_FALLBACK=1'],'recovery'),
                                  ('other',[],'bootloader')]:
        binary = args.output/name
        subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror',*flags,str(probe),'-o',str(binary)],check=True)
        value = subprocess.check_output([str(binary.resolve())]).decode()
        assert value==expected,(name,value)
        result[name]=value
    result['prepared_source_sha256']=hashlib.sha256((args.prepared/'reboot_utils.cpp').read_bytes()).hexdigest()
    result['scope']='Declaration/configuration test only; no runtime failure injection or reboot'
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()

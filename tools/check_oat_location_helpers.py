"""Run extracted ART location helpers on the host; does not load ART or a phone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

SOURCES={
 'art/runtime/gc/space/image_space.cc':'54e4b6efbe65779b8aaa19b8b0dd45cf8b20d1c656a2ccb2192fc46240ed2107',
 'art/libartbase/base/file_utils.cc':'beb29ace281279c0e3c90f6c2acfa988f0add1ac70a7f1daa8f8fdd7308bb7b9',
 'art/runtime/image.h':'024f3b429974b068f967fed85ddbbd08104fe77a56bf60ecb7d378aa01567229'}


def extract(text,signature):
    start=text.index(signature);body=text.index('{',start);depth=1;end=body+1
    # Pinned simple functions have no braces in string literals/comments.
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();texts={}
    for name,expected in SOURCES.items():
        raw=(a.source_root/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Source changed: '+name)
        texts[name]=raw.decode()
    functions={}
    for name,signature in [
        ('art/libartbase/base/file_utils.cc','std::string GetDefaultBootImageLocation(const std::string& android_root)'),
        ('art/libartbase/base/file_utils.cc','static void InsertIsaDirectory('),
        ('art/libartbase/base/file_utils.cc','std::string GetSystemImageFilename('),
        ('art/runtime/gc/space/image_space.cc','std::vector<std::string> ImageSpace::ExpandMultiImageLocations('),
        ('art/runtime/image.h','static std::string GetOatLocationFromImageLocation('),
        ('art/runtime/image.h','static std::string GetLocationFromImageLocation(')]:
        functions[signature]=extract(texts[name],signature)
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep generated outputs inside workspace')
    out.mkdir(parents=True,exist_ok=False)
    prelude=r'''
#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>
#include <type_traits>
#include <vector>
struct Check { explicit Check(bool ok) { assert(ok); } template<class T> Check& operator<<(const T&) { return *this; } };
#define CHECK_NE(a,b) Check((a)!=(b))
#define DCHECK(a) assert(a)
enum class InstructionSet { kArm };
const char* GetInstructionSetString(InstructionSet value) { assert(value==InstructionSet::kArm); return "arm"; }
template<class T> using ArrayRef=std::vector<std::remove_const_t<T>>;
const char* kAndroidArtApexDefaultPath="/apex/com.android.art";
template<class... T> std::string StringPrintf(const char* format,T... args) {
 int n=std::snprintf(nullptr,0,format,args...); assert(n>=0);
 std::vector<char> data(n+1); std::snprintf(data.data(),data.size(),format,args...); return std::string(data.data(),n);
}
class ImageSpace { public: static std::vector<std::string> ExpandMultiImageLocations(ArrayRef<const std::string>,const std::string&,bool); };
'''
    image='class ImageHeader { public:\n'+functions['static std::string GetLocationFromImageLocation(']+'\n'+functions['static std::string GetOatLocationFromImageLocation(']+'\n};\n'
    body='\n'.join(value for key,value in functions.items() if not key.startswith('static std::string Get'))
    tests=r'''
int main() {
 assert(GetDefaultBootImageLocation("/system")=="/apex/com.android.art/javalib/boot.art:/system/framework/boot-framework.art!/system/etc/boot-image.prof");
 std::vector<std::string> bcp={"/system/framework/framework.jar"};
 auto logical=ImageSpace::ExpandMultiImageLocations(bcp,"/system/framework/boot.art",true);
 auto physical=ImageSpace::ExpandMultiImageLocations(bcp,GetSystemImageFilename("/system/framework/boot.art",InstructionSet::kArm),true);
 assert(logical.size()==1 && physical.size()==1);
 assert(logical[0]=="/system/framework/boot-framework.art");
 assert(physical[0]=="/system/framework/arm/boot-framework.art");
 auto logical_oat=ImageHeader::GetOatLocationFromImageLocation(logical[0]);
 auto physical_oat=ImageHeader::GetOatLocationFromImageLocation(physical[0]);
 assert(logical_oat=="/system/framework/boot-framework.oat");
 assert(physical_oat=="/system/framework/arm/boot-framework.oat");
 assert(logical_oat!=physical_oat);
 auto cache=ImageSpace::ExpandMultiImageLocations(bcp,"/data/dalvik-cache/arm/system@framework@boot.art",true);
 assert(cache[0]=="/data/dalvik-cache/arm/system@framework@boot-framework.art");
 std::cout << logical_oat << '\n' << physical_oat << '\n' << cache[0] << '\n';
}
'''
    source=out/'location_helpers.cc';source.write_bytes((prelude+image+body+tests).encode())
    binary=out/'location_helpers'
    def native(path):
        path=path.resolve()
        return '/mnt/'+path.drive[0].lower()+'/'+path.as_posix()[3:] if os.name=='nt' else str(path)
    prefix=['wsl.exe','--exec'] if os.name=='nt' else []
    compile_argv=prefix+['g++','-std=c++17','-Wall','-Wextra','-Werror',native(source),'-o',native(binary)]
    compiled=subprocess.run(compile_argv,capture_output=True,timeout=60)
    (out/'compile.stdout').write_bytes(compiled.stdout);(out/'compile.stderr').write_bytes(compiled.stderr);compiled.check_returncode()
    run=subprocess.run(prefix+[native(binary)],capture_output=True,timeout=10)
    (out/'run.stdout').write_bytes(run.stdout);(out/'run.stderr').write_bytes(run.stderr);run.check_returncode()
    report=dict(source_hashes=SOURCES,extracted_function_hashes={k:hashlib.sha256(v.encode()).hexdigest() for k,v in functions.items()},
        generated_cpp_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),compile_argv=compile_argv,compile_exit=compiled.returncode,
        run_exit=run.returncode,output=run.stdout.decode().splitlines(),
        limits=['Extracted pinned string helpers only, not an ART runtime/image loader or live OatFile inspection.',
                'ArrayRef is modeled with vector, checks assert, ISA-to-string fixed to ARM, printf uses host libc.',
                'Default /system branch is exercised. JIT/custom image-property/cache loading branches require separate evidence.',
                'Logical location does not prove which physical file was loaded. Candidate needs exact owner/header/artifact gates.'])
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()

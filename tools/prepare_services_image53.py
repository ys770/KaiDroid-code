"""Prepare an unbuilt exact53 low-RAM services app-image bypass; preserve OAT fallback."""
import argparse,difflib,hashlib,json
from pathlib import Path
from prepare_oat_rx_image50 import inspect_oat,LIBART
from check_oat_location_helpers import extract
RAW='f587f445ce66e397718110762c7e952fcb19c03feef4b1ae35c7638209c51f56'
SOURCE='9b2d2869e0138fc00810a276a63c653c423d3173f5d3a8ac521dd62ceb15e521'
OAT='bdbb63b7da26018fa9c5e0db7964ecfd27b2fab2ead2d833a715d815b314cf63'
ART='5bf046c4e76b2e4c65107249cc3a423351589b7ebedc512007d881f21fe2abf3'
SIGNATURE='bool OatFileManager::ShouldLoadAppImage('
ANCHOR='''  Runtime* const runtime = Runtime::Current();
  if (kEnableAppImage && (!runtime->IsJavaDebuggable() || source_oat_file->IsDebuggable())) {'''
INSERT='''  Runtime* const runtime = Runtime::Current();
  // Experimental exact-image53 services app-image bypass on low-RAM devices.
  // Keep accepted compiled OAT/DEX and the ordinary LoadDexFiles path intact.
  // A future preopt change must fail closed until its artifacts are reviewed.
  gc::Heap* const heap = runtime->GetHeap();
  if (heap != nullptr && heap->IsLowMemoryMode() && source_oat_file->IsExecutable() &&
      source_oat_file->GetLocation() == "/system/framework/oat/arm/services.odex") {
    const OatHeader& header = source_oat_file->GetOatHeader();
    if (header.IsValid() && header.GetChecksum() == 836049105u &&
        source_oat_file->Size() == 12699918u &&
        header.GetExecutableOffset() == 2895872u) {
      return false;
    }
  }
  if (kEnableAppImage && (!runtime->IsJavaDebuggable() || source_oat_file->IsDebuggable())) {'''

def sha(raw):return hashlib.sha256(raw).hexdigest()

def generate(original):
    if sha(original)!=SOURCE:raise ValueError('Pinned ART manager source required')
    text=original.decode();body=extract(text,SIGNATURE)
    if body.count(ANCHOR)!=1:raise ValueError('App-image gate anchor changed')
    candidate=text.replace(body,body.replace(ANCHOR,INSERT,1),1)
    for old,new in [('#include "gc/scoped_gc_critical_section.h"','#include "gc/heap.h"\n#include "gc/scoped_gc_critical_section.h"'),('#include "oat_file.h"','#include "oat.h"\n#include "oat_file.h"')]:
        if candidate.count(old)!=1:raise ValueError('Include anchor differs')
        candidate=candidate.replace(old,new,1)
    reverted=candidate.replace(extract(candidate,SIGNATURE),body,1).replace('#include "gc/heap.h"\n','',1).replace('#include "oat.h"\n','',1)
    if reverted!=text:raise ValueError('Changes outside helper/includes')
    return candidate.encode()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('image','source','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();identity=(a.image.stat().st_size,a.image.stat().st_mtime_ns)
    with a.image.open('rb') as f:raw_sha=hashlib.file_digest(f,'sha256').hexdigest()
    if identity[0]!=834666496 or raw_sha!=RAW:raise ValueError('Exact accepted53 raw required')
    original=a.source.read_bytes();candidate=generate(original)
    from dissect.extfs import ExtFS
    with a.image.open('rb') as f:
        fs=ExtFS(f)
        if fs.get('/system/build.prop').open().read().splitlines().count(b'ro.kaidroid.image=53')!=1:raise ValueError('Wrong image revision')
        lib=fs.get('/system/apex/com.android.art.release/lib/libart.so').open().read()
        oat=fs.get('/system/framework/oat/arm/services.odex').open().read();art=fs.get('/system/framework/oat/arm/services.art').open().read()
        if (sha(lib),sha(oat),sha(art))!=(LIBART,OAT,ART):raise ValueError('Baseline artifact changed')
        header=inspect_oat(oat)
        if (header['checksum'],header['oat_size'],header['code_offset'])!=(836049105,12699918,2895872):raise ValueError('OAT fingerprint differs')
    if (a.image.stat().st_size,a.image.stat().st_mtime_ns)!=identity:raise ValueError('Image changed during read')
    text=original.decode();open_function=extract(text,'std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat(')
    if not open_function.index('AcceptOatFile(')<open_function.index('ShouldLoadAppImage(')<open_function.index('if (!added_image_space)')<open_function.index('oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location)'):raise ValueError('Accepted-OAT fallback ordering differs')
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep output in workspace')
    out.mkdir(parents=True,exist_ok=False)
    patch=''.join(difflib.unified_diff(text.splitlines(True),candidate.decode().splitlines(True),fromfile='a/art/runtime/oat_file_manager.cc',tofile='b/art/runtime/oat_file_manager.cc')).encode()
    for name,raw in [('original.cc',original),('candidate.cc',candidate),('candidate.patch',patch)]:out.joinpath(name).write_bytes(raw)
    result=dict(image=53,raw_sha256=RAW,baseline_libart_sha256=LIBART,services_oat_sha256=OAT,services_image_sha256=ART,services_image_file_bytes=len(art),services_oat_fingerprint={k:header[k] for k in ('checksum','oat_size','code_offset')},
        original_sha256=SOURCE,candidate_sha256=sha(candidate),patch_sha256=sha(patch),unchanged_open_dex_function_sha256=sha(open_function.encode()),scope=['one existing ShouldLoadAppImage helper','explicit heap/OAT header includes'],built_target=False,installed=False,
        limits=['Only exact53 low-RAM services artifact bypasses preinitialized app image; existing accepted OAT and ordinary LoadDexFiles source remains unchanged.','CRC/size/offset is an experiment filter, not authentication; artifact hashes bind this preparation.','Private ART-image mapping labels show footprint, not unused objects or realizable savings.','Fallback can recreate all objects and cost more RAM/startup latency; no runtime or functionality acceptance.','No framework/UI source, existing50 RX candidate, kernel/bootchain, image or device is modified.','Future accepted preopt requires exact rebind before any build; no build requested.'])
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()

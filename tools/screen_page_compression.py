"""Windows-local WSL compression screen; NOT a kernel-zram or phone benchmark."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import time
import zipfile
from pathlib import Path

PAGE=4096


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    lzo=C.CDLL('liblzo2.so.2')
    zstd=C.CDLL('libzstd.so.1')
    lzo.lzo1x_1_compress.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.POINTER(C.c_size_t),C.c_void_p]
    lzo.lzo1x_decompress_safe.argtypes=lzo.lzo1x_1_compress.argtypes
    zstd.ZSTD_compress.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_int]
    zstd.ZSTD_compress.restype=C.c_size_t
    zstd.ZSTD_decompress.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]
    zstd.ZSTD_decompress.restype=C.c_size_t
    zstd.ZSTD_isError.argtypes=[C.c_size_t]
    zstd.ZSTD_isError.restype=C.c_uint
    lzo.lzo_version_string.restype=C.c_char_p
    zstd.ZSTD_versionString.restype=C.c_char_p
    rng=random.Random(13938)
    pointer_pages=[]
    for _ in range(256):
        words=[0 if rng.randrange(4)==0 else 0x10000000+16*rng.randrange(8192) for j in range(PAGE//4)]
        pointer_pages.append(struct.pack('<1024I',*words))
    random_pages=[rng.randbytes(PAGE) for _ in range(256)]
    dex_inputs=[]
    all_dex_pages=[]
    with zipfile.ZipFile(a.apk) as z:
        for name in sorted(n for n in z.namelist() if n.startswith('classes') and n.endswith('.dex')):
            dex=z.read(name)
            dex_inputs.append(dict(name=name,bytes=len(dex),sha256=hashlib.sha256(dex).hexdigest()))
            all_dex_pages.extend(dex[i:i+PAGE].ljust(PAGE,b'\0') for i in range(0,len(dex),PAGE))
    if not all_dex_pages: raise ValueError('No DEX corpus')
    count=min(256,len(all_dex_pages))
    selected_indices=[i*(len(all_dex_pages)-1)//max(1,count-1) for i in range(count)]
    dex_pages=[all_dex_pages[i] for i in selected_indices]
    corpora={'synthetic_pointer_words':pointer_pages,'seeded_incompressible':random_pages,'donor_dex_file_pages':dex_pages}
    report=dict(lzo_version=lzo.lzo_version_string().decode(),zstd_version=zstd.ZSTD_versionString().decode(),
                apk_sha256=hashlib.sha256(a.apk.read_bytes()).hexdigest(),page_size=PAGE,corpora={},
                dex_inputs=dex_inputs,dex_page_indices=selected_indices,
                limits=['Userland x86-64 libraries and versions, not exact phone kernel implementations or ARM timings.',
                        'Synthetic pointers and file-backed DEX are not sampled anonymous Android pages.',
                        'Compressed bytes exclude zsmalloc rounding/metadata and compressor workspace.',
                        'zstd one-shot calls include context setup; sustained kernel workspace reuse can differ.',
                        'Same-word pages are excluded because zram can represent them without compressed payload.',
                        'No zram configuration changed and no phone memory-saving claim is established.'])
    work=C.create_string_buffer(262144)
    out=C.create_string_buffer(PAGE*2)
    restored=C.create_string_buffer(PAGE)
    for name,pages in corpora.items():
        eligible=[page for page in pages if page!=page[:4]*(PAGE//4)]
        row=dict(pages=len(pages),same_word_pages=len(pages)-len(eligible),
                 corpus_sha256=hashlib.sha256(b''.join(pages)).hexdigest(),algorithms={})
        for algorithm,level in [('lzo1x_1',0),('zstd1',1),('zstd3',3)]:
            sizes=[]; enc_ns=0; dec_ns=0
            for page in eligible:
                src=C.create_string_buffer(page)
                length=C.c_size_t(len(out))
                started=time.perf_counter_ns()
                if level:
                    size=zstd.ZSTD_compress(out,len(out),src,PAGE,level)
                    if zstd.ZSTD_isError(size): raise RuntimeError('zstd compression failed')
                else:
                    status=lzo.lzo1x_1_compress(src,PAGE,out,C.byref(length),work)
                    if status: raise RuntimeError('lzo compression failed')
                    size=length.value
                enc_ns+=time.perf_counter_ns()-started
                sizes.append(size)
                started=time.perf_counter_ns()
                if level:
                    restored_size=zstd.ZSTD_decompress(restored,PAGE,out,size)
                    if zstd.ZSTD_isError(restored_size): raise RuntimeError('zstd decompression failed')
                else:
                    restored_len=C.c_size_t(PAGE)
                    status=lzo.lzo1x_decompress_safe(out,size,restored,C.byref(restored_len),None)
                    if status: raise RuntimeError('lzo decompression failed')
                    restored_size=restored_len.value
                dec_ns+=time.perf_counter_ns()-started
                if restored_size!=PAGE or restored.raw!=page: raise RuntimeError('Roundtrip mismatch')
            row['algorithms'][algorithm]=dict(compressed_bytes=sum(sizes),uncompressed_bytes=len(eligible)*PAGE,
                pages_not_smaller=sum(size>=PAGE for size in sizes),
                compression_ms=enc_ns/1e6,decompression_ms=dec_ns/1e6,roundtrips_verified=len(sizes))
        report['corpora'][name]=row
    with a.output.open('x') as f: f.write(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()

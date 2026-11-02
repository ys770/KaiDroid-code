"""Hash-bound offline Hexagon v5 listener analysis using existing local libLLVM."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct

PINS = {'adsp.b09': '88e25b2c61ade39b1e8f06ebd6baf95c3e15dfe992e687d5a6140e1d7b663eee',
        'adsp.mdt': '6d08f4bf4bbaf2c7046dca3af4113f5553186bd73d08a1754e8f64850af51995',
        'adsp.b04': '0a0d955407203a64537886938df847ada8d4c18a7d64991fdbe4c14c6e0641b0'}
SPANS = {'registration': (0xf044be20, 0xf044be48),
         'skeleton': (0xf044cb48, 0xf044cb88),
         'method0': (0xf044ba04, 0xf044ba30),
         'registration_guard': (0xf044dcf4, 0xf044dd24),
         'state_setter': (0xf044cef0, 0xf044cf14),
         'context_lookup_locked': (0xf044ddfc, 0xf044de20),
         'context_outer_list': (0xf044cf24, 0xf044cfa8),
         'context_inner_list': (0xf044cfa8, 0xf044d014),
         'atomic_exchange': (0xf05fd598, 0xf05fd5c4),
         'atomic_compare_exchange': (0xf05fd604, 0xf05fd628),
         'state_notify_trap': (0xf047f830, 0xf047f838),
         'context_identity': (0xf00157a4, 0xf00157b4),
         'slot_clear_condition': (0xf044ccc8, 0xf044cd30),
         'slot_wait': (0xf044dd24, 0xf044dd50),
         'state_initialize': (0xf044e0a8, 0xf044e11c),
         'state_initialize_wrapper': (0xf044dfd4, 0xf044dfe0),
         'sensor_pd_launch': (0xf04623f0, 0xf0462444)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--llvm', type=Path, default=Path('/lib/x86_64-linux-gnu/libLLVM.so.20.1'))
    args = parser.parse_args()
    raw = {n: (args.input / n).read_bytes() for n in PINS}
    assert all(hashlib.sha256(raw[n]).hexdigest() == pin for n, pin in PINS.items())
    header = raw['adsp.mdt']
    assert header[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', header, 18)[0] == 164
    assert struct.unpack_from('<I', header, 36)[0] == 5
    phoff = struct.unpack_from('<I', header, 28)[0]
    phsize = struct.unpack_from('<H', header, 42)[0]
    segment = struct.unpack_from('<8I', header, phoff + 4 * phsize)
    base = segment[2]
    data = raw['adsp.b04']
    assert base == 0xf015f000 and segment[4] == len(data)
    name_offset = 0xf06ff290 - base
    assert data[name_offset:name_offset+22] == b'adsp_default_listener\0'
    library = ctypes.CDLL(str(args.llvm))
    for suffix in ('TargetInfo', 'Target', 'TargetMC', 'Disassembler'):
        getattr(library, 'LLVMInitializeHexagon' + suffix)()
    library.LLVMCreateDisasmCPU.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    library.LLVMCreateDisasmCPU.restype = ctypes.c_void_p
    library.LLVMDisasmInstruction.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
    library.LLVMDisasmInstruction.restype = ctypes.c_size_t
    library.LLVMDisasmDispose.argtypes = [ctypes.c_void_p]
    decoder = library.LLVMCreateDisasmCPU(b'hexagon', b'hexagonv5', None, 0, None, None)
    assert decoder
    text = ctypes.create_string_buffer(4096)
    result = {'input_hashes': PINS, 'cpu': 'hexagonv5', 'elf_flags': 5,
              'llvm_sha256': hashlib.sha256(args.llvm.read_bytes()).hexdigest(),
              'listener_string_address': '0xf06ff290', 'spans': {},
              'runtime_guard_value_observed': False, 'remote_cause_proven': False}
    try:
        for name, (start, end) in SPANS.items():
            selected = 9 if name == 'context_identity' else 4
            selected_header = struct.unpack_from('<8I', header, phoff + selected * phsize)
            selected_data = raw[f'adsp.b{selected:02d}']
            selected_base = selected_header[2]
            assert selected_header[4] == len(selected_data)
            assert selected_base <= start < end <= selected_base + len(selected_data)
            selected_buffer = ctypes.create_string_buffer(selected_data)
            position = start
            rows = []
            while position < end:
                offset = position - selected_base
                count = library.LLVMDisasmInstruction(decoder, ctypes.byref(selected_buffer, offset), len(selected_data)-offset, position, text, len(text))
                assert count and position + count <= end, (name, hex(position), count)
                rows.append({'address': hex(position), 'bytes': selected_data[offset:offset+count].hex(), 'instruction': text.value.decode().strip()})
                position += count
            result['spans'][name] = rows
    finally:
        library.LLVMDisasmDispose(decoder)
    args.output.mkdir(exist_ok=False)
    (args.output / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'spans': len(SPANS), 'all_packets_decoded': True, 'remote_cause_proven': False}))

if __name__ == '__main__':
    main()

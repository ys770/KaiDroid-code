"""Prepare an offline, hash-pinned AEC message-lifetime candidate; never install it.

Requires keystone-engine. Preserve the original library; output must not exist.
The saved flag replaces r4 only on a path where r4 is dead until epilogue restore.
"""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = '6e28e04df7b0af0bbef3f226e92c62064be21b072d2c584cb95c1654d5634847'
ADDRESS = 0x4A4D8


def candidate(original):
    from elftools.elf.elffile import ELFFile
    from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
    import io
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unreviewed camera library')
    elf = ELFFile(io.BytesIO(original))
    segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                   and s['p_vaddr'] <= ADDRESS < s['p_vaddr'] + s['p_filesz'])
    offset = segment['p_offset'] + ADDRESS - segment['p_vaddr']
    assembler = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    before = bytes(assembler.asm(
        'mov r1, r4; blx 0x80d90; mov r6, r0; ldr r0, [r4, #8]; cmp r0, #1',
        addr=ADDRESS)[0])
    after = bytes(assembler.asm(
        'mov r1, r4; ldr r4, [r4, #8]; blx 0x80d90; mov r6, r0; cmp r4, #1',
        addr=ADDRESS)[0])
    if len(before) != 12 or len(after) != 12 or original[offset:offset+12] != before:
        raise ValueError('Unexpected AEC instruction window')
    return original[:offset] + after + original[offset+12:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    patched = candidate(args.source.read_bytes())
    with args.output.open('xb') as stream:
        stream.write(patched)
    print('Candidate SHA256:', hashlib.sha256(patched).hexdigest())


if __name__ == '__main__':
    main()

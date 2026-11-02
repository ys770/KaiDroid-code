"""Prepare a pinned, offline six-to-three picture-buffer experiment; never install."""
import argparse
import hashlib
import io
from pathlib import Path
from elftools.elf.elffile import ELFFile

SOURCE_SHA256 = '6f43c78aef16a30e3befe482e2a478155eba552623aa82fcb443cf995890b6ca'
ADDRESS = 0x857FE


def candidate(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unreviewed camera HAL')
    elf = ELFFile(io.BytesIO(original))
    segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                   and s['p_vaddr'] <= ADDRESS < s['p_vaddr'] + s['p_filesz'])
    offset = segment['p_offset'] + ADDRESS - segment['p_vaddr']
    # IT EQ and MOV r4,#6: only the mode-word==1 arm changes.
    if original[offset-2:offset+2] != bytes.fromhex('08bf0624'):
        raise ValueError('Unexpected conditional picture-buffer count')
    return original[:offset] + bytes.fromhex('0324') + original[offset+2:]


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

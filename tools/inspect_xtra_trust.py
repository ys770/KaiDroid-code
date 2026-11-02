"""Inspect the captured N139DL XTRA trust stores offline; never contact a device.

Requires pyelftools, capstone and cryptography. Output is metadata/disassembly,
not extracted vendor payloads. Addresses apply only to the pinned binary.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from cryptography import x509
from elftools.elf.elffile import ELFFile

SHA256 = '3167ac591c0372c3e72b3939001ca25350cf90d5c37b18cb4ec567dfbcb4c524'


def inspect(binary):
    blob = binary.read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError('Unreviewed XTRA binary; address map is not applicable')
    elf = ELFFile(io.BytesIO(blob))
    sections = [(s['sh_addr'], s.data()) for s in elf.iter_sections()
                if s['sh_type'] != 'SHT_NOBITS' and s['sh_flags'] & 2]

    def raw(address, count):
        for start, data in sections:
            if start <= address and address + count <= start + len(data):
                return data[address-start:address-start+count]
        raise ValueError('Address outside allocated data')

    def relative(load, displacement, add):
        literal = ((load + 4) & ~3) + displacement
        return (int.from_bytes(raw(literal, 4), 'little') + add + 4) & 0xffffffff

    def text(address):
        return bytes(raw(address+i, 1)[0] for i in range(256)).split(b'\0')[0].decode()

    config_key = text(relative(0x16ee6, 0xdf4, 0x16ef6))
    default_path = text(relative(0x16e22, 0xe98, 0x16e2e))
    assert config_key == 'XTRA_CA_PATH'
    assert default_path == '/vendor/etc/security/cacerts'
    vector_reader = relative(0x1e74e, 0x2dc, 0x1e750)
    vector_writer = relative(0x1fb16, 0x80, 0x1fb1c)
    assert vector_reader == vector_writer
    roots = []
    for load, displacement, add, size in [
        (0x1fa64, 0x118, 0x1fa72, 0x43a),
        (0x1fa82, 0x100, 0x1fa90, 0x4d7),
        (0x1faa0, 0xe4, 0x1faae, 0x363),
        (0x1fabe, 0xcc, 0x1facc, 0x404),
        (0x1fadc, 0xb0, 0x1faea, 0x564),
        (0x1fafa, 0x98, 0x1fb08, 0x5dc),
    ]:
        address = relative(load, displacement, add)
        der = raw(address, size)
        cert = x509.load_der_x509_certificate(der)
        roots.append(dict(address=hex(address), size=size,
                          sha256=hashlib.sha256(der).hexdigest(),
                          subject=cert.subject.rfc4514_string(),
                          not_before=cert.not_valid_before_utc.isoformat(),
                          not_after=cert.not_valid_after_utc.isoformat()))
    # This ELF's ARM PLT has a 32-byte resolver followed by 16-byte entries.
    relocations = elf.get_section_by_name('.rel.plt')
    symbols = elf.get_section(relocations['sh_link'])
    plt = elf.get_section_by_name('.plt')['sh_addr']
    imports = {plt + 32 + i*16: symbols.get_symbol(r['r_info_sym']).name
               for i, r in enumerate(relocations.iter_relocations())}
    assert imports[0x22ad0] == 'SSL_CTX_load_verify_locations'
    assert imports[0x22a00] == 'd2i_X509_fp'
    assert imports[0x22a50] == 'X509_verify_cert'
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    ranges = [(0xe0d2, 0xe0da), (0x16ee6, 0x16f00),
              (0x16f5c, 0x16f66), (0x171ba, 0x171c4),
              (0x1128a, 0x112a6), (0x1ec8a, 0x1ecac),
              (0x1e978, 0x1e9b6), (0x1eab8, 0x1eaee),
              (0x1edce, 0x1edf6)]
    instructions = []
    for start, end in ranges:
        for ins in md.disasm(raw(start, end-start), start):
            symbol = ''
            if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                symbol = imports.get(int(ins.op_str[1:], 16), '')
            instructions.append(dict(address=hex(ins.address), mnemonic=ins.mnemonic,
                                     operands=ins.op_str, imported_symbol=symbol))
    return dict(binary_sha256=SHA256, config_key=config_key,
                compiled_default_path=default_path, fallback_vector=hex(vector_reader),
                embedded_roots=roots, instruction_evidence=instructions,
                scope='Offline structure only; no observed TLS failure, assistance download, or positioning fix.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.binary)
    with args.out.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(dict(binary_sha256=SHA256, embedded_roots=len(result['embedded_roots']),
                          fallback_vector=result['fallback_vector'])))


if __name__ == '__main__':
    main()

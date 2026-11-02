"""Hash-bound offline ARM disassembly of the engineering kernel UART receive path."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zlib
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

KERNEL_SHA = '5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561'
NAMES = ('n_tty_receive_buf_common', 'n_tty_receive_char_flagged',
         'tty_insert_flip_string_fixed_flag', 'tty_ldisc_receive_buf',
         '__receive_buf', 'msm_hs_set_termios', '__tty_insert_flip_char',
         'msm_hs_isr', 'msm_serial_hs_rx_work', 'flip_insert_work',
         'uart_write', 'n_tty_write')


def inspect(kernel, symbols, output, names=NAMES):
    data = kernel.read_bytes()
    if hashlib.sha256(data).hexdigest() != KERNEL_SHA:
        raise ValueError('Unexpected engineering kernel')
    image = None
    for match in re.finditer(b'\x1f\x8b\x08', data):
        try:
            dec = zlib.decompressobj(31)
            candidate = dec.decompress(data[match.start():], 128 * 1024 * 1024)
            if dec.eof and b'Linux version 4.9.268+-ab00.2211.12.01' in candidate:
                image = candidate
                break
        except zlib.error:
            continue
    if image is None:
        raise ValueError('Expected kernel image/banner absent')
    syms = [(int(a, 16), kind, name) for a, kind, name in
            re.findall(r'^([0-9a-f]{8}) ([A-Za-z]) (\S+)$', symbols.read_text(), re.M)]
    by_name = {name: addr for addr, _, name in syms}
    missing = sorted(set(names) - by_name.keys())
    if missing:
        raise ValueError('Requested symbols absent: ' + ', '.join(missing))
    base = by_name['_text']
    banner_offset = by_name['linux_banner'] - base
    if base != 0xc0008000 or not image[banner_offset:].startswith(b'Linux version 4.9.268+-ab00.2211.12.01'):
        raise ValueError('Live symbol-to-file address mapping not established')
    output.mkdir(parents=True, exist_ok=False)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    report = dict(kernel_sha256=KERNEL_SHA, decompressed_sha256=hashlib.sha256(image).hexdigest(),
                  symbols_sha256=hashlib.sha256(symbols.read_bytes()).hexdigest(),
                  address_base=hex(base), banner_mapping_checked=True, functions={})
    for name in names:
        start = by_name[name]
        end = min(addr for addr, kind, _ in syms if addr > start and kind in 'tT')
        body = image[start-base:end-base]
        instructions = list(decoder.disasm(body, start))
        text = '\n'.join(f'{i.address:08x}: {i.bytes.hex():8s} {i.mnemonic} {i.op_str}' for i in instructions)
        (output / (name + '.asm')).write_text(text + '\n')
        report['functions'][name] = dict(start=hex(start), end=hex(end),
             bytes=len(body), decoded_bytes=sum(i.size for i in instructions),
             sha256=hashlib.sha256(body).hexdigest())
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('kernel', 'symbols', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--functions', nargs='+', default=NAMES,
                   help='Exact captured kernel symbols; defaults to UART paths')
    a = p.parse_args()
    inspect(a.kernel, a.symbols, a.output, a.functions)

"""Decode voltage attribute bindings from the exact engineering kernel, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    raw = a.kernel.read_bytes()
    kh = hashlib.sha256(raw).hexdigest()
    if kh != '5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561':
        raise ValueError('Wrong kernel')
    image = None
    dh = 'd529cca2e36a913c377bf8b06ce6d6ff490d55dc7139b21c1ae5348aefad7565'
    for match in re.finditer(b'\x1f\x8b\x08', raw):
        try:
            candidate = zlib.decompress(raw[match.start():], 31)
            if hashlib.sha256(candidate).hexdigest() == dh:
                image = candidate
                break
        except zlib.error:
            pass
    if image is None:
        raise ValueError('Wrong decompressed image')
    base = 0xc0008000
    def word(address):
        return struct.unpack_from('<I', image, address-base)[0]
    def string(address):
        return image[address-base:].split(b'\0', 1)[0].decode()
    rows = []
    for i in (8, 10, 11):
        rows.append(dict(index=i, name=string(word(0xc14b3bc8+i*16)),
                         getter_branch=hex(word(0xc095bf64+i*4))))
    prop = string(0xc11cfbac)
    assert prop == 'qcom,vinmin-mv'
    assert [r['name'] for r in rows] == ['voltage_max', 'voltage_max_design', 'voltage_min_design']
    result = dict(kernel_sha256=kh, decompressed_sha256=dh,
                  attributes=rows, probe_property_at_c0957bc0=prop,
                  getter_minimum='c095c0fc loads chip+0x34; c095c100-c095c104 multiplies by1000',
                  probe_binding='c0957bb0 sets output pointer chip+0x34; c0957bc8 reads qcom,vinmin-mv into it',
                  input_voltage_use='c0957d28 loads chip+0x34; c0957d30 calls qpnp_lbc_vinmin_set',
                  conclusion='voltage_min_design exposes the charger input minimum, not the battery discharge cutoff',
                  scope='Offline exact-kernel mapping; no charger controls written or physical charging validation')
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

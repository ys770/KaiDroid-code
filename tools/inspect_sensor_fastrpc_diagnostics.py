"""Extract exact engineering-kernel FastRPC diagnostic strings offline."""
import argparse
import hashlib
import json
import re
import zlib
from pathlib import Path

KERNEL = '5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561'
IMAGE = 'd529cca2e36a913c377bf8b06ce6d6ff490d55dc7139b21c1ae5348aefad7565'
STRINGS = {
    0xc113deeb: '\x013adsprpc: ERROR: %s: user application %s trying to send a kernel RPC message to channel %d',
    0xc113df47: 'fastrpc_internal_invoke',
    0xc113df5f: '\x013adsprpc: out of context memory\n',
    0xc113ec00: '\x013adsprpc: invalid response or context\n',
}

def inspect(kernel):
    data = kernel.read_bytes()
    if hashlib.sha256(data).hexdigest() != KERNEL:
        raise ValueError('Unexpected kernel')
    image = None
    for match in re.finditer(b'\x1f\x8b\x08', data):
        try:
            dec = zlib.decompressobj(31)
            candidate = dec.decompress(data[match.start():], 128 * 1024 * 1024)
        except zlib.error:
            continue
        if dec.eof and hashlib.sha256(candidate).hexdigest() == IMAGE:
            image = candidate
            break
    if image is None:
        raise ValueError('Expected decompressed image absent')
    values = {}
    for address, expected in STRINGS.items():
        offset = address - 0xc0008000
        value = image[offset:image.index(b'\0', offset)].decode('ascii')
        if value != expected:
            raise ValueError('Diagnostic string mismatch')
        values[hex(address)] = value
    return {'kernel_sha256': KERNEL, 'decompressed_sha256': IMAGE,
            'strings': values, 'runtime_branch_observed': False,
            'limits': ['Strings are static branch discriminators, not evidence that a branch ran.',
                       'Missing log messages cannot exclude a branch without verified log coverage.']}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.kernel)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')

"""Extract the banner and embedded IKCONFIG from a gzip-compressed ARM kernel."""
import argparse
import hashlib
import json
import re
import zlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    payload = args.kernel.read_bytes()
    cursor = 0
    while True:
        start = payload.find(b'\x1f\x8b\x08', cursor)
        if start < 0:
            raise ValueError('No supported gzip kernel with Linux banner found')
        cursor = start + 3
        try:
            decompressor = zlib.decompressobj(31)
            image = decompressor.decompress(payload[start:], 128 * 1024 * 1024)
            if not decompressor.eof:
                continue
        except zlib.error:
            continue
        banners = re.findall(rb'Linux version [^\x00\n]+', image)
        if banners:
            break
    offset = image.find(b'IKCFG_ST')
    if offset < 0:
        raise ValueError('Kernel found but no embedded IKCONFIG marker')
    stop = image.index(b'IKCFG_ED', offset + 8)
    config = zlib.decompress(image[offset + 8:stop], 31)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'kernel.config').write_bytes(config)
    result = {'input_sha256': hashlib.sha256(payload).hexdigest(),
              'gzip_offset': start, 'decompressed_bytes': len(image),
              'banner': banners[0].decode('utf-8', errors='replace'),
              'config_sha256': hashlib.sha256(config).hexdigest()}
    (args.output / 'kernel-summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

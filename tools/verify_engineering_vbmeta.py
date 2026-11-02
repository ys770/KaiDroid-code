"""Bounded AVB RSA4096/SHA256 verification of captured engineering metadata.

Uses the Android 11 AVB header/descriptor formats. This is not an AVB trust,
rollback, hashtree, recovery or bootability verifier. Requires cryptography.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify(folder):
    blob = (folder / 'vbmeta.img').read_bytes()
    def part(data, offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError('Out-of-bounds AVB field')
        return data[offset:offset + size]
    def q(offset):
        return struct.unpack('>Q', part(blob, offset, 8))[0]
    if blob[:4] != b'AVB0' or struct.unpack_from('>I', blob, 28)[0] != 2:
        raise ValueError('Expected signed AVB SHA256_RSA4096')
    auth = part(blob, 256, q(12))
    aux = part(blob, 256 + q(12), q(20))
    signed = blob[:256] + aux
    digest = part(auth, q(32), q(40))
    if digest != hashlib.sha256(signed).digest():
        raise ValueError('VBMeta digest mismatch')
    key = part(aux, q(64), q(72))
    bits = struct.unpack('>I', part(key, 0, 4))[0]
    if bits != 4096 or len(key) != 1032:
        raise ValueError('Expected 4096-bit AVB public key')
    modulus = int.from_bytes(part(key, 8, bits // 8), 'big')
    rsa.RSAPublicNumbers(65537, modulus).public_key().verify(
        part(auth, q(48), q(56)), signed, padding.PKCS1v15(), hashes.SHA256())
    descriptors = part(aux, q(96), q(104))
    offset = 0
    records = []
    while offset < len(descriptors):
        tag, following = struct.unpack('>QQ', part(descriptors, offset, 16))
        data = part(descriptors, offset, 16 + following)
        if following % 8:
            raise ValueError('Unaligned descriptor')
        record = {'tag': tag}
        if tag == 2:
            fields = struct.unpack('>QQQ32sIIII60s', part(data, 0, 132))
            _, _, size, algorithm, nl, sl, dl, flags, _ = fields
            name = part(data, 132, nl).decode('utf-8')
            if name not in ('boot', 'dtbo', 'recovery'):
                raise ValueError('Unexpected hash partition: ' + name)
            salt = part(data, 132 + nl, sl)
            expected = part(data, 132 + nl + sl, dl)
            image = (folder / (name + '.img')).read_bytes()
            payload = part(image, 0, size)
            actual = hashlib.new(algorithm.rstrip(b'\0').decode(), salt + payload).digest()
            if actual != expected:
                raise ValueError('Partition descriptor mismatch: ' + name)
            record.update(partition=name, image_size=size, flags=flags, hash_verified=True)
        elif tag == 3:
            flags, length = struct.unpack('>II', part(data, 16, 8))
            if len(data) != (24 + length + 7) // 8 * 8:
                raise ValueError('Malformed kernel command-line descriptor')
            command = part(data, 24, length).decode('utf-8')
            disabled = bool(struct.unpack_from('>I', blob, 120)[0] & 1)
            selected = not ((flags & 1 and disabled) or (flags & 2 and not disabled))
            record.update(flags=flags, kernel_cmdline=command,
                          selected_by_standard_avb_flags=selected)
        elif tag == 1:
            fields = struct.unpack('>QQIQQQIIIQQ32sIIII60s', part(data, 0, 180))
            name = part(data, 180, fields[12]).decode('utf-8')
            record.update(partition=name, image_size=fields[3],
                          hashtree_verified=False)
        else:
            record['interpreted'] = False
        records.append(record)
        offset += len(data)
    return {'vbmeta_sha256': hashlib.sha256(blob).hexdigest(),
            'embedded_key_sha256': hashlib.sha256(key).hexdigest(),
            'signature_verified_against_embedded_key': True,
            'rollback_index': q(112), 'flags': struct.unpack_from('>I', blob, 120)[0],
            'descriptors': records,
            'limitation': 'Does not establish OEM trust, on-device rollback acceptance, system/vendor hashtree validity, restore or modified-system bootability.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.capture)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')

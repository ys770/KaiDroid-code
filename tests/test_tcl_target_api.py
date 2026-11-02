import hashlib
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_tcl_target_api import parse, resolve


def declaration_fixture():
    # One native declaration plus one reference-only method on the same class.
    strings = [b'Lsample/A;', b'Ljava/lang/Object;', b'V', b'declared', b'onlyReferenced']
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<II', data, 36, 112, 0x12345678)
    string_ids = len(data)
    data.extend(bytes(4 * len(strings)))
    type_ids = len(data)
    data.extend(struct.pack('<III', 0, 1, 2))
    proto_ids = len(data)
    data.extend(struct.pack('<III', 2, 2, 0))
    method_ids = len(data)
    data.extend(struct.pack('<HHIHHI', 0, 0, 3, 0, 0, 4))
    class_defs = len(data)
    data.extend(bytes(32))
    for index, text in enumerate(strings):
        struct.pack_into('<I', data, string_ids + index * 4, len(data))
        data.extend(bytes([len(text)]) + text + b'\0')
    class_data = len(data)
    data.extend(bytes([0, 0, 1, 0, 0, 0x81, 0x02, 0]))  # public native, no code
    struct.pack_into('<IIIIIIII', data, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    for header, count, offset in [(56, 5, string_ids), (64, 3, type_ids),
                                   (72, 1, proto_ids), (80, 0, 0),
                                   (88, 2, method_ids), (96, 1, class_defs)]:
        struct.pack_into('<II', data, header, count, offset)
    struct.pack_into('<I', data, 32, len(data))
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def cls(parent=None, methods=(), fields=(), interfaces=()):
    return dict(superclass=parent, methods=set(methods), fields=set(fields), interfaces=list(interfaces))


class TargetApiTests(unittest.TestCase):
    def test_references_are_not_definitions_and_native_is_a_declaration(self):
        classes, refs, _, stale = parse(declaration_fixture())
        self.assertFalse(stale)
        self.assertIn(('Lsample/A;', 'onlyReferenced', '()V'), refs)
        self.assertEqual(classes['Lsample/A;']['methods'], {('declared', '()V')})

    def test_inherited_method_and_field(self):
        classes = {'A': cls('B'), 'B': cls(methods=[('go', '()V')], fields=[('flag', 'Z')])}
        self.assertEqual(resolve(classes, 'A', 'go', '()V', 'methods')[0], 'B')
        self.assertEqual(resolve(classes, 'A', 'flag', 'Z', 'fields')[0], 'B')

    def test_constructors_do_not_inherit(self):
        classes = {'A': cls('B'), 'B': cls(methods=[('<init>', '()V')])}
        self.assertIsNone(resolve(classes, 'A', '<init>', '()V', 'methods')[0])

    def test_interface_and_missing_ancestor(self):
        classes = {'A': cls('Missing', interfaces=['I']), 'I': cls(methods=[('go', '()V')])}
        self.assertEqual(resolve(classes, 'A', 'go', '()V', 'methods')[0], 'I')
        self.assertEqual(resolve(classes, 'A', 'no', '()V', 'methods'), (None, {'Missing'}))

    def test_cyclic_hierarchy_terminates(self):
        self.assertEqual(resolve({'A': cls('B'), 'B': cls('A')}, 'A', 'no', '()V', 'methods'), (None, set()))


if __name__ == '__main__':
    unittest.main()

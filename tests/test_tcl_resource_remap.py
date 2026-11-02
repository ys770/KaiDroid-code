import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from remap_tcl_app_resources import references, transform
from compare_tcl_resource_values import definitions
from test_resource_xml import document, element, chunk

OLD, NEW = 0x0106000d, 0x0106000e


def resource_table(complex_entry=False, sparse=False):
    value = struct.pack('<HBBI', 8, 0, 1, OLD)
    if complex_entry:
        entry = struct.pack('<HHIII', 16, 1, 0, OLD, 1) + struct.pack('<I', OLD) + value
    else:
        entry = struct.pack('<HHI', 8, 0, 0) + value
    # Minimum synthetic config is size=4; no real platform install is implied.
    header = struct.pack('<BBHIII', 1, int(sparse), 0, 1, 28, 4)
    offsets = struct.pack('<HH', 2, 0) if sparse else struct.pack('<I', 0)
    typ = chunk(0x201, 24, header + offsets + entry)
    package = chunk(0x200, 288, bytes(280) + typ)
    return chunk(2, 12, struct.pack('<I', 1) + package)


class ResourceRemapTests(unittest.TestCase):
    def test_xml_integer_left_unchanged(self):
        data = document(element(0x10))
        output, changes = transform(data, True, {OLD: NEW})
        self.assertEqual(output, data)
        self.assertEqual(changes, [])

    def test_xml_reference_and_attribute(self):
        for typ in (1, 2):
            output, changes = transform(document(element(typ)), True, {OLD: NEW})
            self.assertEqual(len(changes), 1)
            self.assertEqual(struct.unpack_from('<I', output, changes[0]['offset'])[0], NEW)

    def test_dynamic_xml_fails_closed(self):
        with self.assertRaises(ValueError):
            transform(document(element(7)), True, {OLD: NEW})

    def test_dense_sparse_simple_and_complex(self):
        for sparse in (False, True):
            for complex_entry in (False, True):
                with self.subTest(sparse=sparse, complex=complex_entry):
                    data = resource_table(complex_entry, sparse)
                    output, changes = transform(data, False, {OLD: NEW})
                    self.assertEqual(len(changes), 3 if complex_entry else 1)
                    self.assertEqual(len(output), len(data))
                    for offset, _ in references(output, False):
                        self.assertEqual(struct.unpack_from('<I', output, offset)[0], NEW)

    def test_truncated_and_invalid_offsets_rejected(self):
        data = resource_table()
        with self.assertRaises(ValueError):
            transform(data[:-1], False, {OLD: NEW})
        invalid = bytearray(data)
        struct.pack_into('<I', invalid, 12 + 288 + 16, 0xffffffff)
        with self.assertRaises(ValueError):
            transform(invalid, False, {OLD: NEW})

    def test_sparse_encoding_does_not_change_qualifier(self):
        text = ('      spec resource 0x0106000d android:color/test: flags=0x0\n'
                '      config (default){flags}:\n'
                '        resource 0x0106000d android:color/test: t=0x10 d=0x0106000d\n'
                '          (integer) 17170445\n')
        a = definitions(text.format(flags=''))
        b = definitions(text.format(flags=' flags=0x01 [sparse]'))
        self.assertEqual(a, b)
        # An integer resembling a resource ID must not become a symbolic name.
        self.assertIn('d=0x0106000d', a['android:color/test']['(default)'][0])


if __name__ == '__main__':
    unittest.main()

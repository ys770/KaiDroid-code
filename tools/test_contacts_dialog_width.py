import struct
import unittest
from prepare_contacts_dialog_width import transform


def fixture(count=2, value_type=5):
    resource_map = struct.pack('<HHII', 0x180, 8, 12, 0x010100f4)
    elements = b''
    for _ in range(count):
        node = bytearray(56)
        struct.pack_into('<HHI', node, 0, 0x102, 16, 56)
        struct.pack_into('<HHH', node, 24, 20, 20, 1)
        struct.pack_into('<IIIHBBI', node, 36, 0, 0, 0xffffffff, 8, 0, value_type, 0xf001)
        elements += node
    return struct.pack('<HHI', 3, 8, 8 + len(resource_map) + len(elements)) + resource_map + elements


class WidthTests(unittest.TestCase):
    def test_two_typed_widths_only(self):
        before = fixture()
        after, changes = transform(before)
        self.assertEqual(2, len(changes))
        self.assertEqual(len(before), len(after))
        for change in changes:
            self.assertEqual((8, 0, 16, 0xffffffff), struct.unpack_from('<HBBI', after, change['attribute_offset'] + 12))

    def test_wrong_count_or_type_rejected(self):
        for data in (fixture(1), fixture(3), fixture(value_type=16)):
            with self.assertRaises(ValueError): transform(data)

    def test_truncated_xml_rejected(self):
        with self.assertRaises(ValueError): transform(fixture()[:-1])


if __name__ == '__main__':
    unittest.main()

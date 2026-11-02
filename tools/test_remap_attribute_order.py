import struct
import unittest
from remap_tcl_app_resources import transform, reorder_xml_attributes, checked_target_name


def fixture():
    ids = struct.pack('<HHIII', 0x180, 8, 16, 0x01010618, 0x0101061a)
    node = bytearray(76)
    struct.pack_into('<HHI', node, 0, 0x102, 16, 76)
    struct.pack_into('<HHHHHH', node, 24, 20, 20, 2, 1, 2, 0)
    for i, value in enumerate((123, 456)):
        struct.pack_into('<IIIHBBI', node, 36 + i * 20, 0, i, 0xffffffff, 8, 0, 0x10, value)
    return struct.pack('<HHI', 3, 8, 8 + len(ids) + len(node)) + ids + node


class AttributeOrderTests(unittest.TestCase):
    def test_reversed_ids_keep_values_and_special_indices(self):
        data, _ = transform(fixture(), True, {0x01010618: 0x01120037, 0x0101061a: 0x01120036})
        after, changes = reorder_xml_attributes(data)
        self.assertEqual(len(changes), 1)
        node = 24
        self.assertEqual(struct.unpack_from('<HHH', after, node + 30), (2, 1, 0))
        self.assertEqual(struct.unpack_from('<I', after, node + 36 + 4)[0], 1)
        self.assertEqual(struct.unpack_from('<I', after, node + 36 + 16)[0], 456)
        self.assertEqual(struct.unpack_from('<I', after, node + 56 + 16)[0], 123)
        self.assertEqual(reorder_xml_attributes(after), (after, []))

    def test_unchanged_order_is_byte_identical(self):
        data = fixture()
        self.assertEqual(reorder_xml_attributes(data), (data, []))

    def test_only_same_name_private_attribute_alias(self):
        self.assertEqual(checked_target_name(dict(name='android:attr/editTextTitle',
            target_name='android:^attr-private/editTextTitle')), 'android:^attr-private/editTextTitle')
        for target in ('android:^attr-private/other', 'android:id/editTextTitle'):
            with self.assertRaises(ValueError):
                checked_target_name(dict(name='android:attr/editTextTitle', target_name=target))


if __name__ == '__main__':
    unittest.main()

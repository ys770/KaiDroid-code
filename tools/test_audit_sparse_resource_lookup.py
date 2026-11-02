import struct
import unittest
from audit_sparse_resource_lookup import audit


def resource(flags=1, index=1, units=4):
    # One sparse slot whose 4-byte offset units point at a valid entry.
    data = bytearray(48)
    struct.pack_into('<HHIBBHII', data, 0, 0x201, 20, 48, 7, flags, 0, 1, 24)
    struct.pack_into('<HH', data, 20, index, units)
    struct.pack_into('<HHI', data, 40, 8, 0, 3)
    return data


class SparseTest(unittest.TestCase):
    def test_sparse_pair_is_not_dense_offset(self):
        result = audit(resource())
        self.assertEqual(1, result['dense_interpretation_outside_chunk'])
        entry = result['matching_0x40001'][0]
        self.assertEqual(16, entry['sparse_byte_offset'])
        self.assertEqual(1, entry['resource_entry_index'])
        self.assertEqual(262145, entry['dense_misread_offset'])

    def test_dense_chunk_not_misclassified(self):
        self.assertEqual(0, audit(resource(flags=0))['sparse_chunks'])

    def test_truncated_and_invalid_offsets_rejected(self):
        for data in (resource()[:-1], resource(units=100)):
            with self.assertRaises(ValueError): audit(data)


if __name__ == '__main__':
    unittest.main()

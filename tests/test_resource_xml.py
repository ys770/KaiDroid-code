"""Binary-format regression cases for the resource inventory parser."""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_apk_resource_references import xml_references


def chunk(kind, head, payload):
    return struct.pack('<HHI', kind, head, len(payload) + 8) + payload


def document(*chunks):
    return chunk(3, 8, b''.join(chunks))


def element(value_type=1, size=8):
    node = struct.pack('<II', 1, 0xffffffff)
    extension = struct.pack('<IIHHHHHH', 0xffffffff, 0, 20, 20, 1, 0, 0, 0)
    attr = struct.pack('<IIIHBBI', 0xffffffff, 0, 0xffffffff, size, 0, value_type, 0x0106000d)
    return chunk(0x102, 16, node + extension + attr)


class ResourceXmlTests(unittest.TestCase):
    def test_named_attribute_and_typed_reference(self):
        data = document(chunk(0x180, 8, struct.pack('<I', 0x01010054)), element())
        self.assertEqual(xml_references(data), [('attribute-name', 0x01010054), ('reference', 0x0106000d)])

    def test_reference_keeps_consuming_attribute(self):
        data = document(chunk(0x180, 8, struct.pack('<I', 0x01010034)), element())
        self.assertEqual(xml_references(data, include_context=True)[1],
                         ('reference', 0x0106000d, 0x01010034))

    def test_integer_is_not_a_reference(self):
        self.assertEqual(xml_references(document(element(0x10))), [])

    def test_rejects_dynamic_and_malformed_values(self):
        for data in (document(element(7)), document(element(size=4)), document(element())[:-1]):
            with self.assertRaises(ValueError):
                xml_references(data)

    def test_empty_cdata_and_dynamic_cdata(self):
        node = struct.pack('<III', 1, 0xffffffff, 22)
        self.assertEqual(xml_references(document(chunk(0x104, 16, node + bytes(8)))), [])
        with self.assertRaises(ValueError):
            xml_references(document(chunk(0x104, 16, node + struct.pack('<HBBI', 8, 0, 7, 0x0106000d))))


if __name__ == '__main__':
    unittest.main()

import struct,unittest
from rewrite_manifest_identity import rewrite_manifest,rewrite_resource_strings


def fixture(utf8):
    strings=['com.android.deskclock','com.android.deskclock.DeskClock','android.uid.system'];blob=b'';offsets=[]
    for s in strings:
        offsets.append(len(blob));raw=s.encode('utf-8' if utf8 else 'utf-16-le')
        blob+=(bytes([len(s),len(raw)]) if utf8 else struct.pack('<H',len(s)))+raw+(b'\0' if utf8 else b'\0\0')
    blob+=b'\0'*((-len(blob))%4);start=28+4*len(strings)
    pool=struct.pack('<HHIIIIII',1,28,start+len(blob),len(strings),0,(0x100 if utf8 else 0)|1,start,0)+struct.pack('<III',*offsets)+blob
    return struct.pack('<HHI',3,8,8+len(pool))+pool

class ManifestIdentityTests(unittest.TestCase):
    def test_exact_only_utf8_and_utf16(self):
        for encoding in (False,True):
            data=fixture(encoding);out,changes=rewrite_manifest(data,{'com.android.deskclock':'com.kaidroid.tclclock'})
            self.assertEqual(len(out),len(data));self.assertEqual(len(changes),1)
            self.assertEqual(struct.unpack_from('<I',out,24)[0]&1,0)
            self.assertEqual(rewrite_manifest(out,{'com.android.deskclock':'com.kaidroid.tclclock'})[1],[])
            enc='utf-8' if encoding else 'utf-16-le'
            self.assertIn('android.uid.system'.encode(enc),out)
            self.assertIn('com.android.deskclock.DeskClock'.encode(enc),out)
    def test_rejects_width_change(self):
        with self.assertRaises(ValueError):rewrite_manifest(fixture(True),{'com.android.deskclock':'short'})
    def test_rejects_truncated(self):
        with self.assertRaises(ValueError):rewrite_manifest(fixture(False)[:-1],{})
    def test_resource_pool_keeps_package_and_indices(self):
        for encoding in (False,True):
            pool=fixture(encoding)[8:]
            package=struct.pack('<HHI',0x200,8,12)+b'KEEP'
            data=struct.pack('<HHII',2,12,12+len(pool)+len(package),1)+pool+package
            out,changes=rewrite_resource_strings(data,{'com.android.deskclock':'com.kaidroid.tclclock'})
            self.assertEqual(len(out),len(data));self.assertEqual(len(changes),1)
            self.assertEqual(out[-len(package):],package)
            self.assertEqual(out[:12],data[:12])
            self.assertEqual(out[12+28:12+28+12],data[12+28:12+28+12])
            reversed_data,_=rewrite_resource_strings(out,{'com.kaidroid.tclclock':'com.android.deskclock'})
            # Sorted flag is deliberately cleared; restore it only to compare fixture bytes.
            reversed_data=bytearray(reversed_data)
            struct.pack_into('<I',reversed_data,12+16,struct.unpack_from('<I',data,12+16)[0])
            self.assertEqual(bytes(reversed_data),data)

if __name__=='__main__':unittest.main()

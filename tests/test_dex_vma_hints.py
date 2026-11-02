import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from summarize_dex_vma_hints import parse


class VmaHintControls(unittest.TestCase):
    def test_flag_and_file_offset_are_not_residency(self):
        text='1000-5000 r--p 00001000 b3:10 123 /system/framework/framework.jar\nRss: 4 kB\nPss: 2 kB\nVmFlags: rd mr rr ac\n'
        row=parse(text)[0]
        self.assertEqual(row['file_offset'],4096)
        self.assertEqual(row['virtual_bytes'],16384)
        self.assertEqual(row['Rss_KiB'],4)
        self.assertIn('rr',row['vm_flags'])

    def test_truncated_final_mapping_rejected(self):
        text='1000-5000 r--p 00001000 b3:10 123 /system/framework/framework.jar\nRss: 4 kB\nPss: 2 kB\n'
        with self.assertRaises(ValueError):parse(text)

    def test_targeted_mapping_does_not_include_other_files(self):
        text='1000-5000 r--p 00001000 b3:10 123 /other/file\nRss: 4 kB\nPss: 2 kB\nVmFlags: rd mr\n'
        self.assertEqual(parse(text),[])


if __name__=='__main__':unittest.main()

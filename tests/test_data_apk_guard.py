import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from capture_data_apk_guard import parse_manifest


class DataApkManifestControls(unittest.TestCase):
    def test_complete_paths_and_crlf(self):
        path='/data/app/~~value==/com.android.mms-value==/base.apk'
        self.assertEqual(parse_manifest('a'*64+'  '+path+'\r\n'),{path:'a'*64})

    def test_duplicate_paths_rejected(self):
        row='a'*64+'  /data/app/p/base.apk\n'
        with self.assertRaises(ValueError):parse_manifest(row+row)

    def test_empty_and_non_apk_paths_rejected(self):
        for text in ('','a'*64+'  /system/app/p/base.apk\n','a'*64+'  /data/app/p/classes.dex\n'):
            with self.assertRaises(ValueError):parse_manifest(text)

    def test_bad_or_partial_digest_rejected(self):
        for digest in ('a'*63,'z'*64):
            with self.assertRaises(ValueError):parse_manifest(digest+'  /data/app/p/base.apk\n')


if __name__=='__main__':unittest.main()

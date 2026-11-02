import unittest
from prepare_messaging_authority import OLD, NEW, transform


class AuthorityTests(unittest.TestCase):
    def test_uri_literal_preserves_class_reference(self):
        source = ('.class public Lcom/android/mms/util/UriUtil;\n'
                  '.method public static example()V\n'
                  '    const-string v0, "'+OLD+'"\n'
                  '    return-void\n.end method\n')
        result = transform(source, 'smali/com/android/mms/util/UriUtil.smali')
        self.assertEqual(result, source.replace('"'+OLD+'"', '"'+NEW+'"'))

    def test_unreviewed_site_rejected(self):
        with self.assertRaises(ValueError):
            transform('.field a:Ljava/lang/String; = "'+OLD+'"\n', 'other.smali')

    def test_missing_site_rejected(self):
        with self.assertRaises(ValueError):
            transform('.class public LExample;\n', 'smali/com/android/mms/util/UriUtil.smali')


if __name__ == '__main__':
    unittest.main()

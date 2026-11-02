import unittest
from deliver_stock_apps36 import installed_paths, metadata, require_upgrade, require_launch_success, PLATFORM_CERT, EXISTING_CERT


class DeliveryGuards(unittest.TestCase):
    def test_launch_text_must_report_success(self):
        require_launch_success('Starting: Intent\nStatus: ok\nComplete')
        for output in ('Error type 3\nError: Activity does not exist', 'Status: timeout', 'Starting: Intent'):
            with self.assertRaises(ValueError):
                require_launch_success(output)

    def test_package_identity_and_version(self):
        self.assertEqual(metadata("package: name='com.example.app' versionCode='42' versionName='x'", 'com.example.app'), 42)
        with self.assertRaises(ValueError):
            metadata("package: name='com.wrong.app' versionCode='42'", 'com.example.app')

    def test_paths_are_preserved_and_shell_safe(self):
        self.assertEqual(installed_paths(''), [])
        self.assertEqual(installed_paths('package:/data/app/~~abc==/pkg-123/base.apk'), ['/data/app/~~abc==/pkg-123/base.apk'])
        for text in ('Failure', 'package:/data/app/a.apk;reboot', 'package:relative.apk'):
            with self.assertRaises(ValueError):
                installed_paths(text)

    def test_no_signing_migration_fallback(self):
        require_upgrade(2, 1, PLATFORM_CERT, PLATFORM_CERT)
        require_upgrade(2, 1, EXISTING_CERT, EXISTING_CERT, EXISTING_CERT)
        with self.assertRaises(ValueError):
            require_upgrade(2, 1, PLATFORM_CERT, 'different')
        with self.assertRaises(ValueError):
            require_upgrade(2, 1, PLATFORM_CERT, EXISTING_CERT, EXISTING_CERT)

    def test_no_automatic_downgrade(self):
        with self.assertRaises(ValueError):
            require_upgrade(1, 2, PLATFORM_CERT, PLATFORM_CERT)


if __name__ == '__main__':
    unittest.main()

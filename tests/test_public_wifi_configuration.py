"""Missing network configuration must fail before transport or filesystem changes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ('check_image57_boot_wifi.py', 'check_image58_boot_wifi.py',
           'check_image59_boot_wifi.py', 'trial_messaging_network_image56.py')


class PublicWifiConfigurationTests(unittest.TestCase):
    def test_network_is_configurable_in_help(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, str(ROOT/'tools'/script), '--help'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn('--ssid', result.stdout)

    def test_missing_network_stops_before_creating_output(self):
        env = os.environ.copy()
        env.pop('KAIDROID_WIFI_SSID', None)
        with tempfile.TemporaryDirectory() as tmp:
            for script in SCRIPTS:
                with self.subTest(script=script):
                    output = Path(tmp)/script
                    args = [sys.executable, str(ROOT/'tools'/script), '--output', str(output)]
                    if script.startswith('check_'):
                        args += ['--boot', '00000000-0000-0000-0000-000000000000']
                    result = subprocess.run(args, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('--ssid or KAIDROID_WIFI_SSID is required', result.stderr)
                    self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

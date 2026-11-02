"""Reject malformed stock staging inputs before writing shared-tree files."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

NAMES = ('FPCalendar', 'FPDeskClock', 'JrdGallery', 'Calculator', 'Note', 'FileManager')


class StockStagingTests(unittest.TestCase):
    def run_case(self, bad_privilege=False, corrupt_payload=False, media=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries, apps = {}, []
            names = ('TclMusic', 'TctSoundRecorder', 'TctCamera') if media else NAMES
            for name in names:
                payload = ('synthetic-' + name).encode()
                entries[name + '/' + name + '.apk'] = payload
                entries[name + '/Android.mk'] = ('LOCAL_PRIVILEGED_MODULE := ' + str(media).lower() + '\n').encode()
                apps.append(dict(name=name, privileged_module=media,
                                 sha256=hashlib.sha256(payload).hexdigest()))
            if bad_privilege:
                apps[0]['privileged_module'] = not media
            if corrupt_payload:
                entries[names[0] + '/' + names[0] + '.apk'] += b'changed'
            entries['provenance.json'] = json.dumps(dict(apps=apps)).encode()
            archive = root / 'input.tar'
            with tarfile.open(archive, 'w') as output:
                for name, data in entries.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    output.addfile(item, io.BytesIO(data))
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('stage_tcl_ui_apps.py')),
                                     '--media-apps' if media else '--stock-apps', '--archive', str(archive),
                                     '--destination', str(root / 'modules'), '--stage', str(root / 'stage')],
                                    capture_output=True, text=True)
            if bad_privilege or corrupt_payload:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'modules').exists())
                self.assertFalse((root / 'stage').exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads((root / 'stage/staging.json').read_text())
                self.assertEqual(report['stock_apps'], not media)
                self.assertEqual(report['media_apps'], media)
                self.assertFalse(report['installed'])
                self.assertEqual(len(report['files']), 1 + 2 * len(names))

    def test_accepts_media_privileged_set(self):
        self.run_case(media=True)

    def test_rejects_media_privilege_change(self):
        self.run_case(media=True, bad_privilege=True)

    def test_rejects_media_payload_change(self):
        self.run_case(media=True, corrupt_payload=True)

    def test_accepts_complete_nonprivileged_set(self):
        self.run_case()

    def test_rejects_privilege_promotion_without_writes(self):
        self.run_case(bad_privilege=True)

    def test_rejects_changed_payload_without_writes(self):
        self.run_case(corrupt_payload=True)


if __name__ == '__main__':
    unittest.main()

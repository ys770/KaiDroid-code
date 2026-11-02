"""Offline controls; no phone, build host, or ADB invocation."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('capture', HERE / 'trace-priority-capture01.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
CAP = ROOT / 'artifacts/runtime/image59-trace-capability01.json'


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.packet = Path(self.tmp.name) / 'packet'

    def prepare(self):
        with patch.object(capture, 'adb_call', side_effect=AssertionError('offline')):
            return capture.prepare(CAP, self.packet, nonce='0123456789ab')

    def test_offline_exact_capability_and_four_events(self):
        plan = self.prepare()
        self.assertFalse(plan['executed'])
        self.assertEqual(len(plan['events']), 4)
        self.assertEqual(plan['configured_ring_kib'], 256)
        self.assertEqual(plan['expected']['boot_id'], capture.BOOT)

    def test_wrong_capability_rejected_before_packet_creation(self):
        wrong = Path(self.tmp.name) / 'wrong.json'
        wrong.write_bytes(CAP.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            capture.prepare(wrong, self.packet)
        self.assertFalse(self.packet.exists())

    def test_duration_and_name_bounds(self):
        for duration in (0, 9, 46, 999):
            with self.assertRaises(ValueError):
                capture.prepare(CAP, self.packet, duration)
        for name in ('../wifi', 'kaidroid-priority-$(id)', 'wifi'):
            with self.assertRaises(ValueError):
                capture.validate_name(name)

    def test_existing_packet_not_overwritten(self):
        self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_tampered_worker_blocks_start(self):
        self.prepare()
        (self.packet / 'worker.sh').write_text('tampered')
        with patch.object(capture, 'adb_call') as adb:
            with self.assertRaises(ValueError):
                capture.run_action('start', self.packet, Path('unused'))
            adb.assert_not_called()

    def test_serial_mismatch_never_sends_script(self):
        self.prepare()
        with patch.object(capture, 'adb_call', return_value=subprocess.CompletedProcess([], 0, b'wrong\n', b'')) as adb:
            with self.assertRaises(ValueError):
                capture.run_action('start', self.packet, Path('unused'))
            self.assertEqual(adb.call_count, 1)

    def test_timeout_terminal_no_automatic_or_manual_reuse(self):
        self.prepare()
        with patch.object(capture, 'adb_call', side_effect=[
                subprocess.CompletedProcess([], 0, capture.SERIAL.encode(), b''),
                subprocess.TimeoutExpired('mocked', 12)]) as adb:
            with self.assertRaises(subprocess.TimeoutExpired):
                capture.run_action('start', self.packet, Path('unused'))
            self.assertEqual(adb.call_count, 2)
        with patch.object(capture, 'adb_call') as adb:
            with self.assertRaises(FileExistsError):
                capture.run_action('start', self.packet, Path('unused'))
            adb.assert_not_called()

    def test_exec_out_hidden_remote_failure_is_rejected(self):
        self.prepare()
        with patch.object(capture, 'adb_call', side_effect=[
                subprocess.CompletedProcess([], 0, capture.SERIAL.encode(), b''),
                subprocess.CompletedProcess([], 0, b'', b'')]):
            with self.assertRaisesRegex(ValueError, 'ARMED receipt'):
                capture.run_action('start', self.packet, Path('unused'))
        result = json.loads((self.packet / 'start-result.json').read_text())
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['remote_armed_receipt_verified'])

    def test_wrong_instance_receipt_is_rejected(self):
        self.prepare()
        line = b'ARMED kaidroid-priority-ffffffffffff duration=30s; parent may now start chosen app\n'
        with patch.object(capture, 'adb_call', side_effect=[
                subprocess.CompletedProcess([], 0, capture.SERIAL.encode(), b''),
                subprocess.CompletedProcess([], 0, line, b'')]):
            with self.assertRaisesRegex(ValueError, 'ARMED receipt'):
                capture.run_action('start', self.packet, Path('unused'))

    def test_exact_remote_receipt_accepted_with_crlf(self):
        self.prepare()
        line = b'ARMED kaidroid-priority-0123456789ab duration=30s; parent may now start chosen app\r\n'
        with patch.object(capture, 'adb_call', side_effect=[
                subprocess.CompletedProcess([], 0, capture.SERIAL.encode(), b''),
                subprocess.CompletedProcess([], 0, line, b'')]):
            capture.run_action('start', self.packet, Path('unused'))
        result = json.loads((self.packet / 'start-result.json').read_text())
        self.assertTrue(result['remote_armed_receipt_verified'])

    def test_foreign_export_retained_not_extracted(self):
        self.prepare()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as tar:
            member = tarfile.TarInfo('../escape.txt')
            member.size = 1
            tar.addfile(member, io.BytesIO(b'x'))
        with patch.object(capture, 'adb_call', side_effect=[
                subprocess.CompletedProcess([], 0, capture.SERIAL.encode(), b''),
                subprocess.CompletedProcess([], 0, data.getvalue(), b'')]):
            with self.assertRaises(ValueError):
                capture.run_action('collect', self.packet, Path('unused'))
        self.assertEqual((self.packet / 'capture.tar').read_bytes(), data.getvalue())
        self.assertFalse((Path(self.tmp.name) / 'escape.txt').exists())

    def test_shell_write_scope_and_no_deletion(self):
        self.prepare()
        worker = (self.packet / 'worker.sh').read_text()
        self.assertNotIn('sched_switch', worker)
        self.assertNotIn('binder', worker)
        self.assertNotIn('trace_pipe', worker)
        self.assertNotIn('rmdir', worker)
        self.assertNotIn('rm ', worker)
        self.assertNotIn('am start', worker)
        for line in worker.splitlines():
            if '> ' in line or '>> ' in line:
                self.assertTrue('"$work/' in line or '"$inst/' in line,
                                'unreviewed redirection: ' + line)
        self.assertNotIn('> "$inst/events/enable"', worker)

    def test_cleanup_identity_inode_guards_and_stop_first(self):
        self.prepare()
        worker = (self.packet / 'worker.sh').read_text()
        owned = worker.split('owned() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('identity', owned)
        self.assertIn('"$instance_inode"', owned)
        self.assertIn('"$root_inode"', owned)
        finish = worker.split('finish() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(finish.index('stop_owned'), finish.index('protected >'))
        self.assertIn('changed_not_restored', finish)

    def test_deadline_child_arms_then_sleeps_and_stops(self):
        self.prepare()
        worker = (self.packet / 'worker.sh').read_text()
        timer = worker.split('\n(\n', 1)[1].split('\n) &', 1)[0]
        self.assertIn("trap 'stop_owned' EXIT", timer)
        self.assertEqual(timer.count('stop.request'), 2)
        self.assertLess(timer.index('> "$inst/tracing_on"'), timer.index('sleep "$seconds"'))
        self.assertLess(timer.index('sleep "$seconds"'), timer.rindex('stop_owned'))
        self.assertIn('setsid nohup sh', (self.packet / 'launch.sh').read_text())

    def test_actual_oom_schema_retained(self):
        self.prepare()
        launch = (self.packet / 'launch.sh').read_text()
        self.assertRegex(launch, r'field:pid_t pid;\s+offset:8;')
        self.assertRegex(launch, r'field:short oom_score_adj;\s+offset:28;')
        self.assertIn('ID: 174', launch)

    def archive(self, files):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as tar:
            for name, value in files.items():
                raw = value.encode()
                member = tarfile.TarInfo('./' + name)
                member.size = len(raw)
                tar.addfile(member, io.BytesIO(raw))
        return data.getvalue()

    def test_missing_cleanup_or_stats_never_complete(self):
        summary = capture.inspect_archive(self.archive({'trace.txt': 'trace'}))
        self.assertFalse(summary['capture_and_cleanup_status_complete'])
        self.assertEqual(summary['loss_status'], 'unknown')

    def test_loss_counters_zero_and_nonzero(self):
        stats = ''.join(f'cpu{i}\noverrun: 0\ncommit overrun: 0\ndropped events: 0\n' for i in range(4))
        summary = capture.inspect_archive(self.archive({'loss-stats.txt': stats}))
        self.assertEqual(summary['loss_status'], 'observed_counters_zero')
        self.assertFalse(summary['event_delivery_or_race_absence_proven'])
        summary = capture.inspect_archive(self.archive({'loss-stats.txt': stats.replace('overrun: 0', 'overrun: 1', 1)}))
        self.assertEqual(summary['loss_status'], 'nonzero_loss_counters')

    def test_provisional_stop_and_changed_protected_state_not_complete(self):
        summary = capture.inspect_archive(self.archive({
            'cleanup.txt': 'stopped_at_cleanup_deadline_child_not_joined_recheck_required',
            'protected-comparison.txt': 'changed_not_restored', 'supervisor-exit.txt': '0'}))
        self.assertFalse(summary['capture_and_cleanup_status_complete'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

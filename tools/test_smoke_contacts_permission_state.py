import json
import unittest
from smoke_contacts_permission_state import smoke, HELPER_SHA, CANDIDATE_SHA


class FakeShell:
    def __init__(self, failure=None, changed=None):
        self.calls = []
        self.failure = failure
        self.changed = changed or {}

    def __call__(self, label, command):
        self.calls.append((label, command))
        if label == self.failure:
            raise RuntimeError('injected observation failure')
        if label in self.changed:
            return self.changed[label]
        if label.endswith('-density'): return 'Physical density: 213\nOverride density: 160'
        if label.endswith('-image'): return '36'
        if label.endswith('-boot'): return 'test-boot'
        if label.endswith('-root'): return '0'
        if label.endswith('-debug'): return '1'
        if label.endswith('-selinux'): return 'Enforcing'
        if label == 'helper-hash': return HELPER_SHA + '  helper.jar'
        if label == 'candidate-path': return 'package:/data/app/test/base.apk'
        if label == 'candidate-hash': return CANDIDATE_SHA + '  base.apk'
        if label == 'baseline': return json.dumps(dict(boot='test-boot', image='36', uid=10073))
        if label.startswith('baseline-hash'): return 'a' * 64 + '  baseline.json'
        if label in ('capture', 'verify-before', 'restore-noop', 'verify-after'): return 'ok'
        raise AssertionError('Unexpected call ' + label)


class SmokeTest(unittest.TestCase):
    def test_success_has_no_ui_install_or_grant_commands(self):
        shell = FakeShell()
        result = smoke(shell, '/data/local/tmp/test', 'test-boot')
        self.assertTrue(result['no_grant_smoke_passed'])
        self.assertFalse(result['actual_grant_restoration_verified'])
        commands = '\n'.join(command for _, command in shell.calls)
        for forbidden in ('install ', 'am start', 'input ', 'pm grant', 'appops set', ' restore '):
            self.assertNotIn(forbidden, commands)
        self.assertIn(' restore-noop ', commands)

    def test_failed_readonly_verify_never_restores(self):
        shell = FakeShell(failure='verify-before')
        with self.assertRaises(RuntimeError): smoke(shell, '/data/local/tmp/test', 'test-boot')
        self.assertNotIn('restore-noop', [label for label, _ in shell.calls])

    def test_changed_guards_hashes_stop_before_restore(self):
        for label, value in [('before-image', '32'), ('before-boot', 'changed'),
                             ('before-density', 'Physical density: 213'),
                             ('before-root', '2000'), ('before-selinux', 'Permissive'),
                             ('helper-hash', 'bad'), ('candidate-hash', 'bad'),
                             ('baseline-hash-again', 'b' * 64)]:
            with self.subTest(label=label):
                shell = FakeShell(changed={label: value})
                with self.assertRaises(ValueError): smoke(shell, '/data/local/tmp/test', 'test-boot')
                self.assertNotIn('restore-noop', [key for key, _ in shell.calls])

    def test_failed_restore_or_final_verify_is_not_retried(self):
        for label in ('restore-noop', 'verify-after'):
            shell = FakeShell(failure=label)
            with self.assertRaises(RuntimeError): smoke(shell, '/data/local/tmp/test', 'test-boot')
            self.assertEqual(1, sum(key == label for key, _ in shell.calls))


if __name__ == '__main__':
    unittest.main()

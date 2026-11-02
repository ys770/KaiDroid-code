import json
import unittest
from unittest.mock import patch
from trial_contacts_one_permission import check_prompt, trial, CONTROLLER_SHA


def xml(focus='deny', question='Allow Contacts to access your phone call logs?'):
    return '<hierarchy>' + ''.join([
        f'<node resource-id="com.android.permissioncontroller:id/permission_message" text="{question}"/>',
        *[f'<node resource-id="com.android.permissioncontroller:id/permission_{name}_button" '
          f'package="com.android.permissioncontroller" text="{name.upper()}" enabled="true" '
          f'clickable="true" focused="{str(name == focus).lower()}"/>' for name in ('allow', 'deny')],
        f'<node package="com.android.permissioncontroller" text="{focus.title()}" bounds="[80,280][159,320]"/>',
    ]) + '</hierarchy>'


PACKAGE = '''Packages:
  Package [com.android.contacts] (abc):
    userId=10073
    User 0: installed=true
      runtime permissions:
        android.permission.READ_CALL_LOG: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
'''


class Fake:
    def __init__(self, failure=None, wrong_prompt=False):
        self.calls = []
        self.failure = failure
        self.wrong_prompt = wrong_prompt

    def __call__(self, label, command):
        self.calls.append((label, command))
        if label == self.failure:
            raise TimeoutError('uncertain activation')
        if label == 'controller-path': return 'package:/data/app/controller/base.apk'
        if label == 'controller-hash': return CONTROLLER_SHA
        if label.startswith('full-package'): return PACKAGE
        if label in ('read-baseline', 'read-after-choice'):
            return json.dumps(dict(permissions={
                'READ_CALL_LOG': dict(granted=label == 'read-after-choice', flags=2048),
                'READ_SMS': dict(granted=False, flags=2048)}))
        if label.endswith('-xml'):
            return xml(label.split('-')[0], 'Other question' if self.wrong_prompt else
                       'Allow Contacts to access your phone call logs?')
        if label == 'baseline-hash-before-restore': return 'a' * 64
        return 'ok'


class TrialTests(unittest.TestCase):
    def execute(self, fake, report):
        with patch('trial_contacts_one_permission.smoke', return_value={'baseline_sha256': 'a' * 64}):
            trial(fake, lambda _: None, '/data/local/tmp/test', 'boot', report, settle=lambda _: None)

    def test_exactly_one_choice_then_restoration(self):
        fake, report = Fake(), {}
        self.execute(fake, report)
        self.assertTrue(report['restoration_verified'])
        self.assertTrue(report['call_log_grant_observed'])
        self.assertEqual(1, sum(command == 'input keyevent 23' for _, command in fake.calls))
        self.assertIn('verify-restored-settled', [key for key, _ in fake.calls])

    def test_wrong_prompt_never_activates_and_restores(self):
        fake, report = Fake(wrong_prompt=True), {}
        with self.assertRaises(ValueError): self.execute(fake, report)
        self.assertFalse(report['choice_attempted'])
        self.assertTrue(report['restoration_verified'])

    def test_uncertain_activation_never_retries_or_interleaves_restore(self):
        fake, report = Fake(failure='activate-allow-once'), {}
        with self.assertRaises(TimeoutError): self.execute(fake, report)
        self.assertFalse(report['restoration_verified'])
        self.assertTrue(report['observation_timeout_requires_process_review'])
        self.assertNotIn('restore-state', [key for key, _ in fake.calls])

    def test_restore_failure_does_not_report_success(self):
        fake, report = Fake(failure='restore-state'), {}
        with self.assertRaises(TimeoutError): self.execute(fake, report)
        self.assertFalse(report['restoration_verified'])

    def test_prompt_requires_expected_focus_and_center_label(self):
        check_prompt(xml(), 'deny')
        check_prompt(xml('allow'), 'allow')
        for bad in [xml('allow'), xml().replace('text="Deny"', 'text="Allow"'),
                    xml().replace('enabled="true"', 'enabled="false"'),
                    xml().replace('phone call logs?', 'text messages?')]:
            with self.assertRaises(ValueError): check_prompt(bad, 'deny')


if __name__ == '__main__':
    unittest.main()

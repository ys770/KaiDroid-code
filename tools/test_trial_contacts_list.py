import json
import unittest
from unittest.mock import patch
from test_trial_contacts_one_permission import Fake, xml as old_xml
from trial_contacts_list import trial, check_prompt


def xml(*args):
    return old_xml(*args).replace('[80,280][159,320]', '[80,290][159,320]')


class ListFake(Fake):
    def __init__(self, wrong_sms=False, failure=None):
        super().__init__(failure=failure)
        self.wrong_sms = wrong_sms

    def __call__(self, label, command):
        if label == 'cleanup-controller-path': return 'package:/data/app/controller/base.apk'
        if label == 'cleanup-controller-hash':
            from trial_contacts_list import CONTROLLER_SHA
            return CONTROLLER_SHA
        if label == 'cleanup-activities': return 'ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)'
        if label.endswith('-xml') and label.startswith('read_'):
            self.calls.append((label, command))
            focus = 'allow' if '-allow-' in label else 'deny'
            question = ('Allow Contacts to send and view SMS messages?' if label.startswith('read_sms')
                        else 'Allow Contacts to access your phone call logs?')
            if self.wrong_sms and label.startswith('read_sms'):
                question = 'Allow Contacts to access files?'
            return xml(focus, question)
        if label in ('read_call_log-state', 'read_sms-state'):
            self.calls.append((label, command))
            return json.dumps(dict(permissions={
                'READ_CALL_LOG': dict(granted=True, flags=2049),
                'READ_SMS': dict(granted=label == 'read_sms-state', flags=2048)}))
        if label == 'people-activity':
            self.calls.append((label, command))
            return 'mResumedActivity: ActivityRecord{123 u0 com.android.contacts/.activities.PeopleActivity t1}'
        if label == 'people-xml':
            self.calls.append((label, command))
            return '<hierarchy><node package="com.android.contacts"/></hierarchy>'
        return super().__call__(label, command)


class ListTests(unittest.TestCase):
    def execute(self, fake, report):
        with patch('trial_contacts_list.smoke', return_value={'baseline_sha256': 'a' * 64}):
            trial(fake, lambda _: None, '/data/local/tmp/test', 'boot', report, settle=lambda _: None)

    def test_two_choices_then_people_observation_and_restore(self):
        fake, report = ListFake(), {}
        self.execute(fake, report)
        self.assertEqual(['READ_CALL_LOG', 'READ_SMS'], report['granted_permissions'])
        self.assertEqual(2, sum(command == 'input keyevent 23' for _, command in fake.calls))
        self.assertTrue(report['people_activity_observed'])
        self.assertTrue(report['restoration_verified'])

    def test_unexpected_second_prompt_stops_and_restores_first_grant(self):
        fake, report = ListFake(wrong_sms=True), {}
        with self.assertRaises(ValueError): self.execute(fake, report)
        self.assertEqual(1, report['choices_attempted'])
        self.assertTrue(report['restoration_verified'])

    def test_second_activation_timeout_preserves_for_process_review(self):
        fake, report = ListFake(failure='read_sms-activate-once'), {}
        with self.assertRaises(TimeoutError): self.execute(fake, report)
        self.assertFalse(report['restoration_verified'])
        self.assertNotIn('restore-state', [label for label, _ in fake.calls])

    def test_cleanup_stops_both_writers_before_restore(self):
        fake, report = ListFake(), {}
        self.execute(fake, report)
        labels = [label for label, _ in fake.calls]
        self.assertLess(labels.index('stop-before-restore'), labels.index('stop-controller-before-restore'))
        self.assertLess(labels.index('stop-controller-before-restore'), labels.index('restore-state'))

    def test_controller_stop_timeout_does_not_restore_or_retry(self):
        fake, report = ListFake(failure='stop-controller-before-restore'), {}
        with self.assertRaises(TimeoutError): self.execute(fake, report)
        labels = [label for label, _ in fake.calls]
        self.assertEqual(1, labels.count('stop-controller-before-restore'))
        self.assertNotIn('restore-state', labels)
        self.assertFalse(report['restoration_verified'])

    def test_live_or_unknown_dialog_and_changed_controller_block_restore(self):
        for target, output in [
                ('cleanup-activities', 'ACTIVITY MANAGER ACTIVITIES GrantPermissionsActivity'),
                ('cleanup-activities', ''),
                ('cleanup-controller-hash', 'wrong'),
                ('cleanup-controller-path', 'package:/system/app/other.apk')]:
            fake, report = ListFake(), {}
            def shell(label, command):
                return output if label == target else fake(label, command)
            with self.assertRaises(ValueError): self.execute(shell, report)
            self.assertFalse(report['restoration_verified'])
            self.assertNotIn('restore-state', [label for label, _ in fake.calls])

    def test_sms_question_must_match_pinned_controller_text(self):
        question = 'Allow Contacts to send and view SMS messages?'
        check_prompt(xml('deny', question), 'deny', question)
        with self.assertRaises(ValueError): check_prompt(xml(), 'deny', question)


if __name__ == '__main__':
    unittest.main()

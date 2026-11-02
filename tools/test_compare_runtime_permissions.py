import unittest

from compare_runtime_permissions import compare, snapshot


BASE = '''Packages:
  Package [com.android.contacts] (abc):
    userId=10073
    User 0: installed=true
      runtime permissions:
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET|GRANTED_BY_DEFAULT]
    User 10: installed=true
      runtime permissions:
        android.permission.READ_CONTACTS: granted=false, flags=[ USER_FIXED]
'''


class PermissionComparisonTest(unittest.TestCase):
    def state(self, text=BASE, user=0):
        return snapshot(text, 'com.android.contacts', user)

    def test_flag_order_does_not_change_state(self):
        self.assertTrue(compare(self.state(), self.state(BASE.replace(
            'USER_SET|GRANTED_BY_DEFAULT', 'GRANTED_BY_DEFAULT|USER_SET')))['runtime_permissions_equal'])

    def test_grant_flag_and_uid_changes_fail(self):
        for old, new in [('granted=true', 'granted=false'), ('USER_SET', 'USER_FIXED'),
                         ('userId=10073', 'userId=10074')]:
            with self.subTest(old=old):
                self.assertFalse(compare(self.state(), self.state(BASE.replace(old, new)))['runtime_permissions_equal'])

    def test_user_isolation(self):
        self.assertFalse(self.state(user=10)['permissions']['android.permission.READ_CONTACTS']['granted'])

    def test_absent_is_not_denied(self):
        denied = self.state(BASE.replace('granted=true', 'granted=false'))
        absent = self.state(BASE.replace('        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET|GRANTED_BY_DEFAULT]\n', ''))
        self.assertFalse(compare(denied, absent)['runtime_permissions_equal'])

    def test_hidden_system_baseline_ignored(self):
        self.assertEqual(self.state(), self.state(BASE + 'Hidden system packages:\n' + BASE))

    def test_invalid_or_incomplete_input_fails(self):
        for text in [BASE + BASE, BASE.replace('flags=[', 'flags=oops['),
                     BASE.replace('runtime permissions:', 'missing:'), '']:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self.state(text)


if __name__ == '__main__':
    unittest.main()

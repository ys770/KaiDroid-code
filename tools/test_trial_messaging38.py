import unittest
from trial_messaging38 import sms_holder, provider_owners, fresh, ORIGINAL, TELEPHONY, PACKAGE, AUTHORITIES


class MessagingGuards(unittest.TestCase):
    def test_sms_role_requires_single_user_and_exact_holder(self):
        good = 'user_id=0\n{\n name=android.app.role.SMS\n holders=com.android.messaging\n}\n'
        self.assertEqual(sms_holder(good), ORIGINAL)
        for bad in (good.replace(ORIGINAL, PACKAGE), good+'user_id=10\n', good+good, good.replace(' holders=', ' unrelated=')):
            with self.assertRaises(ValueError):
                sms_holder(bad)

    def test_provider_parser_and_collision(self):
        text = 'Registered ContentProviders:\n  [settings]:\n    Provider{abc com.android.providers.settings/.SettingsProvider}\n'
        self.assertEqual(provider_owners(text), {'settings':'com.android.providers.settings'})
        fresh({ORIGINAL, TELEPHONY}, text)
        for authority in AUTHORITIES:
            with self.assertRaises(ValueError):
                fresh({ORIGINAL, TELEPHONY}, text.replace('[settings]', '['+authority+']'))
        with self.assertRaises(ValueError):
            fresh({ORIGINAL, TELEPHONY, PACKAGE}, text)
        with self.assertRaises(ValueError):
            provider_owners('permission denied')
        with self.assertRaises(ValueError):
            provider_owners(text+text)


if __name__ == '__main__':
    unittest.main()

import unittest
from contacts_settings_navigation import navigate, empty_state, sort_order, sort_dialog


EMPTY = '''<hierarchy>
<node resource-id="com.android.contacts:id/contact_title" text="Contacts"/>
<node resource-id="com.android.contacts:id/message" text="No contacts"/>
<node text="Settings" package="com.android.contacts" bounds="[159,290][240,320]"/>
<node focused="true" class="android.widget.FrameLayout" package="com.android.contacts" bounds="[0,62][240,290]"/>
</hierarchy>'''


class NavigationTests(unittest.TestCase):
    def execute(self, wrong_activity=False, changed_focus=False, sort_cancel=False, changed_sort=False):
        calls, report = [], {}
        def shell(label, command):
            calls.append(command)
            if label.endswith('-activity'):
                component = '.preference.ContactsPreferenceActivity' if label in ('nav-settings-activity','sort-return-activity') else '.activities.PeopleActivity'
                if wrong_activity: component = '.QuickContactActivity'
                return 'mResumedActivity: ActivityRecord{a com.android.contacts/' + component + ' t1}'
            if label.endswith('-xml'):
                if label == 'sort-dialog-xml':
                    return '<hierarchy><node resource-id="com.android.contacts:id/tv_dialog_title" text="Sort contacts by"/><node resource-id="com.android.contacts:id/lv_photo_source_dialog" focused="true"/><node text="Select" package="com.android.contacts"/></hierarchy>'
                if label in ('nav-settings-xml','sort-return-xml'):
                    return EMPTY.replace('</hierarchy>', '<node text="1.Sort contacts by"/></hierarchy>')
                if changed_focus and label == 'nav-return-xml': return EMPTY.replace('[0,62][240,290]', '[0,63][240,290]')
                return EMPTY
            if label.startswith('sort-preference-'):
                value = '2' if changed_sort and label.endswith('after') else '1'
                return '<map><int name="android.contacts.SORT_ORDER" value="' + value + '"/></map>'
            return ''
        navigate(shell, lambda _: None, '/data/local/tmp/test', report, lambda _: None, sort_cancel=sort_cancel)
        return calls, report

    def test_open_back_only_and_focus_restored(self):
        calls, report = self.execute()
        self.assertEqual(['input keyevent 2', 'input keyevent 4'], [c for c in calls if c.startswith('input ')])
        self.assertTrue(report['empty_state_focus_restored'])

    def test_unexpected_activity_rejected(self):
        with self.assertRaises(ValueError): self.execute(wrong_activity=True)

    def test_changed_return_focus_rejected(self):
        with self.assertRaises(ValueError): self.execute(changed_focus=True)

    def test_nonempty_or_wrong_softkey_rejected(self):
        for bad in [EMPTY.replace('No contacts','Someone'), EMPTY.replace('text="Settings"','text="Call"')]:
            with self.assertRaises(ValueError): empty_state(bad)

    def test_sort_state_is_exact_and_requires_valid_baseline(self):
        self.assertEqual('1', sort_order('<map><int name="android.contacts.SORT_ORDER" value="1"/></map>'))
        for value in ['<map/>', '<map><int name="android.contacts.SORT_ORDER" value="9"/></map>']:
            with self.assertRaises(ValueError): sort_order(value)

    def test_sort_cancel_never_activates_an_option(self):
        calls, report = self.execute(sort_cancel=True)
        self.assertEqual(['input keyevent 2','input keyevent 8','input keyevent 4','input keyevent 4'], [c for c in calls if c.startswith('input ')])
        self.assertTrue(report['sort_cancel_preserved_preference'])

    def test_changed_sort_state_is_failure(self):
        with self.assertRaises(ValueError): self.execute(sort_cancel=True, changed_sort=True)

    def test_sort_dialog_requires_title_focus_and_select(self):
        xml = '''<hierarchy>
<node resource-id="com.android.contacts:id/tv_dialog_title" text="Sort contacts by"/>
<node resource-id="com.android.contacts:id/lv_photo_source_dialog" focused="true"/>
<node package="com.android.contacts" text="Select"/>
</hierarchy>'''
        sort_dialog(xml)
        for bad in [xml.replace('Sort contacts by','Import'), xml.replace('focused="true"','focused="false"'), xml.replace('text="Select"','text="Save"')]:
            with self.assertRaises(ValueError): sort_dialog(bad)


if __name__ == '__main__':
    unittest.main()

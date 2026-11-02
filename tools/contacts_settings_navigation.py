"""Bounded Settings open/back observation; no preference activation."""
import re
import xml.etree.ElementTree as ET


def empty_state(xml):
    nodes = list(ET.fromstring(xml).iter('node'))
    for resource, text in [('contact_title', 'Contacts'), ('message', 'No contacts')]:
        if not any(n.get('resource-id') == 'com.android.contacts:id/' + resource
                   and n.get('text') == text for n in nodes):
            raise ValueError('Expected Contacts empty state')
    if not any(n.get('text') == 'Settings' and n.get('bounds') == '[159,290][240,320]'
               and n.get('package') == 'com.android.contacts' for n in nodes):
        raise ValueError('Expected Settings right soft key')
    focused = [n for n in nodes if n.get('focused') == 'true']
    if len(focused) != 1:
        raise ValueError('Ambiguous empty-state focus')
    return {key: focused[0].get(key, '') for key in ('resource-id', 'class', 'bounds', 'package')}


def resumed(text, component):
    if not re.search(r'mResumedActivity:.*com\.android\.contacts/(?:com\.android\.contacts)?'
                     + re.escape(component) + r'(?:\s|})', text):
        raise ValueError('Unexpected resumed activity')


def sort_order(xml):
    root = ET.fromstring(xml)
    values = [n.get('value') for n in root.findall('int') if n.get('name') == 'android.contacts.SORT_ORDER']
    if len(values) != 1 or values[0] not in ('1', '2'):
        raise ValueError('Missing/invalid persisted sort-order baseline')
    return values[0]


def sort_dialog(xml):
    nodes = list(ET.fromstring(xml).iter('node'))
    if not any(n.get('resource-id') == 'com.android.contacts:id/tv_dialog_title'
               and n.get('text') == 'Sort contacts by' for n in nodes):
        raise ValueError('Unexpected sort dialog title')
    if not any(n.get('resource-id') == 'com.android.contacts:id/lv_photo_source_dialog'
               and n.get('focused') == 'true' for n in nodes):
        raise ValueError('Expected sort dialog list focus')
    if not any(n.get('text') == 'Select' and n.get('package') == 'com.android.contacts' for n in nodes):
        raise ValueError('Missing dialog Select label')


def navigate(shell, screen, remote, report, settle, sort_cancel=False):
    def hierarchy(stage):
        shell(stage + '-dump', 'uiautomator dump ' + remote + '/navigation.xml')
        result = shell(stage + '-xml', 'cat ' + remote + '/navigation.xml')
        screen(stage)
        return result
    resumed(shell('nav-before-activity', 'dumpsys activity activities'), '.activities.PeopleActivity')
    before = empty_state(hierarchy('nav-before'))
    shell('nav-open-settings-once', 'input keyevent 2')
    settle(3)
    resumed(shell('nav-settings-activity', 'dumpsys activity activities'), '.preference.ContactsPreferenceActivity')
    settings = hierarchy('nav-settings')
    nodes = list(ET.fromstring(settings).iter('node'))
    if not any(n.get('package') == 'com.android.contacts' for n in nodes):
        raise ValueError('Missing Contacts settings UI')
    report['settings_screen_observed'] = True
    if sort_cancel:
        if not any(n.get('text') == '1.Sort contacts by' for n in nodes):
            raise ValueError('Sort preference not present')
        pref_command = 'cat /data/user/0/com.android.contacts/shared_prefs/com.android.contacts.xml'
        original_sort = sort_order(shell('sort-preference-before', pref_command))
        report['sort_cancel_preserved_preference'] = False
        # Known numeric shortcut opens the dialog; never activate a dialog item.
        shell('sort-open-once', 'input keyevent 8')
        settle(2)
        sort_dialog(hierarchy('sort-dialog'))
        report['sort_dialog_observed'] = True
        shell('sort-cancel-once', 'input keyevent 4')
        settle(2)
        resumed(shell('sort-return-activity', 'dumpsys activity activities'), '.preference.ContactsPreferenceActivity')
        returned = hierarchy('sort-return')
        if any(n.get('resource-id') == 'com.android.contacts:id/tv_dialog_title'
               for n in ET.fromstring(returned).iter('node')):
            raise ValueError('Sort dialog remained after Back')
        if sort_order(shell('sort-preference-after', pref_command)) != original_sort:
            raise ValueError('Sort preference changed on cancellation')
        report['sort_cancel_preserved_preference'] = True
    shell('nav-back-once', 'input keyevent 4')
    settle(2)
    resumed(shell('nav-return-activity', 'dumpsys activity activities'), '.activities.PeopleActivity')
    after = empty_state(hierarchy('nav-return'))
    report['settings_back_return_verified'] = True
    report['empty_state_focus_restored'] = before == after
    if before != after:
        raise ValueError('Empty-state focus changed after Settings return')

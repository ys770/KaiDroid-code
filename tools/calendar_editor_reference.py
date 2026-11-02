"""Calendar's observed unsaved-editor route and strict donor comparison.

This module performs no phone operations. A transition is permitted only after
observing its source capture; dialog selection, Save and text entry have no edge.
Geometry and values remain separate from navigation so an unmatched date or
viewport cannot silently become a parity pass.
"""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / 'docs/evidence/tcl-app-editors-reference04.json'
PACKAGE = 'com.android.calendar'
PREFIX = PACKAGE + ':id/'
FIELDS = ('title', 'location', 'is_all_day', 'start_date', 'start_time',
          'end_date', 'end_time', 'rrule', 'timezone_button',
          'event_reminder', 'description')
# Names are retained verbatim from the acquisition receipt. The first capture
# called reminder-focus is actually timezone_button; focus02 is the reminder.
FOCUS_NAMES = ('new-event', 'location-focus', 'all-day-focus',
               'start-date-focus', 'start-time-focus', 'end-date-focus',
               'end-time-focus', 'repeat-focus', 'reminder-focus',
               'reminder-focus02', 'notes-focus')
PICKERS = {
    'start_date': ('start-date', 'month_select'),
    'start_time': ('start-time', 'tv_hour'),
    'end_date': ('end-date', 'month_select'),
    'end_time': ('end-time', 'tv_hour'),
    'rrule': ('repeat', 'repeat_list'),
    'timezone_button': ('timezone', 'list'),
    'event_reminder': ('event-reminder', 'settings_reminder_lv'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def nodes(xml):
    root = ET.fromstring(xml)
    require(root.tag == 'hierarchy', 'Complete hierarchy required')
    result = list(root.iter('node'))
    require(result and all(n.get('package') == PACKAGE for n in result),
            'Calendar alone must own the hierarchy')
    return result


def focused_id(xml):
    focused = [n for n in nodes(xml) if n.get('focused') == 'true']
    require(len(focused) == 1, 'Exactly one focused node required')
    return focused[0].get('resource-id', '')


def plan():
    """Return only key edges actually captured on the identified original TCL."""
    result = []
    for index, (field, name) in enumerate(zip(FIELDS, FOCUS_NAMES)):
        source = 'calendar-' + name
        if field in PICKERS:
            stem, unused = PICKERS[field]
            dialog = 'calendar-' + stem + '-dialog'
            back = 'calendar-' + stem + '-back'
            result.extend([(source, 23, dialog), (dialog, 4, back)])
            source = back
        if index + 1 < len(FIELDS):
            result.append((source, 20, 'calendar-' + FOCUS_NAMES[index + 1]))
        else:
            result.append((source, 4, 'calendar-new-event-back'))
    return result


def references():
    receipt = json.loads(RECEIPT.read_text(encoding='utf-8'))
    require(receipt['apk_sha256'][PACKAGE] ==
            'bb2c27d93c666a548f84d388c57b70551821fdf72404c1756d221c219ee95168',
            'Original Calendar APK binding changed')
    rows = {r['capture']: r for r in receipt['states']
            if r['capture'].startswith('calendar-')}
    expected = {'calendar-new-event'}
    for source, key, target in plan():
        expected.update((source, target))
    require(set(rows) == expected, 'Unexpected Calendar reference membership')
    result = {}
    for name, row in rows.items():
        for kind in ('png', 'xml'):
            path = ROOT / row[kind]
            path.resolve().relative_to((ROOT / 'docs/screenshots').resolve())
            require(hashlib.sha256(path.read_bytes()).hexdigest() ==
                    row[kind + '_sha256'], 'Reference hash changed: ' + name)
        result[name] = (ROOT / row['xml']).read_text(encoding='utf-8')
    # Each target receipt documents the action from the preceding capture.
    for source, key, target in plan():
        require(rows[target]['actions'] == ['input keyevent ' + str(key)],
                'Transition is not backed by the original action receipt')
    return result


def observed_kind(xml):
    ns = nodes(xml)
    focus = focused_id(xml)
    ids = {n.get('resource-id') for n in ns}
    if PREFIX + 'edit_event' in ids:
        require(focus in {PREFIX + f for f in FIELDS},
                'Unexpected editor focus')
        titles = [n for n in ns if n.get('resource-id') == PREFIX + 'title']
        require(not titles or (len(titles) == 1 and titles[0].get('text') == ''),
                'Nonblank title; this route does not own a saved/user draft')
        return 'editor', focus
    if any(PREFIX + value[1] == focus for value in PICKERS.values()):
        return 'picker', focus
    labels = {n.get('text') for n in ns}
    require('Add event' in labels and 'Options' in labels,
            'Neither editor, observed picker nor Calendar landing state')
    return 'calendar', focus


def comparison(reference_xml, candidate_xml):
    """Report exact app structure, text/selection, bounds and footer separately."""
    def inventory(xml, footer):
        result = []
        for n in nodes(xml):
            rid = n.get('resource-id', '')
            is_footer = rid.startswith('android:id/menu_') or rid == 'android:id/decor_menu_bar'
            if is_footer != footer:
                continue
            # Resource-bearing app nodes include clipped labels and containers.
            if not footer and not rid.startswith(PREFIX):
                continue
            result.append({k: n.get(k, '') for k in
                           ('resource-id', 'class', 'text', 'checked', 'focused', 'bounds')})
        return result
    before = inventory(reference_xml, False)
    after = inventory(candidate_xml, False)
    def stripped(rows, omit):
        return [{k: v for k, v in row.items() if k not in omit} for row in rows]
    return dict(
        donor_kind=observed_kind(reference_xml),
        candidate_kind=observed_kind(candidate_xml),
        app_resource_nodes_exact=before == after,
        app_structure_values_focus_exact=stripped(before, ('bounds',)) == stripped(after, ('bounds',)),
        app_geometry_structure_exact=stripped(before, ('text', 'checked', 'focused')) ==
                                     stripped(after, ('text', 'checked', 'focused')),
        footer_nodes_exact=inventory(reference_xml, True) == inventory(candidate_xml, True),
        footer_exception='Kyocera soft keys; differences reported separately',
        screenshots_compared=False, physical_keys=False, full_parity=False)


def authorize(source, key, target, current_xml, corpus):
    require((source, key, target) in plan(), 'Unobserved or selecting/saving transition')
    reference = corpus[source]
    require(observed_kind(reference) == observed_kind(current_xml),
            'Observed screen/focus differs; do not send the next key')
    # Match all visible app text and selection as well as focus. Bounds may be
    # a framework defect to measure, but changed draft/default values must stop.
    require(comparison(reference, current_xml)['app_structure_values_focus_exact'],
            'App fields/values/selection differ; matching starting state required')
    return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True)
    parser.add_argument('--candidate', required=True, type=Path)
    args = parser.parse_args()
    corpus = references()
    require(args.capture in corpus, 'Unknown donor capture')
    print(json.dumps(comparison(corpus[args.capture], args.candidate.read_text(encoding='utf-8')), indent=2))


if __name__ == '__main__':
    main()

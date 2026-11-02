"""Coordinated image59 unsaved Calendar route; no Save, text or provider writes.

Requires a fresh exclusive Nokia lease. A later image requires a reviewed source
rebind; do not bypass the image guard. Observation/action timeouts are terminal.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import time
import uuid

import calendar_editor_reference as reference
import trial_tcl_media_navigation_image59 as transport
from image59_home_observer import observe

APK = '971e5f9d32ab5b4f8e616a6c5d44073d66a000631cd47c353abf5ca4bc540b0d'
PROVIDER = 'com.android.providers.calendar'
PROVIDER_APK = '255247f97c0208b9504e3eadbca63b192b1c35f18e3bc768bda461ac7d5b0dbc'
PACKAGE = reference.PACKAGE
COMPONENT = PACKAGE + '/.AllInOneActivity'
TRANSPORT_SHA = '273743dd8a5d23cf16d490e12d945eea8ee47cfb8a73138fb60bf8a79a5317b4'
# 2026-10-26 08:00 America/New_York; a VIEW selection, not a system-clock write.
BEGIN = 1793016000000
TABLES = ('calendars', 'events', 'reminders', 'calendar_alerts')


class Trial(transport.Trial):
    def __init__(self, args):
        reference.require(hashlib.sha256(Path(transport.__file__).read_bytes()).hexdigest() == TRANSPORT_SHA,
                          'Reviewed transport source changed')
        self.corpus = reference.references()
        self.a = args
        self.seq = 0
        self.ambiguous = False
        self.current = None
        self.before = None
        self.report = dict(image=59, boot=args.boot, passed=False,
                           scope='Original Calendar unsaved editor and seven picker cancellations',
                           actions=[], save_requested=False, text_requested=False,
                           provider_writes_requested=False, full_parity=False, physical_keys=False)
        args.output.mkdir(parents=True, exist_ok=False)

    def installed(self, package, expected):
        path = self.shell('path-' + package, 'pm path ' + package)
        reference.require(re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk', path), 'Ambiguous APK path')
        reference.require(self.shell('hash-' + package, 'sha256sum ' + shlex.quote(path[8:])).split()[0] == expected,
                          'Active package is not the reviewed variant: ' + package)

    def state(self, label):
        settings = {}
        for key in ('default_input_method', 'enabled_input_methods', 'selected_input_method_subtype',
                    'input_methods_subtype_history', 'show_ime_with_hard_keyboard'):
            settings[key] = self.shell(label + '-' + key, 'settings get secure ' + key)
        settings['bluetooth_on'] = self.shell(label + '-bt', 'settings get global bluetooth_on')
        files = {}
        for package in (PACKAGE, PROVIDER):
            files[package] = sorted(self.shell(label + '-files-' + package,
                'for d in /data/user/0/' + package + ' /data/user_de/0/' + package +
                '; do if test -d "$d"; then find "$d" -type f -exec sha256sum {} +; fi; done').splitlines())
        rows = {}
        for table in TABLES + ('events?caller_is_syncadapter=true',):
            raw = self.shell(label + '-rows-' + table.split('?')[0] + ('-sync' if '?' in table else ''),
                             'content query --uri ' + shlex.quote('content://com.android.calendar/' + table) +
                             " --sort '_id ASC'")
            reference.require(raw == 'No result found.' or raw.startswith('Row: '), 'Provider query not conclusive')
            rows[table] = hashlib.sha256(raw.encode()).hexdigest()
        permissions = transport.runtime_state(self.shell(label + '-package', 'dumpsys package ' + PACKAGE), PACKAGE)
        reference.require(permissions['uid'] == 10085, 'Calendar installed UID changed')
        return dict(settings=settings, appfiles=files, provider_rows_sha256=rows, permissions=permissions)

    def capture(self, name):
        self.identity()
        owner = self.focus()
        reference.require(owner[1].startswith(PACKAGE + '/'), 'Calendar no longer owns the window')
        remote = '/data/local/tmp/kaidroid-calendar59-' + uuid.uuid4().hex + '.xml'
        self.shell(name + '-dump', 'uiautomator dump ' + shlex.quote(remote))
        xml = self.shell(name + '-xml', 'cat ' + shlex.quote(remote))
        png = self.run(name + '-png', ['exec-out', 'screencap', '-p'])
        reference.require(png[:8] == b'\x89PNG\r\n\x1a\n' and struct.unpack('>II', png[16:24]) == (240, 320), 'Invalid screenshot')
        reference.require(self.focus() == owner, 'Capture ownership changed')
        (self.a.output / (name + '.xml')).write_text(xml, encoding='utf-8')
        (self.a.output / (name + '.png')).write_bytes(png)
        self.current = dict(name=name, owner=owner, xml=xml)
        if name in self.corpus:
            comparison = reference.comparison(self.corpus[name], xml)
            self.report.setdefault('comparisons', {})[name] = comparison
        else:
            reference.require(reference.observed_kind(xml)[0] == 'calendar', 'Expected Calendar landing screen')
        self.save()
        return xml

    def action(self, code):
        reference.require(not self.ambiguous and self.current, 'No proven current screen')
        name = self.current['name']
        if code == 1:
            reference.require(name == 'calendar-entry' and reference.observed_kind(self.current['xml'])[0] == 'calendar',
                              'Add event LSK only at the observed landing screen')
        elif code == 3:
            reference.require(name == 'calendar-new-event-back' and reference.observed_kind(self.current['xml'])[0] == 'calendar',
                              'Home only after the observed editor cancellation')
        else:
            edges = [(s, k, t) for s, k, t in reference.plan() if s == name and k == code]
            reference.require(len(edges) == 1, 'No observed key edge; no Save/picker choice')
            reference.authorize(*edges[0], self.current['xml'], self.corpus)
        self.identity()
        reference.require(self.focus() == self.current['owner'], 'Input ownership changed')
        self.shell('key-' + str(code), 'input keyevent ' + str(code), True)
        time.sleep(1)

    def execute(self):
        try:
            self.identity()
            home = self.focus()
            reference.require(home[1] == transport.HOME, 'Start at Launcher')
            self.report['before_home'] = home
            hashes = self.shell('core-hashes', 'sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
            reference.require([line.split()[0] for line in hashes.splitlines()] ==
                              [transport.FRAMEWORK, transport.SYSTEMUI], 'Core hashes differ')
            self.installed(PACKAGE, APK)
            self.installed(PROVIDER, PROVIDER_APK)
            activities = self.shell('activities-before', 'dumpsys activity activities')
            services = self.shell('services-before', 'dumpsys activity services ' + PACKAGE)
            reference.require(not re.search(r'ActivityRecord\{[^\n]*' + re.escape(PACKAGE) + '/', activities), 'Existing Calendar activity; do not duplicate')
            reference.require(not re.search(r'ServiceRecord\{[^\n]*' + re.escape(PACKAGE), services), 'Existing Calendar service')
            self.before = self.state('before')
            self.report['before_state'] = self.before
            result = self.shell('launch', 'am start -W -n ' + COMPONENT +
                                ' -a android.intent.action.VIEW --el beginTime ' + str(BEGIN), True)
            reference.require(re.search(r'^Status:\s*ok\s*$', result, re.M), 'Launch result ambiguous')
            self.capture('calendar-entry')
            # LSK is allowed once only on the captured landing screen.
            self.action(1)
            self.capture('calendar-new-event')
            for source, key, target in reference.plan():
                reference.require(self.current['name'] == source, 'Route order changed')
                reference.authorize(source, key, target, self.current['xml'], self.corpus)
                self.action(key)
                self.capture(target)
            self.report['unsaved_route_completed'] = True
            reference.require(reference.observed_kind(self.current['xml'])[0] == 'calendar', 'Editor did not cancel')
            self.action(3)
            def read():
                self.identity()
                return self.shell('home-window', 'dumpsys window')
            self.report['home_observation'] = observe(read, home)
            reference.require(self.report['home_observation']['home_component_observed'], 'Home not observed')
            after = self.state('after')
            self.report['after_state'] = after
            self.report['state_equal'] = after == self.before
            reference.require(after == self.before, 'App/provider/permission/settings preservation unproven')
            self.report['passed'] = True
        except Exception as error:
            self.report['failure'] = repr(error)
            self.report['further_input_deferred'] = True
        finally:
            self.report['command_state_ambiguous'] = self.ambiguous
            self.save()
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--boot', required=True, type=lambda value: str(uuid.UUID(value)))
    parser.add_argument('--output', required=True, type=Path)
    report = Trial(parser.parse_args()).execute()
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Calendar route failed; preserve evidence and do not retry blindly')


if __name__ == '__main__':
    main()

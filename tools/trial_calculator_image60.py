"""Leased original Calculator arithmetic/clear/error counterpart on exact60.

No Save, settings/permission writes, data clear, force-stop or blind retry.
Only a matching zero-entry calculation is owned. Full pixels stay separate
from bounded functional acceptance; physical keys remain unverified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import uuid

import calculator_reference as reference
import trial_tcl_media_navigation_image59 as transport
from image60_app_guard import Image60Guard
from image59_home_observer import observe

PACKAGE = reference.PACKAGE
COMPONENT = PACKAGE + '/com.android.calculator2.Calculator'
APK = '88b33864b35de46509dc3efdd47b8ca315db8c8f1667ab64ec55f07b6b695e53'
TRANSPORT_SHA = '273743dd8a5d23cf16d490e12d945eea8ee47cfb8a73138fb60bf8a79a5317b4'
SHADERS = {base + PACKAGE + '/code_cache/' + name
           for base in ('/data/user/0/', '/data/user_de/0/')
           for name in ('com.android.opengl.shaders_cache', 'com.android.skia.shaders_cache')}


def file_inventory(lines):
    result = {}
    for line in lines:
        match = re.fullmatch(r'([a-f0-9]{64})  (/(?:data/user|data/user_de)/0/com\.android\.calculator2/.+)', line)
        reference.require(match is not None and match[2] not in result, 'Ambiguous Calculator file inventory')
        result[match[2]] = match[1]
    return result


def preservation(before, after):
    old, new = file_inventory(before['files']), file_inventory(after['files'])
    changed = {name for name in set(old) | set(new) if old.get(name) != new.get(name)}
    # Existing cache entries may change, but additions/removals remain failures.
    cache_only = changed <= SHADERS and set(old) == set(new)
    stable = before['settings'] == after['settings'] and before['permissions'] == after['permissions']
    return dict(settings_and_runtime_permissions_equal=stable, appfiles_exact=old == new,
                only_existing_shader_cache_changes=bool(changed) and cache_only,
                changed_files=[dict(path=n, before=old.get(n), after=new.get(n)) for n in sorted(changed)],
                scoped_preservation=stable and (not changed or cache_only), appops_verified=False)


class Trial(Image60Guard, transport.Trial):
    def __init__(self, args):
        reference.require(hashlib.sha256(Path(transport.__file__).read_bytes()).hexdigest() == TRANSPORT_SHA,
                          'Reviewed transport source changed')
        self.a = args
        self.seq = 0
        self.ambiguous = False
        self.current = None
        self.receipt, self.corpus = reference.references()
        self.report = dict(image=60, boot=args.boot, passed=False, actions=[],
                           scope='Original eleven-key Calculator arithmetic/clear/error route and Back',
                           save_requested=False, settings_writes=False, permission_choices=False,
                           app_data_clear_requested=False, physical_keys=False, full_parity=False)
        args.output.mkdir(parents=True, exist_ok=False)

    def state(self, label):
        settings = {key: self.shell(label + '-' + key, 'settings get secure ' + key)
                    for key in ('default_input_method', 'enabled_input_methods', 'selected_input_method_subtype',
                                'input_methods_subtype_history', 'show_ime_with_hard_keyboard')}
        settings['bluetooth_on'] = self.shell(label + '-bt', 'settings get global bluetooth_on')
        package = self.shell(label + '-package', 'dumpsys package ' + PACKAGE)
        block = transport.package_block(package, PACKAGE)
        reference.require(len(re.findall(r'\bversionCode=30\b', block)) == 1, 'Unexpected Calculator version')
        permissions = transport.runtime_state(package, PACKAGE)
        reference.require(10000 <= permissions['uid'] < 20000 and not permissions['permissions'],
                          'Unexpected Calculator app UID or runtime permissions')
        files = sorted(self.shell(label + '-files', 'for d in /data/user/0/' + PACKAGE + ' /data/user_de/0/' + PACKAGE +
            '; do if test -d "$d"; then find "$d" -type f -exec sha256sum {} +; fi; done').splitlines())
        file_inventory(files)
        return dict(settings=settings, permissions=permissions, files=files)

    def capture(self, name, label=None):
        label = label or name
        self.identity()
        owner = self.focus()
        reference.require(owner[1] == COMPONENT, 'Calculator no longer owns input')
        remote = '/data/local/tmp/kaidroid-calculator60-' + uuid.uuid4().hex + '.xml'
        self.shell(label + '-dump', 'uiautomator dump ' + shlex.quote(remote))
        xml = self.shell(label + '-xml', 'cat ' + shlex.quote(remote))
        png = self.run(label + '-png', ['exec-out', 'screencap', '-p'])
        reference.require(png[:8] == b'\x89PNG\r\n\x1a\n' and struct.unpack('>II', png[16:24]) == (240, 320), 'Invalid screenshot')
        reference.require(self.focus() == owner, 'Capture ownership changed')
        (self.a.output / (label + '.xml')).write_text(xml, encoding='utf-8')
        (self.a.output / (label + '.png')).write_bytes(png)
        self.report.setdefault('comparisons', {})[label] = reference.compare(self.corpus[name], xml)
        self.current = dict(name=name, owner=owner, xml=xml)
        self.save()

    def key(self, code, target):
        reference.require(not self.ambiguous and self.current, 'No unambiguous owned Calculator state')
        source = self.current['name']
        back = (source, code, target) == ('calculator-error-clear-all', 4, 'home')
        reference.require(back or (source, code, target) in reference.plan(), 'Key outside the observed route')
        self.capture(source, 'before-' + target)
        if back:
            reference.require(reference.compare(self.corpus[source], self.current['xml'])['expression_and_structure_exact'], 'Final zero state changed')
        else:
            reference.authorize(source, code, target, self.current['xml'])
        self.identity()
        reference.require(self.focus() == self.current['owner'], 'Input ownership changed')
        self.shell('key-' + str(code), 'input keyevent ' + str(code), True)

    def pixels(self):
        from compare_ui_pixels import compare
        by_name = {r['capture']: r for r in self.receipt['captures']}
        results = {}
        for name in self.corpus:
            results[name] = compare(reference.ROOT / by_name[name]['png'], self.a.output / (name + '.png'),
                                    self.a.output / ('pixels-' + name),
                                    dict(status=[0, 0, 240, 24], app_body=[0, 24, 240, 290], footer=[0, 290, 240, 320]))
        self.report['pixel_comparisons'] = results
        self.report['all_app_body_pixels_exact'] = all(r['regions']['app_body']['changed_pixels'] == 0 for r in results.values())
        self.report['all_full_frames_exact'] = all(r['exact_pixel_match'] for r in results.values())

    def execute(self):
        try:
            self.identity()
            home = self.focus()
            reference.require(home[1] == transport.HOME, 'Start at Launcher')
            self.report['before_home'] = home
            hashes = self.shell('core-hashes', 'sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
            reference.require([line.split()[0] for line in hashes.splitlines()] == [transport.FRAMEWORK, transport.SYSTEMUI], 'Core bytes differ')
            path = self.shell('apk-path', 'pm path ' + PACKAGE)
            reference.require(re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk', path), 'Ambiguous Calculator APK')
            reference.require(self.shell('apk-hash', 'sha256sum ' + shlex.quote(path[8:])).split()[0] == APK, 'Not the original installed Calculator variant')
            activities = self.shell('activities-before', 'dumpsys activity activities')
            reference.require(not re.search(r'ActivityRecord\{[^\n]*' + re.escape(PACKAGE) + '/', activities), 'Existing Calculator activity; do not duplicate')
            before = self.state('before')
            self.report['before_state'] = before
            launch = self.shell('launch', 'am start -W -n ' + COMPONENT, True)
            reference.require(re.search(r'^Status:\s*ok\s*$', launch, re.M), 'Launch not definite success')
            self.capture('calculator-entry')
            for source, code, target in reference.plan():
                reference.require(self.current['name'] == source, 'Route order changed')
                self.key(code, target)
                self.capture(target)
            self.report['bounded_functional_route_completed'] = True
            self.key(4, 'home')
            def read():
                self.identity()
                return self.shell('home-window', 'dumpsys window')
            self.report['home_observation'] = observe(read, home)
            reference.require(self.report['home_observation']['home_component_observed'], 'Back did not restore prior Home component')
            after = self.state('after')
            self.report['after_state'] = after
            self.report['preservation'] = preservation(before, after)
            reference.require(self.report['preservation']['scoped_preservation'], 'Calculator/settings/runtime state preservation unproven')
            self.report['passed'] = True
        except Exception as error:
            self.report.update(failure=repr(error), further_input_deferred=True)
        finally:
            self.report['command_state_ambiguous'] = self.ambiguous
            self.save()
        if self.report['passed']:
            try:
                self.pixels()
            except Exception as error:
                self.report['offline_pixel_analysis_failure'] = repr(error)
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
        raise RuntimeError('Calculator route failed; preserve evidence and do not blindly retry')


if __name__ == '__main__':
    main()

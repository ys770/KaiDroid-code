"""Build the original API-30 keypad diagnostic APK locally; never installs it."""
import argparse
import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path
from audit_dex_references import read_dex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', required=True, type=Path)
    parser.add_argument('--jdk', required=True, type=Path)
    parser.add_argument('--build-tools', default='35.0.0')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--diagnostic-keystore', type=Path,
                        help='Reuse an existing local diagnostic key for retained-data updates')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'tests/inputprobe'
    out = args.output.resolve()
    if out.exists():
        raise ValueError('Use a new output directory')
    sdk = args.sdk.resolve()
    jdk = args.jdk.resolve()
    bt = sdk / 'build-tools' / args.build_tools
    android = sdk / 'platforms/android-30/android.jar'
    executable = '.exe' if os.name == 'nt' else ''
    env = os.environ.copy()
    env['JAVA_HOME'] = str(jdk)
    env['PATH'] = str(jdk / 'bin') + os.pathsep + env.get('PATH', '')
    out.mkdir(parents=True)
    commands = []

    def run(argv):
        args_list = [str(a) for a in argv]
        commands.append(args_list)
        result = subprocess.run(args_list, env=env, capture_output=True, text=True, timeout=120)
        with (out / 'build.log').open('a', encoding='utf-8') as log:
            log.write(json.dumps(args_list) + '\n' + result.stdout + result.stderr)
        result.check_returncode()

    classes = out / 'classes'
    dex = out / 'dex'
    classes.mkdir()
    dex.mkdir()
    resources = root / 'framework/core/res/res'
    generated_resources = out / 'resource-java'
    generated_resources.mkdir()
    unsigned = out / 'unsigned.apk'
    test_resources = source / 'res'
    resource_args = ['-S', test_resources] if test_resources.exists() else []
    run([bt / ('aapt' + executable), 'package', '-f', '-m', '--auto-add-overlay',
         '-M', source / 'AndroidManifest.xml', '-S', resources,
         *resource_args,
         '-I', android, '-J', generated_resources, '-F', unsigned])
    sources = sorted(source.glob('src/**/*.java'))
    # Exercise the exact production callback-handled branch with real MenuBar.
    from prepare_window_patch import HANDLED_KEY_BLOCK
    bridge = out / 'WindowCallbackBridge.java'
    bridge.write_text('package org.kaidroid.inputprobe;\n'
        'import android.view.KeyEvent;\n'
        'import org.kaidroid.inputprobe.compat.widget.MenuBar;\n'
        'final class WindowCallbackBridge { static boolean dispatch(MenuBar mKaiDroidMenuBar, '
        'KeyEvent event, boolean handled) {\n' + HANDLED_KEY_BLOCK + '\n'
        'return event.getAction() == KeyEvent.ACTION_DOWN ? mKaiDroidMenuBar.onKeyDown(event.getKeyCode(), event) '
        ': mKaiDroidMenuBar.onKeyUp(event.getKeyCode(), event); }}\n')
    sources.append(bridge)

    # MarqueeTextView needs methods added to the real boot TextView. An SDK
    # relocation cannot test that integration; do not replace those calls with stubs.
    # Internal resolver presentation has its own dedicated probe. This probe
    # relocates only android.app/widget; it cannot silently validate that host.
    framework_sources = sorted(p for p in (root / 'framework/core/java').rglob('*.java')
                               if p.name != 'MarqueeTextView.java'
                               and p.relative_to(root / 'framework/core/java').parts[0]=='android')
    relocated = []
    for original in framework_sources:
        relative = original.relative_to(root / 'framework/core/java')
        generated = out / 'relocated' / relative
        generated.parent.mkdir(parents=True, exist_ok=True)
        text = original.read_text()
        package = 'android.' + relative.parts[1]
        text = text.replace('package ' + package + ';',
                            'package org.kaidroid.inputprobe.compat.' + relative.parts[1]
                            + ';\nimport ' + package + '.*;', 1)
        for name in ('MenuBar', 'TctDialogMessage'):
            text = text.replace('import android.widget.' + name + ';',
                                'import org.kaidroid.inputprobe.compat.widget.' + name + ';')
        text = text.replace('com.android.internal.R.style.TctDialogStyle',
                            'org.kaidroid.inputprobe.R.style.TctDialogStyle')
        text = text.replace('import com.android.internal.R;',
                            'import org.kaidroid.inputprobe.R;')
        generated.write_text(text)
        relocated.append(generated)
    run([jdk / 'bin' / ('javac' + executable), '--release', '8',
         '-classpath', android, '-d', classes, *sources, *relocated,
         *sorted(generated_resources.rglob('*.java'))])
    run([jdk / 'bin' / ('java' + executable), '-cp', bt / 'lib/d8.jar',
         'com.android.tools.r8.D8', '--min-api', '30', '--lib', android,
         '--output', dex, *sorted(classes.rglob('*.class'))])
    refs, definitions, _, _ = read_dex((dex / 'classes.dex').read_bytes())
    required = {'Lorg/kaidroid/inputprobe/compat/widget/MenuBar;',
                'Lorg/kaidroid/inputprobe/compat/widget/TitleEditText;',
                'Lorg/kaidroid/inputprobe/compat/widget/KeypadSoftkeyBar;',
                'Lorg/kaidroid/inputprobe/compat/widget/KeypadSoftkeyState;',
                'Lorg/kaidroid/inputprobe/compat/widget/TctDialogMessage;',
                'Lorg/kaidroid/inputprobe/compat/app/TctDialog;'}
    forbidden = {'Landroid/widget/MenuBar;', 'Landroid/widget/TctDialogMessage;',
                 'Landroid/widget/TitleEditText;', 'Lcom/android/internal/R$styleable;',
                 'Landroid/widget/KeypadSoftkeyBar;', 'Landroid/widget/KeypadSoftkeyState;',
                 'Landroid/app/TctDialog;', 'Lcom/android/internal/R$style;'}
    if not required <= definitions or forbidden & refs:
        raise ValueError('Framework test isolation failed')
    with zipfile.ZipFile(unsigned, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    aligned = out / 'aligned.apk'
    run([bt / ('zipalign' + executable), '-f', '4', unsigned, aligned])
    key = args.diagnostic_keystore.resolve(strict=True) if args.diagnostic_keystore else out / 'diagnostic-only.p12'
    if not args.diagnostic_keystore:
        run([jdk / 'bin' / ('keytool' + executable), '-genkeypair', '-keystore', key,
             '-storepass', 'android', '-keypass', 'android', '-alias', 'diagnostic',
             '-dname', 'CN=KaiDroid Local Diagnostic', '-keyalg', 'RSA', '-keysize', '2048',
             '-validity', '3650', '-noprompt'])
    apk = out / 'kaidroid-input-probe.apk'
    signer = [jdk / 'bin' / ('java' + executable), '-jar', bt / 'lib/apksigner.jar']
    run([*signer, 'sign', '--ks', key, '--ks-pass', 'pass:android', '--key-pass',
         'pass:android', '--out', apk, aligned])
    run([*signer, 'verify', '--verbose', '--print-certs', apk])
    run([bt / ('aapt' + executable), 'dump', 'badging', apk])
    inputs = [source / 'AndroidManifest.xml', *sources, *framework_sources,
              *sorted(p for p in test_resources.rglob('*') if p.is_file()),
              *sorted(p for p in resources.rglob('*') if p.is_file()), Path(__file__).resolve(), root / 'tools/prepare_window_patch.py']
    report = {'scope': 'Compiled and signature-verified only; not installed or UI-tested',
              'excluded_platform_integration': ['MarqueeTextView requires patched boot TextView',
                  'Internal resolver presentation uses its dedicated resolver probe'],
              'api': 30, 'build_tools': args.build_tools,
              'existing_diagnostic_key_reused': bool(args.diagnostic_keystore),
              'test_relocation': 'android.app/widget original classes -> org.kaidroid.inputprobe.compat.app/widget',
              'isolated_definitions': sorted(required),
              'source_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in inputs},
              'android_jar_sha256': hashlib.sha256(android.read_bytes()).hexdigest(),
              'apk_sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
              'apk_bytes': apk.stat().st_size, 'commands': commands}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'apk': str(apk), 'sha256': report['apk_sha256'], 'bytes': report['apk_bytes']}))


if __name__ == '__main__':
    main()

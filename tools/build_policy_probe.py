"""Generate an Android 11 platform CIL probe outside a full Android build.

Follows inspected sepolicy Android.mk/definitions.mk ordering. This diagnostic
does not replace the product's build-time policy generation and tests.
"""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ORDER = '''security_classes initial_sids access_vectors global_macros neverallow_macros
mls_macros mls_decl mls policy_capabilities te_macros attributes ioctl_defines ioctl_macros
*.te roles_decl roles users initial_sid_contexts fs_use genfs_contexts port_contexts'''.split()
DEFINES = {'mls_num_sens': '1', 'mls_num_cats': '1024', 'target_build_variant': 'userdebug',
           'target_with_dexpreopt': 'true', 'target_arch': 'arm', 'target_with_asan': 'false',
           'target_with_native_coverage': 'false', 'target_full_treble': 'true',
           'target_compatible_property': 'true', 'target_treble_sysprop_neverallow': 'true',
           'target_exclude_build_test': 'false', 'target_requires_insecure_execmem_for_swiftshader': 'false'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--tools-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variant', choices=('user', 'userdebug', 'eng'), default='userdebug')
    parser.add_argument('--extra-private', type=Path, action='append', default=[],
                        help='Additional private TE inputs for a diagnostic combined policy, not a system_ext build')
    parser.add_argument('--legacy-sysprop-launch-api', type=int,
                        help='Probe AOSP BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW for a verified launch API <=29')
    args = parser.parse_args()
    if args.legacy_sysprop_launch_api is not None and not 1 <= args.legacy_sysprop_launch_api <= 29:
        parser.error('Legacy sysprop compatibility is restricted to launch API 1..29')
    source, root, output = (p.resolve() for p in (args.source, args.tools_root, args.output))
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('Use an empty output directory for each probe run')
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = str(root / 'usr/lib/x86_64-linux-gnu')
    directories = [source / 'public', source / 'private'] + [p.resolve() for p in args.extra_private]
    if any(not p.is_dir() for p in directories):
        raise ValueError('Missing policy input directory')
    files = [p for pattern in ORDER for directory in directories
             for p in sorted(directory.glob(pattern))]
    commands = []

    def run(command, name, stdout_path=None):
        result = subprocess.run([str(x) for x in command], env=env, capture_output=True)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        (stdout_path or output / (name + '.stdout')).write_bytes(result.stdout)
        commands.append({'argv': [str(x) for x in command], 'exit_code': result.returncode})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        result.check_returncode()

    conf, cil = output / 'plat_policy.conf', output / 'plat_sepolicy.cil'
    command = [root / 'usr/bin/m4', '--fatal-warnings']
    defines = dict(DEFINES, target_build_variant=args.variant)
    if args.legacy_sysprop_launch_api is not None:
        defines['target_treble_sysprop_neverallow'] = 'false'
    for key, value in defines.items():
        command.extend(['-D', key + '=' + value])
    run(command + ['-s'] + files, 'm4', conf)
    # A Windows Git checkout can contain CRLF; checkpolicy treats CR as invalid.
    # Normalize derived text only, preserving source checkout bytes and hashes.
    conf.write_bytes(conf.read_bytes().replace(b'\r\n', b'\n'))
    run([root / 'usr/bin/checkpolicy', '-M', '-C', '-c', '30', '-o', cil, conf], 'checkpolicy')
    debt = source / 'private/technical_debt.cil'
    with cil.open('ab') as stream:
        stream.write(b'\n' + debt.read_bytes().replace(b'\r\n', b'\n'))
    run([root / 'usr/bin/secilc', '-m', '-M', 'true', '-G', '-c', '30', cil,
         '-o', output / 'platform.policy.30', '-f', output / 'platform.file_contexts'], 'secilc')
    manifest = {'scope': 'Standalone platform policy probe; not product build verification.',
                'legacy_sysprop_launch_api': args.legacy_sysprop_launch_api,
                'extra_private': [str(p.resolve()) for p in args.extra_private],
                'defines': defines, 'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                             for p in files + [debt]},
                'cil_sha256': hashlib.sha256(cil.read_bytes()).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Platform probe compiled with neverallow checks enabled:', cil)


if __name__ == '__main__':
    main()

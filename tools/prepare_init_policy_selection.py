"""Prepare hash-bound Android11 init sources selecting the reviewed engineering CIL.

Output only: no active AOSP checkout or handset is changed. The paired VNDK,
contexts and init actions remain required before installation.
"""
import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source anchor: ' + old[:80])
    return text.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Pinned system/core/init directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    pinned = {
        'builtins.cpp': 'e6930e11f9ede993626d81baa503d7c8cd5327b6ba7d4324a2272c744304381b',
        'util.cpp': 'dae3d44c2527fbc770a063dd72f76fbab53e994958603a5ca63bbfaa83eb7593',
        'reboot_utils.cpp': '389037839e0d884aa74b45eb5c287cf829a5eed6ddb44fab21b9dfa7afdae156',
        'selinux.cpp': 'cd3a29557e746aec1bd6cdcb48bb28fb1899d1cae412b6ee7915dd0590096b60',
        'Android.bp': '2d50db572bf958086332b3b3dd1acaa621bbed5385b44594e3301f2cdd92df84',
    }
    originals = {}
    for name, expected in pinned.items():
        data = (args.source / name).read_bytes().replace(b'\r\n', b'\n')
        if sha(data) != expected:
            raise ValueError('Unrecognized init source: ' + name)
        originals[name] = data
    text = originals['selinux.cpp'].decode()
    text = replace_once(text, '#include "selinux.h"', '#include "selinux.h"\n#include "kaidroid_policy.h"')
    text = replace_once(text, 'bool LoadSplitPolicy() {', '''bool LoadSplitPolicy() {
    const bool kaidroid_policy = KaiDroidEngineeringPolicyMatches();
    if (!kaidroid_policy) return false;
    if (access("/odm/etc/selinux/odm_sepolicy.cil", F_OK) == 0) {
        LOG(ERROR) << "Unexpected ODM policy in engineering profile";
        return false;
    }''')
    text = replace_once(text, 'if (!use_userdebug_policy && FindPrecompiledSplitPolicy(',
                        'if (!kaidroid_policy && !use_userdebug_policy && FindPrecompiledSplitPolicy(')
    text = replace_once(text, '    std::string plat_mapping_file(', '''    if (vend_plat_vers != "29.0") {
        LOG(ERROR) << "Unsupported KaiDroid vendor policy version";
        return false;
    }
    std::string plat_mapping_file(''')
    text = replace_once(text, '"/system/etc/selinux/mapping/" + vend_plat_vers +\n                                     ".compat.cil"',
                        '"/system/etc/selinux/kaidroid/29.0.compat.cil"')
    for name in ('plat_pub_versioned.cil', 'vendor_sepolicy.cil'):
        text = replace_once(text, '"/vendor/etc/selinux/' + name + '"',
                            '"/system/etc/selinux/kaidroid/' + name + '"')
    text = replace_once(text, '"-m", "-M", "true", "-G", "-N",',
                        '"-m", "-M", "true", "-G",')
    bp = replace_once(originals['Android.bp'].decode(), '        "libavb",',
                      '        "libavb",\n        "libcrypto_static",')
    bp = replace_once(bp, '    name: "init_defaults",', '''    name: "init_defaults",
    target: {
        recovery: {
            exclude_static_libs: ["libcrypto_static"],
            shared_libs: ["libcrypto"],
        },
    },''')
    bp = replace_once(bp, '                "-USHUTDOWN_ZERO_TIMEOUT",',
                      '                "-DKAIDROID_ENG_LEGACY_DATA_OWNER=1",\n                "-DKAIDROID_ENG_LEGACY_FOTA=1",\n                "-DKAIDROID_ENG_RECOVERY_FALLBACK=1",\n                "-USHUTDOWN_ZERO_TIMEOUT",')
    builtins = replace_once(originals['builtins.cpp'].decode(), '#include "builtins.h"',
                            '#include "builtins.h"\n#include "kaidroid_legacy_data.h"')
    builtins = replace_once(builtins, '    return make_dir_with_options(*options);', '''#if defined(KAIDROID_ENG_LEGACY_DATA_OWNER)
    struct stat legacy_state;
    const bool existing_directory = lstat(options->target.c_str(), &legacy_state) == 0 &&
                                    S_ISDIR(legacy_state.st_mode);
    if (KaiDroidPreservePlatformDirectoryPolicy(args.context, options->target,
                                               args.args.size(), existing_directory)) {
        options->fscrypt_action = FscryptAction::kNone;
    }
#endif
    return make_dir_with_options(*options);''')
    util = replace_once(originals['util.cpp'].decode(),
                        'static FscryptAction FscryptInferAction(const std::string& dir) {',
                        '''static FscryptAction FscryptInferAction(const std::string& dir) {
#if defined(KAIDROID_ENG_LEGACY_FOTA)
    // Measured stock N139DL path is populated and has no encryption policy.
    // Also covers the retained vendor mkdir, which lacks an explicit action.
    if (dir == "/data/fota") return FscryptAction::kNone;
#endif''')
    reboot = replace_once(originals['reboot_utils.cpp'].decode(),
                          'static std::string init_fatal_reboot_target = "bootloader";',
                          '#if defined(KAIDROID_ENG_RECOVERY_FALLBACK)\n'
                          'static std::string init_fatal_reboot_target = "recovery";\n'
                          '#else\nstatic std::string init_fatal_reboot_target = "bootloader";\n#endif')
    reboot = replace_once(reboot, 'return;  // We already default to bootloader if no setting is provided.',
                          'return;  // Retain the build-specific default when no override is provided.')
    header = Path(__file__).resolve().parents[1] / 'device/nokia/n139dl/init/kaidroid_policy.h'
    outputs = {'selinux.cpp': text.encode(), 'Android.bp': bp.encode(),
               'reboot_utils.cpp': reboot.encode(),
               'util.cpp': util.encode(),
               'builtins.cpp': builtins.encode(),
               'kaidroid_legacy_data.h': (header.parent/'kaidroid_legacy_data.h').read_bytes().replace(b'\r\n', b'\n'),
               'kaidroid_policy.h': header.read_bytes().replace(b'\r\n', b'\n')}
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in outputs.items():
        (args.output / name).write_bytes(data)
    (args.output / 'selection.json').write_text(json.dumps({
        'source_sha256': pinned, 'output_sha256': {n: sha(b) for n, b in outputs.items()},
        'scope': 'Prepared source only; requires Android compilation, bundle packaging and boot validation.',
        'fatal_reboot': 'Eng-only recovery default; existing kernel command-line override remains honored. Not a kernel-hang watchdog.',
        'legacy_fota': 'Eng-only default None for exact /data/fota; explicit actions and other paths remain unchanged.',
        'legacy_data_owner': 'Eng vendor bare mkdir preserves policy on existing exact platform-owned fota/usbmsc/hostapd; platform and explicit actions unchanged.',
        'behavior': 'Reject unknown vendor inputs; bypass precompiled vendor policy; compile E013 with restored mappings with neverallow checks.',
    }, indent=2) + '\n')
    print('Prepared engineering init policy selection:', args.output)


if __name__ == '__main__':
    main()

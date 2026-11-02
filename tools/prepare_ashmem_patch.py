"""Prepare an experimental Q libcutils backport; never modify the source tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

PIN = 'af278f2583155f4cc195df565ce1da60cc976e553e9be362b54e4957e08e785c'
REVISION = '1dea9a052b7f214c10a77d5ed6ffd3602722a817'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    relative = 'libcutils/ashmem-dev.cpp'
    old = (args.source / relative).read_text(encoding='utf-8')
    if hashlib.sha256(old.encode()).hexdigest() != PIN:
        raise ValueError('Unexpected LF-normalized source hash')
    if args.output.exists():
        raise ValueError('Output already exists')
    new = old.replace('#include <android-base/properties.h>',
                      '#include <android-base/file.h>\n#include <android-base/strings.h>\n#include <android-base/properties.h>')
    marker = '/* logistics of getting file descriptor for ashmem */'
    helper = '''// Android 11 device naming; retain Q allocation and ioctl behavior.
static std::string get_ashmem_device_path() {
    std::string boot_id;
    if (!android::base::ReadFileToString("/proc/sys/kernel/random/boot_id", &boot_id)) {
        return "";
    }
    boot_id = android::base::Trim(boot_id);
    if (boot_id.empty()) {
        return "";
    }
    return std::string(ASHMEM_DEVICE) + boot_id;
}

'''
    new = new.replace(marker, helper + marker)
    anchor = '        fd = TEMP_FAILURE_RETRY(open(ASHMEM_DEVICE, O_RDWR | O_CLOEXEC));'
    replacement = '''        static const std::string path = get_ashmem_device_path();
        if (!path.empty()) {
            fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDWR | O_CLOEXEC));
        }
        // Retain stock-Q fallback; policy may deny it on Android 11.
        if (fd < 0) {
            fd = TEMP_FAILURE_RETRY(open(ASHMEM_DEVICE, O_RDWR | O_CLOEXEC));
        }'''
    assert old.count(marker) == old.count(anchor) == 1
    new = new.replace(anchor, replacement)
    patch = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                    fromfile='a/' + relative, tofile='b/' + relative))
    args.output.mkdir(parents=True)
    (args.output / 'ashmem-dev.cpp').write_bytes(new.encode())
    (args.output / '0001-q-ashmem-boot-id.patch').write_bytes(patch.encode())
    (args.output / 'manifest.json').write_text(json.dumps({
        'source_revision': REVISION, 'source_file': relative,
        'source_lf_sha256': PIN,
        'patched_lf_sha256': hashlib.sha256(new.encode()).hexdigest(),
        'patch_sha256': hashlib.sha256(patch.encode()).hexdigest(),
        'status': 'Experimental source only; not a replacement VNDK binary or product integration',
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()

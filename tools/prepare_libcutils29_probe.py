"""Stage a pinned Q libcutils platform-build probe in a NEW directory.

Does not modify AOSP, install a library, or replace a VNDK snapshot. Git symlink
headers are materialized from pinned blobs so Windows checkout settings do not
silently turn include files into pathname text. Requires the prepared ashmem patch.
"""
import argparse
import hashlib
import json
import posixpath
import subprocess
from pathlib import Path

PIN = '1dea9a052b7f214c10a77d5ed6ffd3602722a817'
SOURCES = '''config_utils.cpp canned_fs_config.cpp iosched_policy.cpp load_file.cpp
native_handle.cpp record_stream.cpp sockets.cpp strdup16to8.cpp strdup8to16.cpp
strlcpy.c threads.cpp fs.cpp hashmap.cpp multiuser.cpp socket_inaddr_any_server_unix.cpp
socket_local_client_unix.cpp socket_local_server_unix.cpp socket_network_client_unix.cpp
sockets_unix.cpp str_parms.cpp android_get_control_file.cpp android_reboot.cpp
ashmem-dev.cpp fs_config.cpp klog.cpp partition_utils.cpp properties.cpp trace-dev.cpp
uevent.cpp arch-arm/memset32.S'''.split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--patch-output', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Output must not exist')
    def git(*argv):
        return subprocess.check_output(['git', '-C', str(args.source), *argv])
    if git('rev-parse', 'HEAD').decode().strip() != PIN:
        raise ValueError('Wrong source revision')
    records = {}
    for entry in git('ls-tree', '-rz', PIN, '--', 'libcutils').split(b'\0'):
        if not entry:
            continue
        meta, path = entry.split(b'\t')
        mode, kind, oid = meta.decode().split()
        if kind != 'blob':
            raise ValueError('Unexpected tree entry')
        records[path.decode()] = (mode, oid)
    def read(path, seen=()):
        if path in seen or not path.startswith('libcutils/'):
            raise ValueError('Invalid source symlink')
        mode, oid = records[path]
        data = git('cat-file', 'blob', oid)
        if mode == '120000':
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), data.decode()))
            return read(target, (*seen, path))
        return data
    manifest = json.loads((args.patch_output / 'manifest.json').read_text())
    patched = (args.patch_output / 'ashmem-dev.cpp').read_bytes()
    if manifest['source_revision'] != PIN or hashlib.sha256(patched).hexdigest() != manifest['patched_lf_sha256']:
        raise ValueError('Patch provenance mismatch')
    if hashlib.sha256(read('libcutils/ashmem-dev.cpp')).hexdigest() != manifest['source_lf_sha256']:
        raise ValueError('Patch input mismatch')
    selected = set(SOURCES)
    selected.update(p.removeprefix('libcutils/') for p in records
                    if p.startswith(('libcutils/include/', 'libcutils/include_vndk/')))
    selected.update(p.removeprefix('libcutils/') for p in records
                    if '/' not in p.removeprefix('libcutils/') and p.endswith(('.h', '.inc')))
    selected.add('NOTICE')
    payload = {p: read('libcutils/' + p) for p in sorted(selected)}
    payload['ashmem-dev.cpp'] = patched
    bp = '''// Generated Q source probe; not installed or used by the product.
cc_library_shared {
    name: "kaidroid_libcutils29_probe",
    stem: "libcutils",
    vendor: true,
    compile_multilib: "32",
    installable: false,
    srcs: %s,
    local_include_dirs: ["include", "include_vndk"],
    export_include_dirs: ["include_vndk"],
    shared_libs: ["liblog", "libbase"],
    header_libs: ["libbase_headers", "libutils_headers", "libprocessgroup_headers"],
    cflags: ["-Wall", "-Wextra", "-Werror"],
    notice: "NOTICE",
}
''' % json.dumps(SOURCES)
    payload['Android.bp'] = bp.encode()
    args.output.mkdir(parents=True)
    for name, data in payload.items():
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    report = {'source_revision': PIN, 'patch': manifest,
              'files': {p: hashlib.sha256(b).hexdigest() for p, b in payload.items()},
              'scope': 'ARM32 vendor platform-build probe only. Uses current platform dependency headers/libraries; not proven VNDK29 ABI or installed replacement.'}
    (args.output / 'probe-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'files': len(payload), 'module': 'kaidroid_libcutils29_probe'}))


if __name__ == '__main__':
    main()

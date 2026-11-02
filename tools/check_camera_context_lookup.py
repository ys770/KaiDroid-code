"""Linux libselinux text-rule lookup check; no phone or image writes."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import stat


class Option(C.Structure):
    _fields_ = [('type', C.c_int), ('value', C.c_char_p)]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'merged', 'inventory', 'library', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    if sha(a.baseline) != '0ab9ae6b9f576bb798ffe55eedc0c3140dc5e5b56c0569149441875b108405be':
        raise ValueError('Wrong baseline contexts')
    if sha(a.merged) != '31638cc9dfa5d8c2be93340537b147a92565538d4968bbc73a40779dce326106':
        raise ValueError('Wrong merged contexts')
    if sha(a.inventory) != 'c3de5cdc992291082c6464f9eb3e2d4925182682f5d134a4e4453f29e93196aa':
        raise ValueError('Wrong image49 system inventory')
    a.output.mkdir(exist_ok=False)
    # Different basenames deliberately exclude companion .bin/.local files.
    old = a.output/'original-text'; new = a.output/'merged-text'
    old.write_bytes(a.baseline.read_bytes()); new.write_bytes(a.merged.read_bytes())
    lib = C.CDLL(str(a.library), use_errno=True)
    lib.selabel_open.argtypes = [C.c_uint, C.POINTER(Option), C.c_uint]
    lib.selabel_open.restype = C.c_void_p
    lib.selabel_lookup_raw.argtypes = [C.c_void_p, C.POINTER(C.c_void_p), C.c_char_p, C.c_int]
    lib.selabel_lookup_raw.restype = C.c_int
    lib.freecon.argtypes = [C.c_void_p]; lib.freecon.restype = None
    lib.selabel_close.argtypes = [C.c_void_p]; lib.selabel_close.restype = None
    handles = []
    try:
        for path in (old, new):
            # Constants/signatures verified from the retained AOSP selinux headers.
            opts = (Option * 2)(Option(3, str(path).encode()), Option(2, b'1'))
            h = lib.selabel_open(0, opts, 2)
            if not h: raise OSError(C.get_errno(), 'selabel_open')
            handles.append(h)

        def lookup(handle, path, mode):
            value = C.c_void_p()
            if lib.selabel_lookup_raw(handle, C.byref(value), path.encode(), mode):
                raise OSError(C.get_errno(), 'lookup '+path)
            try: return C.string_at(value).decode()
            finally: lib.freecon(value)

        inventory = json.loads(a.inventory.read_text())
        types = dict(file=stat.S_IFREG, dir=stat.S_IFDIR, link=stat.S_IFLNK)
        for name, entry in inventory.items():
            path = '/system/'+name
            if lookup(handles[0], path, types[entry[0]]) != lookup(handles[1], path, types[entry[0]]):
                raise ValueError('Existing label changed: '+path)
        expected = {
            '/system/etc/kaidroid-camera': (stat.S_IFDIR, 'u:object_r:vendor_file:s0'),
            '/system/etc/kaidroid-camera/libmmcamera2_stats_modules.so': (stat.S_IFREG, 'u:object_r:vendor_file:s0'),
            '/system/etc/init/kaidroid-camera.rc': (stat.S_IFREG, 'u:object_r:system_file:s0'),
        }
        actual = {path: lookup(handles[1], path, mode) for path, (mode, _) in expected.items()}
        if actual != {path: label for path, (_, label) in expected.items()}:
            raise ValueError('Unexpected camera labels: '+str(actual))
        result = dict(existing_system_paths=len(inventory), existing_labels_unchanged=True,
                      added_path_labels=actual, libselinux_sha256=sha(a.library),
                      source_inventory_sha256=sha(a.inventory), installed=False,
                      scope='Linux libselinux text-rule lookup, not Android compiled-context or filesystem xattr enforcement')
        (a.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
    finally:
        for h in handles: lib.selabel_close(h)


if __name__ == '__main__':
    main()

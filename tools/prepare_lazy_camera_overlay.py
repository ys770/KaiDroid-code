"""Prepare an inert, hash-bound camera overlay for coordinated image integration.

Does not modify an image, device, shared source or global property. File modes and
labels are declarative requirements, to be checked in the final assembled image.
"""
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise ValueError('Use a new overlay output')
    evidence = json.loads(a.evidence.read_text())
    data = a.binary.read_bytes()
    if sha(data) != evidence['binary_sha256'] or evidence['unresolved_strong_imports']:
        raise ValueError('Binary or direct imports not verified')
    with a.binary.open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 32 or elf['e_machine'] != 'EM_ARM' or elf['e_type'] != 'ET_DYN':
            raise ValueError('Expected ARM32 PIE')
    source = Path(__file__).resolve().parents[1]/'experiments/memory/lazy-camera'
    rc = (source/'service.rc.example').read_text().replace('\r\n', '\n')
    if rc.count('service vendor.camera-provider-2-4 ') != 1:
        raise ValueError('Unexpected service identity')
    if any(line.startswith('on ') for line in rc.splitlines()):
        raise ValueError('Overlay must not introduce automatic control triggers')
    required = ['    override', '    disabled', '    oneshot', '    user cameraserver',
                '    group audio camera input drmrpc', '    capabilities SYS_NICE',
                '    interface android.hardware.camera.provider@2.4::ICameraProvider legacy/0']
    if any(rc.splitlines().count(line) != 1 for line in required):
        raise ValueError('Missing reviewed service setting')
    files = {
        'root/odm/kaidroid/bin/kaidroid-camera-lazy-experiment': data,
        'system/etc/init/kaidroid-camera-lazy.rc': rc.encode(),
        'file_contexts.fragment': (source/'file_contexts.example').read_text().encode(),
    }
    manifest = dict(base_image_sha256=evidence['image_sha256'],
                    files={name: sha(value) for name, value in files.items()},
                    executable=dict(path='/odm/kaidroid/bin/kaidroid-camera-lazy-experiment',
                                    mode='0755', uid=0, gid=0,
                                    selinux='u:object_r:hal_camera_default_exec:s0'),
                    required_property={'ro.camera.enableLazyHal': 'true'},
                    replaced_service='vendor.camera-provider-2-4',
                    original_vendor_binary_preserved=True,
                    image_assembled=False, installed=False,
                    integration_requirements=[
                        'Use a coordinated image revision; preserve current baseline and rollback.',
                        'Merge property exactly once into the final property source.',
                        'Merge file context into image builder contexts; verify inode label and executable mode.',
                        'Verify effective single init service and vendor linker namespace.',
                        'Validate camera and torch lifecycle and physical footprint against the same workload.'])
    a.output.mkdir(parents=True, exist_ok=False)
    for name, value in files.items():
        dest = a.output/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(value)
    (a.output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

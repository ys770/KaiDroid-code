"""Make a deterministic private product-alarm payload from verified donor captures.

No phone, remote build, existing stage, alarm setting or media database is changed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

NAMES = {'Ahead.ogg', 'Dew.ogg', 'Illuminate.ogg', 'RollingAwake.ogg',
         'Snoozer.ogg', 'Sojourn.ogg', 'Wonder.ogg', 'Xylo.ogg'}
FINGERPRINT = 'TCL/4058L1/Gflip6_USCC:11/RP1A.200720.011/PJEP:user/release-keys'


def prepare(source, manifest, output):
    spec = json.loads(manifest.read_text())
    assert spec['source_fingerprint'] == FINGERPRINT
    assert len(spec['files']) == 8
    assert {f['name'] for f in spec['files']} == NAMES
    assert spec['total_bytes'] == 2691019
    payload = {}
    for item in spec['files']:
        name = item['name']
        assert item['source'] == '/product/media/audio/alarms/' + name
        path = source / name
        assert not path.is_symlink() and path.is_file(), name
        content = path.read_bytes()
        assert len(content) == item['bytes'], name
        assert content.startswith(b'OggS'), name
        assert hashlib.sha256(content).hexdigest() == item['sha256'], name
        payload['product/media/audio/alarms/' + name] = content
    assert sum(map(len, payload.values())) == spec['total_bytes']
    if output.exists():
        raise FileExistsError(output)
    # Validate every input before creating output. Fixed metadata makes repeat
    # builds byte-identical without relying on host timestamps or ownership.
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in ('product/media', 'product/media/audio', 'product/media/audio/alarms'):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            tar.addfile(entry)
        for name, content in sorted(payload.items()):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
    data = archive.getvalue()
    report = dict(source_fingerprint=FINGERPRINT,
                  source_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                  archive_sha256=hashlib.sha256(data).hexdigest(),
                  files={n: hashlib.sha256(b).hexdigest() for n, b in sorted(payload.items())},
                  directories_mode='0755', files_mode='0644', uid=0, gid=0,
                  expected_selinux_label='u:object_r:system_file:s0',
                  total_payload_bytes=spec['total_bytes'], installed=False,
                  note='Stage only into a new reviewed compact-system; verify final ext4 labels and MediaStore indexing.')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'alarms.tar').write_bytes(data)
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=Path('docs/evidence/tcl-alarm-tones-reference01.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.manifest, args.output), indent=2))

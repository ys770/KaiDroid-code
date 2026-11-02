"""Verify a completed donor capture and extract selected regular files locally."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath
from inspect_transfer import sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prefix', action='append', required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    archive = args.manifest.parent / manifest['archive']
    if archive.parent.resolve() != args.manifest.parent.resolve():
        raise ValueError('Archive must be adjacent to capture manifest')
    if archive.stat().st_size != manifest['archive_bytes'] or sha256(archive) != manifest['archive_sha256']:
        raise ValueError('Capture verification failed')
    args.output.mkdir(parents=True, exist_ok=False)
    files = []
    with tarfile.open(archive, 'r:') as package:
        for entry in package:
            if not entry.isfile() or not any(entry.name.startswith(prefix) for prefix in args.prefix):
                continue
            name = PurePosixPath(entry.name)
            if name.is_absolute() or '..' in name.parts or ':' in entry.name or '\\' in entry.name:
                raise ValueError('Unsafe tar path')
            destination = args.output.joinpath(*name.parts)
            if not destination.resolve().is_relative_to(args.output.resolve()):
                raise ValueError('Path leaves output folder')
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with package.extractfile(entry) as source, destination.open('xb') as output:
                for block in iter(lambda: source.read(1024*1024), b''):
                    output.write(block)
                    digest.update(block)
            if destination.stat().st_size != entry.size:
                raise ValueError('Extracted size mismatch')
            files.append({'path': entry.name, 'bytes': entry.size, 'sha256': digest.hexdigest()})
    (args.output / 'extraction-manifest.json').write_text(json.dumps(
        {'source_sha256': manifest['archive_sha256'], 'files': files}, indent=2) + '\n', encoding='utf-8')
    print(f'Verified and extracted {len(files)} regular files; symlinks and special entries not materialized.')


if __name__ == '__main__':
    main()

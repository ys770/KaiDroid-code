"""Verify a transfer manifest and inventory a ZIP without unpacking bulk captures."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extract-prefix', action='append', default=[])
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8-sig'))
    archive = args.manifest.parent / manifest['archive']
    if archive.parent.resolve() != args.manifest.parent.resolve():
        raise ValueError('Archive must be adjacent to manifest')
    if archive.stat().st_size != manifest['archive_bytes']:
        raise ValueError('Archive size mismatch: transfer may be incomplete')
    digest = sha256(archive)
    if digest.lower() != manifest['archive_sha256'].lower():
        raise ValueError('Archive SHA-256 mismatch')
    expected = {entry['path']: entry['bytes'] for entry in manifest['files']}
    if len(expected) != manifest['file_count']:
        raise ValueError('Manifest count mismatch or duplicate entries')
    extracted = []
    with zipfile.ZipFile(archive) as package:
        entries = [entry for entry in package.infolist() if not entry.is_dir()]
        actual = {entry.filename: entry.file_size for entry in entries}
        if actual != expected or len(entries) != len(expected):
            raise ValueError('ZIP inventory does not match manifest')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or ':' in entry.filename:
                raise ValueError('Unsafe archive path')
            if not any(entry.filename.startswith(prefix) for prefix in args.extract_prefix):
                continue
            if args.destination is None:
                raise ValueError('--destination is required for extraction')
            target = args.destination.joinpath(*path.parts)
            if not target.resolve().is_relative_to(args.destination.resolve()):
                raise ValueError('Extraction escapes destination')
            target.parent.mkdir(parents=True, exist_ok=True)
            hasher = hashlib.sha256()
            # Never overwrite existing evidence. A fresh destination is required.
            with package.open(entry) as source, target.open('xb') as output:
                for block in iter(lambda: source.read(8 * 1024 * 1024), b''):
                    output.write(block)
                    hasher.update(block)
            extracted.append({'path': entry.filename, 'bytes': entry.file_size,
                              'sha256': hasher.hexdigest()})
    result = {'archive': archive.name, 'archive_bytes': archive.stat().st_size,
              'sha256': digest, 'verified_entries': len(expected),
              'uncompressed_bytes': sum(expected.values()), 'extracted': extracted,
              'note': 'Whole archive hash and ZIP inventory verified; CRC checked for extracted entries.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'extracted'}, indent=2))
    print(f'Extracted {len(extracted)} selected files')


if __name__ == '__main__':
    main()

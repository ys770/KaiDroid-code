"""Back up and stage hash-bound source files; never deletes files or builds."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    spec = json.loads((args.payload/'manifest.json').read_text())
    source = args.source.resolve()
    for entry in spec['files']:
        relative = Path(entry['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe source path')
        current = (source/relative).resolve()
        if not current.is_relative_to(source):
            raise ValueError('Source escaped checkout')
        before = entry['before_sha256']
        if before is None:
            if current.exists() or (source/relative).is_symlink():
                raise ValueError('Expected absent new source: '+str(relative))
        elif sha(current) != before:
            raise ValueError('Original hash mismatch: '+str(relative))
        if sha(args.payload/relative) != entry['after_sha256']:
            raise ValueError('Hash mismatch: '+str(relative))
    args.output.mkdir(parents=True, exist_ok=False)
    result = {'preflight': True, 'apply': args.apply, 'files': spec['files']}
    if args.apply:
        for entry in spec['files']:
            relative = Path(entry['path'])
            if entry['before_sha256'] is None:
                continue
            backup = args.output/'before'/relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source/relative, backup)
            if sha(backup) != entry['before_sha256']:
                raise ValueError('Backup mismatch')
        for entry in spec['files']:
            relative = Path(entry['path'])
            if entry['before_sha256'] is None:
                # Exclusive creation cannot overwrite a file appearing after preflight.
                with (source/relative).open('xb') as destination:
                    destination.write((args.payload/relative).read_bytes())
            else:
                if sha(source/relative) != entry['before_sha256']:
                    raise ValueError('Source changed after backup')
                shutil.copyfile(args.payload/relative, source/relative)
            if sha(source/relative) != entry['after_sha256']:
                raise ValueError('Staging mismatch')
    (args.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

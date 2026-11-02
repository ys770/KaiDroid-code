"""Copy a system image input tree, omitting two optional UI apps without deleting inputs.

Run only after its producer build finishes. This prepares input, not an image:
use the matching AOSP build_image configuration and all existing image verifiers.
EasterEgg is decorative; Traceur is the recording UI, not the tracing backend.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


EXCLUDED = ('app/EasterEgg', 'app/Traceur')


def stage(source, output):
    source = source.resolve(strict=True)
    output = output.absolute()
    if not source.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Source must be a directory; output must be new')
    resolved_output = output.resolve()
    if source == resolved_output or source in resolved_output.parents:
        raise ValueError('Output must not be inside source')
    excluded = []
    for relative in EXCLUDED:
        target = source / relative
        if target.is_symlink() or not target.is_dir():
            raise ValueError('Expected actual optional-app directory: ' + relative)
        for path in sorted(target.rglob('*')):
            entry = {'path': path.relative_to(source).as_posix()}
            if path.is_symlink():
                entry['symlink'] = str(path.readlink())
            elif path.is_file():
                entry['bytes'] = path.stat().st_size
                with path.open('rb') as stream:
                    entry['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            else:
                continue
            excluded.append(entry)

    def ignore(directory, names):
        return [name for name in names
                if (Path(directory) / name).relative_to(source).as_posix() in EXCLUDED]

    # Symlinks are copied as links; do not traverse /vendor or other external trees.
    shutil.copytree(source, output, symlinks=True, ignore=ignore)
    return {'source': str(source), 'output': str(output),
            'excluded_directories': list(EXCLUDED), 'excluded_entries': excluded,
            'excluded_regular_bytes': sum(e.get('bytes', 0) for e in excluded),
            'source_deleted': False, 'image_built': False,
            'note': 'Byte sum is not an ext4 size prediction; shared blocks and overhead differ.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    report = args.report.absolute()
    if report.exists() or report.is_symlink():
        raise ValueError('Report must be new')
    for tree in (args.source.resolve(), args.output.resolve()):
        if report.resolve() == tree or tree in report.resolve().parents:
            raise ValueError('Report must be outside image trees')
    result = stage(args.source, args.output)
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'excluded_regular_bytes': result['excluded_regular_bytes'],
                      'report': str(report), 'image_built': False}))


if __name__ == '__main__':
    main()

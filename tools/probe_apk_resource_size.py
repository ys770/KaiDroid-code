"""Measure density/sparse resource encoding on separate, non-installable APK copies."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--aapt2', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.system.resolve(), args.output.resolve()
    if output == source or source in output.parents or output.exists():
        raise ValueError('Use a new output directory outside the system tree')
    files = sorted(source.rglob('*.apk'))
    if not files:
        raise ValueError('No APKs found')
    output.mkdir(parents=True)
    report = {'aapt2_sha256': digest(args.aapt2), 'options': ['--target-densities', 'mdpi', '--enable-sparse-encoding'],
              'scope': 'Unsigned resource-size probes only. No APK installation, original mutation, or runtime validation.',
              'apks': [], 'complete': False}
    for path in files:
        relative = path.relative_to(source)
        target = output / 'apks' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        before = digest(path)
        result = subprocess.run([str(args.aapt2.resolve()), 'optimize', *report['options'],
                                 '-o', str(target), str(path)], capture_output=True, timeout=120)
        target.with_suffix('.stderr').write_bytes(result.stderr)
        if digest(path) != before:
            raise ValueError('Source changed during probe: ' + str(path))
        row = {'path': str(relative), 'input_sha256': before, 'before_bytes': path.stat().st_size,
               'exit_code': result.returncode}
        if result.returncode == 0:
            row.update(after_bytes=target.stat().st_size, output_sha256=digest(target))
            row['saved_bytes'] = row['before_bytes'] - row['after_bytes']
        report['apks'].append(row)
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    report['complete'] = True
    report['saved_bytes'] = sum(r.get('saved_bytes', 0) for r in report['apks'])
    report['failures'] = sum(r['exit_code'] != 0 for r in report['apks'])
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('complete', 'saved_bytes', 'failures')}))
    for row in sorted(report['apks'], key=lambda r: r.get('saved_bytes', 0), reverse=True)[:15]:
        print(row['path'], row.get('saved_bytes'))


if __name__ == '__main__':
    main()

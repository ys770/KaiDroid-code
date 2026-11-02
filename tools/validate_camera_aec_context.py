"""Compile camera overlay contexts against immutable image49; never pack or flash."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

BASELINE = '0ab9ae6b9f576bb798ffe55eedc0c3140dc5e5b56c0569149441875b108405be'
FRAGMENT = 'dbd97d30db2521e251a55156208ac2a3f9fd5aad4ed187660530ffe525c3df35'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'fragment', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if digest(args.baseline) != BASELINE or digest(args.fragment) != FRAGMENT:
        raise ValueError('Unreviewed baseline or camera fragment')
    if args.output.exists():
        raise FileExistsError(args.output)
    source = args.baseline.read_bytes()
    fragment = args.fragment.read_bytes()
    if b'/system/etc/kaidroid-camera' in source:
        raise ValueError('Camera rule already present')
    args.output.mkdir()
    merged = args.output / 'file_contexts.txt'
    merged.write_bytes(source + (b'' if source.endswith(b'\n') else b'\n') + fragment)
    compiled = args.output / 'file_contexts.bin'
    command = [str(args.compiler), '-o', str(compiled), str(merged)]
    result = subprocess.run(command, capture_output=True, timeout=30)
    (args.output / 'compiler.stdout').write_bytes(result.stdout)
    (args.output / 'compiler.stderr').write_bytes(result.stderr)
    result.check_returncode()
    if not compiled.is_file() or not compiled.stat().st_size:
        raise ValueError('Compiler produced no contexts')
    if digest(args.baseline) != BASELINE or digest(args.fragment) != FRAGMENT:
        raise ValueError('Input changed during validation')
    report = dict(baseline_image=49, baseline_context_sha256=BASELINE,
                  fragment_sha256=FRAGMENT, compiler_sha256=digest(args.compiler),
                  merged_sha256=digest(merged), compiled_sha256=digest(compiled),
                  compiled_bytes=compiled.stat().st_size, compiler_exit=result.returncode,
                  original_inputs_unchanged=True, image_built=False, installed=False,
                  limits=['Compilation only; not a label lookup, image xattr, policy enforcement or boot test',
                          'Camera APK integration, provider mount and physical camera tests still required'])
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

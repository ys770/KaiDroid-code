"""Test a fresh synthetic OverlayFS cache without modifying existing build files.

Run as root on the Linux build host. All created files are retained; the mount
is removed in finally. This proves copy-up behavior, not an AOSP build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--builder-image', help='Optional exact Docker image ID for a UID1000 write test')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Requires root for mount; no changes made')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise SystemExit('Output must be new; no existing path is reused')
    if any(c in str(output) for c in ',:\n'):
        raise SystemExit('Unsupported mount path')
    if args.builder_image:
        expected = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
        if args.builder_image != expected:
            raise SystemExit('Unreviewed builder image')
        info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', expected]))
        if len(info) != 1 or info[0]['Id'] != expected:
            raise SystemExit('Builder image identity mismatch')
    output.mkdir()
    lower, upper, work, merged = [output / n for n in ('lower', 'upper', 'work', 'merged')]
    for path in (lower, upper, work, merged):
        path.mkdir()
    original = lower / 'synthetic-cache.txt'
    original.write_bytes(b'preserved baseline cache\n')
    if args.builder_image:
        # Only these newly created synthetic inputs are assigned to the builder.
        os.chown(lower, 1000, 1000)
        os.chown(original, 1000, 1000)
        # Overlay root metadata comes from upper, not the lower directory.
        # A root-owned upper permits copied-file edits but denies new outputs.
        os.chown(upper, 1000, 1000)
    before = digest(original)
    report = {'synthetic_only': True, 'lower_before_sha256': before,
              'mounted': False, 'unmounted': False, 'passed': False}
    try:
        subprocess.run(['mount', '-t', 'overlay', 'overlay', '-o',
                        f'lowerdir={lower},upperdir={upper},workdir={work}',
                        str(merged)], check=True, capture_output=True)
        report['mounted'] = True
        report['host_overlay_mountinfo'] = [
            line for line in Path('/proc/self/mountinfo').read_text().splitlines()
            if line.split()[4] == str(merged)]
        assert digest(merged / original.name) == before
        # Overwriting the view must copy up, leaving the original inode/bytes.
        (merged / original.name).write_bytes(b'new candidate cache\n')
        (merged / 'new-output.txt').write_bytes(b'new build result\n')
        assert digest(original) == before
        assert (upper / original.name).read_bytes() == b'new candidate cache\n'
        assert not (lower / 'new-output.txt').exists()
        assert (upper / 'new-output.txt').read_bytes() == b'new build result\n'
        if args.builder_image:
            # The first root copy-up retains lower ownership. Builder must also
            # be able to create a new file through this Docker bind mount.
            command = ['docker', 'create', '--read-only', '--network', 'none',
                       '--user', '1000:1000', '--mount',
                       f'type=bind,src={merged},dst=/probe', args.builder_image,
                       'bash', '-c', "printf 'builder candidate\\n' > /probe/synthetic-cache.txt && "
                       "printf 'builder result\\n' > /probe/builder-output.txt && "
                       "grep ' /probe ' /proc/self/mountinfo"]
            cid = subprocess.check_output(command, text=True).strip()
            report['container_id'] = cid
            started = subprocess.run(['docker', 'start', '-a', cid], capture_output=True, text=True)
            report['container_output'] = started.stdout + started.stderr
            state = json.loads(subprocess.check_output(['docker', 'inspect', cid]))[0]['State']
            report['container_state'] = state
            assert started.returncode == 0 and state['Status'] == 'exited' and state['ExitCode'] == 0
            assert not state['Running'] and not state['OOMKilled']
            assert digest(original) == before
            assert (upper / original.name).read_bytes() == b'builder candidate\n'
            assert (upper / 'builder-output.txt').read_bytes() == b'builder result\n'
            assert not (lower / 'builder-output.txt').exists()
            report['builder_copyup_passed'] = True
        report.update(lower_after_sha256=digest(original),
                      upper_sha256=digest(upper / original.name), passed=True)
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        try:
            if report['mounted']:
                subprocess.run(['umount', str(merged)], check=True, capture_output=True)
                report['unmounted'] = True
        finally:
            (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

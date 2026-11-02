"""Verify actual ext4 metadata for the root memtrack executable (requires debugfs)."""
import argparse
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    path = '/odm/kaidroid/bin/kaidroid-memtrack-service'
    def inspect(command):
        result = subprocess.run(['debugfs', '-R', command, args.image],
                                capture_output=True, check=True, text=True)
        print(result.stdout)
        return result.stdout
    stat = inspect('stat ' + path)
    if not re.search(r'Type:\s+regular\s+Mode:\s+0755\b', stat):
        raise ValueError('Memtrack must be a regular executable with mode 0755')
    if not re.search(r'User:\s+0\s+Group:\s+0\b', stat):
        raise ValueError('Memtrack ownership must be root:root')
    label = inspect('ea_get ' + path + ' security.selinux')
    if 'u:object_r:hal_memtrack_default_exec:s0' not in label:
        raise ValueError('Unexpected memtrack executable label')


if __name__ == '__main__':
    main()

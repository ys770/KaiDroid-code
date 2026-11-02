"""Reviewed image60 binding of the unchanged bounded Music/Recorder navigation.

Hardware retains Nokia ownership until a separately coordinated lease. This
binding does not permit Record/Play, permission choices or date/settings changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

import trial_tcl_media_navigation_image59 as base
from image60_app_guard import Image60Guard

BASE_SHA = '273743dd8a5d23cf16d490e12d945eea8ee47cfb8a73138fb60bf8a79a5317b4'


class Trial(Image60Guard, base.Trial):
    def __init__(self, args):
        base.require(hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest() == BASE_SHA,
                     'Original59 navigation source changed')
        super().__init__(args)
        self.report['image'] = 60
        self.report['base59_source_sha256'] = BASE_SHA
        self.report['list_data_access_verified'] = False
        self.report['recording_and_playback_verified'] = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--boot', required=True, type=lambda value: str(uuid.UUID(value)))
    parser.add_argument('--app', required=True, choices=base.PROFILES)
    parser.add_argument('--output', required=True, type=Path)
    report = Trial(parser.parse_args()).execute()
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Media navigation failed; preserve state, no blind retry')


if __name__ == '__main__':
    main()

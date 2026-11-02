"""Reviewed image60 binding of the unchanged unsaved Calendar editor route.

Requires a separately coordinated Nokia lease, matching reference defaults and
exact active Calendar/provider bytes. No Save, data writes or keyboard changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

import trial_calendar_editor_image59 as base
from image60_app_guard import Image60Guard

BASE_SHA = '183cc5a2b4746efcf9f0af420df61e6fecb809e9f73db58f8b5eecbf3e5a6274'


class Trial(Image60Guard, base.Trial):
    def __init__(self, args):
        base.reference.require(hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest() == BASE_SHA,
                               'Original59 Calendar route source changed')
        super().__init__(args)
        self.report['image'] = 60
        self.report['base59_source_sha256'] = BASE_SHA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--boot', required=True, type=lambda value: str(uuid.UUID(value)))
    parser.add_argument('--output', required=True, type=Path)
    report = Trial(parser.parse_args()).execute()
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Calendar route failed; preserve state, no blind retry')


if __name__ == '__main__':
    main()

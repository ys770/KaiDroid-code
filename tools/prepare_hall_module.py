"""Stage the original hinge bridge as an isolated AOSP module, without product selection."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
inputs = {
    'n139dl_hall_bridge.c': root / 'tools/n139dl_hall_bridge.c',
    'kaidroid-hall.rc': root / 'device/nokia/n139dl/hall/kaidroid-hall.rc',
}
for source in inputs.values():
    if not source.is_file():
        raise ValueError('Missing input: ' + str(source))
a.output.mkdir(parents=True, exist_ok=False)
for name, source in inputs.items():
    shutil.copyfile(source, a.output / name)
(a.output / 'Android.bp').write_text('''cc_binary {
    name: "kaidroid-hall",
    srcs: ["n139dl_hall_bridge.c"],
    cflags: ["-Wall", "-Wextra", "-Werror"],
    init_rc: ["kaidroid-hall.rc"],
}
''')
report = {
    'inputs': {name: hashlib.sha256(source.read_bytes()).hexdigest() for name, source in inputs.items()},
    'product_selected': False, 'policy_integrated': False, 'boot_enabled': False,
}
(a.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))

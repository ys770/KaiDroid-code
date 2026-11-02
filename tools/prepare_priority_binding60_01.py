"""Prepare a separate exact-image60 priority capture packet offline; preserve59."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'experiments/memory'
BOOT = '00000000-0000-0000-0000-000000000007'
CAP_SHA = 'db9b5000abad028f8bd79e47eaddcd14b52645be5b8b8e579a8754377afbc64d'
PINS = {'trace-priority-capture01.py': '740dfe9e3b4b5a4eeb35a062129655c30dcba2ac256f71e5c7b3ec4b65100caa',
        'trace-priority-worker01.sh': '7e4aeaaecbbef189ab5c0ace659ec10e83220aadf55baaee1ab5d095cc771c0a'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(output):
    capability = ROOT / 'artifacts/runtime/image60-trace-capability02.json'
    raw = capability.read_bytes()
    if sha(raw) != CAP_SHA:
        raise ValueError('Exact parent image60 capability02 receipt required')
    cap = json.loads(raw)
    if not cap['inspection_valid'] or not cap['identity_verified'] or cap['expected'] != {
            'serial': 'DEVICE_SERIAL_REQUIRED', 'image': '60', 'boot_id': BOOT}:
        raise ValueError('Capability identity/validity differs')
    texts = {}
    for name, expected in PINS.items():
        content = (BASE / name).read_bytes()
        if sha(content) != expected:
            raise ValueError('Frozen59 source changed: ' + name)
        texts[name] = content.decode()
    replacements = [
        ('image59', 'image60', 2),
        ('00000000-0000-0000-0000-000000000002', BOOT, 1),
        ('8d985956203a1680c60819a1b071d47774ee82bbef71923817b0362bf138cae5', CAP_SHA, 1),
        ("'image': '59'", "'image': '60'", 2),
        ('= 59 ]', '= 60 ]', 1),
        ('trace-priority-worker01.sh', 'trace-priority-worker60-01.sh', 1),
    ]
    driver = texts['trace-priority-capture01.py']
    for old, new, count in replacements:
        if driver.count(old) != count:
            raise ValueError('Unexpected exact binding substitution: ' + old)
        driver = driver.replace(old, new)
    worker = texts['trace-priority-worker01.sh']
    if worker.count('= 59 ]') != 1:
        raise ValueError('Worker image pin boundary differs')
    worker = worker.replace('= 59 ]', '= 60 ]')
    # Only the explicit constants, labels and sibling worker basename differ.
    reversed_driver = driver
    for old, new, _ in reversed(replacements):
        reversed_driver = reversed_driver.replace(new, old)
    if reversed_driver != texts['trace-priority-capture01.py'] or worker.replace('= 60 ]', '= 59 ]') != texts['trace-priority-worker01.sh']:
        raise ValueError('Binding diff is not reversible')
    output.mkdir(parents=True, exist_ok=False)
    path = output / 'trace-priority-capture60-01.py'
    path.write_bytes(driver.encode())
    (output / 'trace-priority-worker60-01.sh').write_bytes(worker.encode())
    spec = importlib.util.spec_from_file_location('priority60_prepared', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = module.prepare(capability, output / 'packet')
    report = dict(classification='offline_separate_image60_capture_binding', executed=False,
                  capability_sha256=CAP_SHA, expected=cap['expected'], source59_pins=PINS,
                  driver_sha256=sha(driver.encode()), worker_template_sha256=sha(worker.encode()),
                  reversible_binding_only_diff=True, packet_plan=plan,
                  inspector_used_by_parent='work/trace-capability-image60-inspect02.py',
                  inspector_sha256=cap['analyzer_sha256'],
                  query_sha256=cap['probe_script_sha256'],
                  source59_unchanged=all(sha((BASE / n).read_bytes()) == h for n, h in PINS.items()))
    (output / 'binding.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output), indent=2))

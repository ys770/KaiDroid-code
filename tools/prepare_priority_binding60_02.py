"""Prepare a fresh image60 packet with pushed scripts and shell-v2 file launch."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(output):
    old = ROOT / 'work/memory/priority60-review01'
    driver = (old / 'trace-priority-capture60-01.py').read_bytes()
    worker = (old / 'trace-priority-worker60-01.sh').read_bytes()
    if sha(driver) != '3148352f1db06331df74469ae838ec69658d2255b4683c223377e3577a761942':
        raise ValueError('Frozen60 stdin driver changed')
    if sha(worker) != '20cfb75e3a41db3b91969c3b9fb43fd4b75ab943162c97fc6006e9568368ba45':
        raise ValueError('Frozen60 worker changed')
    text = driver.decode()
    start = text.index('def adb_call(')
    end = text.index('def inspect_archive(', start)
    text = text[:start] + text[end:]
    start = text.index('def run_action(')
    end = text.index('def main():', start)
    fragment = (ROOT / 'experiments/memory/trace-priority-file-transport01.py').read_text()
    text = text[:start] + fragment + '\n\n' + text[end:]
    if "['exec-out', 'sh', '-s']" in text or 'input=data' in text:
        raise ValueError('Legacy stdin call remains')
    output.mkdir(parents=True, exist_ok=False)
    path = output / 'trace-priority-capture60-02.py'
    path.write_bytes(text.encode())
    (output / 'trace-priority-worker60-01.sh').write_bytes(worker)
    spec = importlib.util.spec_from_file_location('priority60_files', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = module.prepare(ROOT / 'artifacts/runtime/image60-trace-capability02.json', output / 'packet')
    if plan['name'] == 'kaidroid-priority-b13354ec20be':
        raise ValueError('Failed packet identity reused')
    result = dict(classification='offline_image60_file_transport_binding', executed=False,
                  failed_packet_retained=str(old), capability_sha256=module.CAP_SHA,
                  expected=plan['expected'], driver_sha256=sha(text.encode()),
                  worker_template_sha256=sha(worker), fragment_sha256=sha(fragment.encode()),
                  packet_plan=plan, transport_action_deadline_seconds=45,
                  command_timeout_seconds=12, owned_client_stop_grace_seconds=3,
                  no_stdin_transport=True, remote_artifacts_retained=True,
                  worker_control_logic_unchanged=True)
    (output / 'binding.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    print(json.dumps(prepare(parser.parse_args().output), indent=2))

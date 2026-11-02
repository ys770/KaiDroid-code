"""Execute the worker against synthetic ordinary files under local Git Bash.

No ADB or build-host calls. This tests shell control flow, not Android/tracefs.
The two-second model deadline is deliberately shorter than production's10..45s.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASH = Path('bash')
spec = importlib.util.spec_from_file_location('capture', HERE / 'trace-priority-capture01.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


@unittest.skipUnless(BASH.is_file(), 'Requires local Git Bash; never invokes WSL/ADB')
class ShellModel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='priority-shell-')
        self.addCleanup(self.cleanup_model)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'tracefs'
        self.work = self.base / 'owned-output'
        self.work.mkdir()
        self.name = 'kaidroid-priority-0123456789ab'
        self.inst = self.root / 'instances' / self.name
        cap = json.loads((ROOT / 'artifacts/runtime/image59-trace-capability01.json').read_text())
        self.oom = cap['reads']['root0.oom_format']['value'].rstrip('\n') + '\n'
        # Minimal synthetic sched schemas test required-field gates only.
        self.formats = [self.oom, 'field:pid_t parent_pid;\nfield:pid_t child_pid;\n',
                        'field:pid_t pid;\nfield:pid_t old_pid;\nfield:char[] filename;\n',
                        'field:pid_t pid;\n']
        self.populate(self.root)
        self.populate(self.root / 'instances' / 'wifi', aggregate='X')
        (self.work / 'expected-oom-format.txt').write_bytes(self.oom.encode())
        for i, text in enumerate(self.formats):
            (self.base / f'format-{i}.txt').write_bytes(text.encode())
        self.worker = (HERE / 'trace-priority-worker01.sh').read_text()
        self.worker = self.worker.replace('root=/sys/kernel/tracing', f"root='{self.root.as_posix()}'")
        self.worker = self.worker.replace('alias=/sys/kernel/debug/tracing', 'alias="$root"')
        self.worker = self.worker.replace('set -eu\n', 'set -eu\nprintf \'%s\\n\' "$$" > "$work/supervisor-pid.txt"\n', 1)
        # Override only external observations and instance-population behavior.
        # Ordinary writes/cmp/ownership inode checks/timer/wait/traps remain real.
        self.helpers = f'''
getprop() {{ printf '59\\n'; }}
id() {{ printf '0\\n'; }}
grep() {{
  if [ "$1" = -F ] && [ "$2" = '[boot]' ] && [ "$3" = "$inst/trace_clock" ]; then
    printf '[boot]\\n'
  else command grep "$@"; fi
}}
cat() {{
  case "$1" in
    /proc/sys/kernel/random/boot_id) printf '%s\\n' "$boot" ;;
    /sys/devices/system/cpu/possible) printf '0-3\\n' ;;
    "$inst/trace_clock") printf '[boot]\\n' ;;
    "$inst/buffer_total_size_kb") printf '256\\n' ;;
    *) command cat "$@" ;;
  esac
}}
mkdir() {{
  command mkdir "$@" || return $?
  if [ "$1" = "$inst" ]; then
    printf '0\\n' > "$inst/tracing_on"
    printf 'nop\\n' > "$inst/current_tracer"
    command mkdir "$inst/events"
    printf '0\\n' > "$inst/events/enable"
    i=0
    for ev in $events; do
      command mkdir -p "$inst/events/$ev"
      printf '0\\n' > "$inst/events/$ev/enable"
      printf 'none\\n' > "$inst/events/$ev/filter"
      command cat '{self.base.as_posix()}'/format-$i.txt > "$inst/events/$ev/format"
      i=$((i+1))
    done
    printf 'synthetic trace only\\n' > "$inst/trace"
    command mkdir -p "$inst/per_cpu/cpu0"
    printf 'overrun: 0\\ncommit overrun: 0\\ndropped events: 0\\n' > "$inst/per_cpu/cpu0/stats"
  fi
}}
'''

    def cleanup_model(self):
        # A killed supervisor's surviving deadline child closes its inherited
        # log handles after its EXIT stop verification. Retry only that known
        # temporary directory, rather than suppressing a live-handle failure.
        limit = time.monotonic() + 4
        while True:
            try:
                self.tmp.cleanup()
                return
            except OSError:
                if time.monotonic() >= limit:
                    raise
                time.sleep(0.05)

    def populate(self, scope, aggregate='0'):
        scope.mkdir(parents=True)
        values = {'tracing_on': '0', 'current_tracer': 'nop', 'trace_clock': '[boot]',
                  'buffer_size_kb': '4', 'buffer_total_size_kb': '16', 'events/enable': aggregate}
        for key, value in values.items():
            path = scope / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((value + '\n').encode())
        for i, event in enumerate(capture.EVENTS):
            path = scope / 'events' / event
            path.mkdir(parents=True)
            (path / 'enable').write_bytes(b'0\n')
            (path / 'filter').write_bytes(b'none\n')
            (path / 'format').write_bytes(self.formats[i].encode())

    def start(self):
        prefix = (f"name='{self.name}'\nwork='{self.work.as_posix()}'\n"
                  f"boot='{capture.BOOT}'\nseconds='2'\n")
        path = self.base / 'worker-model.sh'
        path.write_bytes((prefix + self.helpers + self.worker).encode())
        self.stdout = (self.base / 'stdout.txt').open('wb')
        self.stderr = (self.base / 'stderr.txt').open('wb')
        self.addCleanup(self.stdout.close)
        self.addCleanup(self.stderr.close)
        proc = subprocess.Popen([str(BASH), '--noprofile', '--norc', str(path)],
                                stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def await_file(self, name, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if (self.work / name).is_file():
                return (self.work / name).read_text().strip()
            if name == 'armed.txt' and (self.work / 'finished.txt').is_file():
                break
            time.sleep(0.025)
        status = {p.name: p.read_text(errors='replace')[:200] for p in self.work.glob('*.txt')
                  if p.name in ('stderr.txt', 'cleanup.txt', 'supervisor-exit.txt', 'finished.txt')}
        self.fail(f'Missing {name}; status={status}; stderr=' + (self.base / 'stderr.txt').read_text(errors='replace'))

    def assert_stopped(self):
        self.assertEqual((self.inst / 'tracing_on').read_text().strip(), '0')
        for event in capture.EVENTS:
            self.assertEqual((self.inst / 'events' / event / 'enable').read_text().strip(), '0')
        self.assertEqual((self.root / 'tracing_on').read_text().strip(), '0')
        self.assertEqual((self.root / 'instances/wifi/events/enable').read_text().strip(), 'X')

    def test_normal_deadline_retains_own_trace_and_compares_metadata(self):
        proc = self.start()
        self.assertEqual(self.await_file('armed.txt'), 'armed')
        self.assertEqual(self.await_file('finished.txt'), 'finished')
        self.assertEqual(proc.wait(timeout=3), 0)
        self.assertEqual(self.await_file('cleanup.txt'), 'instance_retained_stopped')
        self.assertEqual(self.await_file('protected-comparison.txt'), 'equal')
        self.assertEqual(self.await_file('deadline.txt'), 'deadline_stopped')
        self.assertEqual((self.work / 'trace.txt').read_text().strip(), 'synthetic trace only')
        self.assert_stopped()

    def test_killed_supervisor_child_still_stops(self):
        proc = self.start()
        self.await_file('armed.txt')
        pid = self.await_file('supervisor-pid.txt')
        self.assertTrue(pid.isdigit())
        subprocess.run([str(BASH), '--noprofile', '--norc', '-c', 'kill -KILL ' + pid],
                       timeout=3, check=True, capture_output=True)
        proc.wait(timeout=3)
        self.assertEqual(self.await_file('deadline.txt'), 'deadline_stopped')
        self.assert_stopped()
        self.assertFalse((self.work / 'finished.txt').exists())

    def test_existing_instance_collision_never_stopped_or_deleted(self):
        self.populate(self.inst)
        (self.inst / 'tracing_on').write_bytes(b'1\n')
        proc = self.start()
        self.await_file('finished.txt')
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertEqual(self.await_file('cleanup.txt'), 'no_instance_created')
        self.assertEqual((self.inst / 'tracing_on').read_text().strip(), '1')
        self.assertFalse((self.work / 'armed.txt').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)

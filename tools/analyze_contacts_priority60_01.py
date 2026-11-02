"""Offline exact-capture priority/lifetime analysis; no device or host calls."""
import argparse
from collections import Counter
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA = '892ff2dd41e19bb7f376fa2c7015270f143a52b9e1d4a481d2d7797d9b8c316b'
BOOT = '00000000-0000-0000-0000-000000000007'
TARGETS = {1858: 'Contacts', 1901: 'acore', 1946: 'first_permission_controller', 1982: 'replacement_permission_controller'}
TRACE = re.compile(r'^\s*(?P<comm>.+)-(?P<writer>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+(?P<time>\d+\.\d+): (?P<event>\w+): (?P<payload>.*)$')
LOG = re.compile(r'^\s*(\d+\.\d+)\s+(\d+)\s+(\d+)\s+([A-Z])\s+([^:]+): (.*)$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ns(text):
    return int(Decimal(text) * 1000000000)


def ms(nanoseconds):
    return float(Decimal(nanoseconds) / 1000000)


def parse_trace(text):
    rows = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith('#'):
            continue
        match = TRACE.fullmatch(line)
        if not match:
            raise ValueError('Unparsed trace row ' + str(line_number))
        item = dict(line=line_number, boot_ns=ns(match['time']), timestamp=match['time'],
                    writer_tid=int(match['writer']), cpu=int(match['cpu']), event=match['event'],
                    payload=match['payload'])
        if item['event'] == 'oom_score_adj_update':
            payload = re.fullmatch(r'pid=(\d+) comm=(.*?) oom_score_adj=(-?\d+)', item['payload'])
            if not payload:
                raise ValueError('Unparsed OOM target payload')
            item.update(target_pid=int(payload[1]), target_comm=payload[2], oom_score_adj=int(payload[3]))
        elif item['event'] == 'sched_process_fork':
            payload = re.fullmatch(r'comm=(.*?) pid=(\d+) child_comm=(.*?) child_pid=(\d+)', item['payload'])
            if not payload:
                raise ValueError('Unparsed fork payload')
            item.update(parent_pid=int(payload[2]), target_pid=int(payload[4]))
        elif item['event'] == 'sched_process_exit':
            payload = re.fullmatch(r'comm=(.*?) pid=(\d+) prio=(-?\d+)', item['payload'])
            if not payload:
                raise ValueError('Unparsed exit payload')
            item.update(target_pid=int(payload[2]))
        rows.append(item)
    return rows


def read_archive(path):
    data = path.read_bytes()
    if sha(data) != ARCHIVE_SHA:
        raise ValueError('Exact parent capture archive required')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for item in archive.getmembers():
            name = item.name.removeprefix('./')
            if item.isdir() and name in ('', '.'):
                continue
            if not item.isfile() or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in files or item.size > 4194305:
                raise ValueError('Unexpected archive member')
            files[name] = archive.extractfile(item).read()
    return files


def parse_sample(text):
    lines = text.splitlines()
    result = dict(uptime=lines[0].split()[0],
                  meminfo_KiB={k: int(v) for k, v in re.findall(r'^(MemFree|MemAvailable|SwapFree):\s+(\d+) kB$', text, re.M)},
                  processes=[])
    for block in re.split(r'^PROCESS ', text, flags=re.M)[1:]:
        rows = block.splitlines()
        command, pid = rows[0].rsplit(' ', 1)
        fields = rows[1].rsplit(')', 1)[1].split()
        status = {k: int(v) for k, v in re.findall(r'^(VmRSS|VmSwap):\s+(\d+) kB$', block, re.M)}
        result['processes'].append(dict(command=command, pid=int(pid), start_ticks=int(fields[19]),
                                        minflt=int(fields[7]), majflt=int(fields[9]),
                                        oom_score_adj=int(rows[2]), **status))
    return result


def run():
    folder = ROOT / 'artifacts/runtime/image60-contacts-priority02'
    packet = ROOT / 'work/memory/priority60-review03/packet'
    files = read_archive(packet / 'capture.tar')
    statuses = {'cleanup.txt': 'instance_retained_stopped', 'deadline.txt': 'deadline_stopped',
                'timer-exit.txt': '0', 'supervisor-exit.txt': '0', 'finished.txt': 'finished',
                'protected-comparison.txt': 'equal', 'trace-bound.txt': 'within_4MiB_bound'}
    if any(files[k].decode().strip() != v for k, v in statuses.items()):
        raise ValueError('Capture cleanup/completeness state differs')
    summary = json.loads((packet / 'capture-result.json').read_text(encoding='utf-8'))
    if summary['archive_sha256'] != ARCHIVE_SHA or summary['loss_status'] != 'observed_counters_zero':
        raise ValueError('Capture summary/loss status differs')
    if not summary['file_transport_pre_post_identity_verified']:
        raise ValueError('Transport identity incomplete')
    if not (files['protected-before.txt'] == files['protected-prearm.txt'] == files['protected-after.txt']):
        raise ValueError('Protected metadata bytes differ')
    loss = {}
    for block in re.split(r'(?m)^cpu', files['loss-stats.txt'].decode())[1:]:
        cpu, _, rest = block.partition('\n')
        loss[cpu] = {}
        for key in ('overrun', 'commit overrun', 'dropped events'):
            found = re.findall(r'^' + re.escape(key) + r':\s*(\d+)\s*$', rest, re.M)
            if len(found) != 1:
                raise ValueError('Unknown/ambiguous per-CPU loss counter')
            loss[cpu][key] = int(found[0])
    if set(loss) != {'0', '1', '2', '3'} or loss != summary['loss_counters'] or any(any(v.values()) for v in loss.values()):
        raise ValueError('Raw loss counters disagree')
    if '[boot]' not in files['trace-clock.txt'].decode().split():
        raise ValueError('Trace clock differs')
    format_names = ('oom_score_adj_update', 'sched_process_fork', 'sched_process_exec', 'sched_process_exit')
    for i, name in enumerate(format_names):
        if not files[f'format-{i}.txt'].decode().startswith('name: ' + name + '\n'):
            raise ValueError('Runtime event format/name differs')
    expected_identity = ['DEVICE_SERIAL_REQUIRED', '60', BOOT, 'Enforcing', '538 1166 1339']
    for name in ('before.stdout', 'after.stdout', 'cleanup-guard.stdout', 'ready-guard.stdout'):
        if (folder / name).read_text(encoding='utf-8').splitlines() != expected_identity:
            raise ValueError('Stimulus identity drift: ' + name)
    trace = files['trace.txt'].decode()
    rows = parse_trace(trace)
    header = re.search(r'entries-in-buffer/entries-written: (\d+)/(\d+)', trace)
    if not header or int(header[1]) != len(rows) or header[1] != header[2]:
        raise ValueError('Trace row/header counts differ')
    marker = [r for r in rows if r['event'] == 'tracing_mark_write' and
              r['payload'] == 'KAIDROID_PRIORITY_ARM_kaidroid-priority-f64a3bdb8511']
    if len(marker) != 1:
        raise ValueError('Unique exact marker required')
    before = ns(files['realtime-before.txt'].decode().strip())
    after = ns(files['realtime-after.txt'].decode().strip())
    if after < before:
        raise ValueError('Wall clock bracket reversed')
    # Trace timestamps print microseconds; conservatively expand by1us.
    offset = [before - marker[0]['boot_ns'] - 1000, after - marker[0]['boot_ns'] + 1000]
    raw_log = (folder / 'fresh-log.stdout').read_text(encoding='utf-8')
    logs = []
    for line_number, line in enumerate(raw_log.splitlines(), 1):
        match = LOG.fullmatch(line)
        if match:
            epoch = ns(match[1])
            logs.append(dict(line=line_number, epoch=match[1], epoch_ns=epoch, pid=int(match[2]),
                             tid=int(match[3]), tag=match[5].strip(), message=match[6],
                             boot_ns_interval=[epoch - offset[1] - 1000000, epoch - offset[0] + 1000000]))
    lifetimes = {}
    kills = []
    for pid, label in TARGETS.items():
        fork = [r for r in rows if r['event'] == 'sched_process_fork' and r.get('target_pid') == pid]
        exits = [r for r in rows if r['event'] == 'sched_process_exit' and r.get('target_pid') == pid]
        writes = [r for r in rows if r['event'] == 'oom_score_adj_update' and r.get('target_pid') == pid]
        if len(fork) != 1 or len(exits) > 1:
            raise ValueError('Ambiguous target lifetime')
        end = exits[0] if exits else None
        if any(r['boot_ns'] < fork[0]['boot_ns'] or (end and r['boot_ns'] > end['boot_ns']) for r in writes):
            raise ValueError('OOM event outside bound lifetime')
        lifetimes[str(pid)] = dict(label=label, fork=fork[0], leader_exit=end, oom_writes=writes,
                                  fork_to_leader_exit_ms=ms(end['boot_ns'] - fork[0]['boot_ns']) if end else None,
                                  first_write_after_fork_ms=ms(writes[0]['boot_ns'] - fork[0]['boot_ns']) if writes else None)
    for log in logs:
        match = re.fullmatch(r"Kill '([^']+)' \((\d+)\), uid (\d+), oom_adj (-?\d+) to free (\d+)kB", log['message'])
        if log['tag'] == 'lowmemorykiller' and match:
            kills.append(dict(**log, target_pid=int(match[2]), target_name=match[1],
                              oom_score_adj=int(match[4]), reported_kB=int(match[5])))
    samples = {p.name: parse_sample(p.read_text(encoding='utf-8')) for p in sorted(folder.glob('sample-*.stdout'))}
    sample_changes = {}
    for pid in (1858, 1982):
        observations = [(v, p) for v in sorted(samples.values(), key=lambda x: ns(x['uptime']))
                        for p in v['processes'] if p['pid'] == pid]
        if len(observations) != 4 or len({p['start_ticks'] for _, p in observations}) != 1:
            raise ValueError('Sampled target lifetime incomplete/reused')
        first_sample, last_sample = observations[0], observations[-1]
        sample_changes[str(pid)] = dict(first_uptime=first_sample[0]['uptime'], last_uptime=last_sample[0]['uptime'],
            start_ticks=first_sample[1]['start_ticks'],
            major_fault_delta=last_sample[1]['majflt'] - first_sample[1]['majflt'],
            VmSwap_delta_KiB=last_sample[1]['VmSwap'] - first_sample[1]['VmSwap'])
    permission_lines = {}
    for key in ('before', 'after'):
        text = (folder / ('package-' + key + '.stdout')).read_text(encoding='utf-8')
        permission_lines[key] = sorted(re.findall(r'^\s+(android\.permission\.\S+: granted=\w+, flags=\[.*\])\s*$', text, re.M))
    if not permission_lines['before'] or not permission_lines['after']:
        raise ValueError('No permission grant/flag observations')
    highlights = [r for r in logs if any(x in r['message'] for x in (
        'Start proc 1858:', 'Start proc 1901:', 'Start proc 1946:', 'Start proc 1982:',
        'pid 1946) has died', 'pid 1901) has died', 'Exception when starting activity',
        'Displayed com.android.permissioncontroller', 'Configured tracing session 3',
        'Tracing session 3 ended', 'Perfetto TraceBuffer saved to file:', 'Producer stop (id=3)'))]
    inputs = {p.name: sha(p.read_bytes()) for p in sorted(folder.iterdir()) if p.is_file()}
    first = lifetimes['1946']
    last = lifetimes['1982']
    cached_write = first['oom_writes'][0]
    kill = next(x for x in kills if x['target_pid'] == 1946)
    return dict(classification='offline_exact_image60_contacts_priority_trace', boot=BOOT,
                archive_sha256=ARCHIVE_SHA, archive_file_sha256={k: sha(v) for k, v in files.items()},
                raw_stimulus_inputs_sha256=inputs, capture_summary=summary,
                trace_records=len(rows), trace_event_counts=dict(Counter(r['event'] for r in rows)),
                trace_timestamps_nondecreasing=all(a['boot_ns'] <= b['boot_ns'] for a, b in zip(rows, rows[1:])),
                trace_first_boot_ns=rows[0]['boot_ns'], trace_last_boot_ns=rows[-1]['boot_ns'],
                marker=marker[0], wall_before_ns=before, wall_after_ns=after,
                anchor_bracket_width_ms=ms(after - before), offset_epoch_minus_boot_ns=offset,
                log_timestamp_uncertainty_ns=1000000, log_first_epoch=logs[0]['epoch'], log_last_epoch=logs[-1]['epoch'],
                lifetimes=lifetimes, lmk_records=kills, highlights=highlights, samples=samples,
                sampled_lifetime_changes=sample_changes,
                runtime_event_formats={name: files[f'format-{i}.txt'].decode() for i, name in enumerate(format_names)},
                first_controller_cached_write_to_leader_exit_ms=ms(first['leader_exit']['boot_ns'] - cached_write['boot_ns']),
                first_controller_cached_write_to_lmk_log_ms_interval=[ms(t - cached_write['boot_ns']) for t in kill['boot_ns_interval']],
                replacement_fork_after_first_leader_exit_ms=ms(last['fork']['boot_ns'] - first['leader_exit']['boot_ns']),
                observed_permission_grant_flag_lines_equal=permission_lines['before'] == permission_lines['after'],
                permission_line_count=len(permission_lines['before']),
                home_window_restored=(folder / 'focus-before.stdout').read_text(encoding='utf-8').strip() == (folder / 'home-after.stdout').read_text(encoding='utf-8').strip(),
                operator_stimulus=json.loads((folder / 'stimulus.json').read_text(encoding='utf-8')),
                launch_output=(folder / 'launch.stdout').read_text(encoding='utf-8'),
                first_controller_observed_adj0_write=False if all(r['oom_score_adj'] != 0 for r in first['oom_writes']) else True,
                actual_priority_bug_cause_proven=False, matched_memory_saving_proven=False,
                limits=['Trace common_pid/task prefix is writer TID; oom payload pid is the target.',
                        'Zero observed ring loss does not establish event delivery or absence of an unobserved transition.',
                        'Log wall times use the marker bracket plus conservative timestamp precision; no exact point offset.',
                        'Fork/exit events bind leader lifetime, not every thread or process-reap completion.',
                        'Initial inherited OOM score before first observed write is not measured.',
                        'No provider published/binding references, pending-top ownership or AMS internal adj reason was captured.',
                        'IORAP/Perfetto five-second session configures4096KB; resident cost/causality not measured.',
                        'Fresh main/system log ends before late replacement controller exit; its cause is unattributed.',
                        'am-start TotalTime ends at RequestPermissionsActivity, not final GrantPermissionsActivity readiness.',
                        'MemAvailable/VmRSS/VmSwap and reported LMK kill sizes are not unique freed physical pages or a frozen comparison.',
                        'Permission flag observations and no operator choices do not prove database byte/logical preservation.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = run()
    result['analyzer_sha256'] = sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('trace_records', 'anchor_bracket_width_ms',
          'first_controller_cached_write_to_leader_exit_ms', 'replacement_fork_after_first_leader_exit_ms',
          'observed_permission_grant_flag_lines_equal', 'home_window_restored')}, indent=2))

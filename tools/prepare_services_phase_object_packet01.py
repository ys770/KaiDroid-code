"""Create a reviewable compile-only matrix packet locally; no host execution mode."""
import argparse
import json
import shutil
from pathlib import Path
import services_phase_object_contract01 as c
import prepare_services_phase_diagnostics01 as p

ROOT = Path(__file__).resolve().parents[1]


def prepare(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        raise ValueError('Fresh workspace packet directory required')
    record_path = ROOT / 'work/memory/libart-compile03/compile-record.json'
    commands_path = ROOT / 'work/memory/libart-query01/commands.stdout'
    if c.sha(record_path) != c.COMPILE_RECORD or c.sha(commands_path) != c.COMMANDS:
        raise ValueError('Exact compile03 record/commands required')
    record = json.loads(record_path.read_text())
    phase = json.loads((ROOT / 'experiments/memory/services-phase-diagnostics01.json').read_text())
    if phase['generator_sha256'] != c.sha(ROOT / 'tools/prepare_services_phase_diagnostics01.py'):
        raise ValueError('Phase generator provenance differs')
    receipts = [
        (record_path, 'compile-record.json', c.COMPILE_RECORD),
        (commands_path, 'commands.stdout', c.COMMANDS),
        (ROOT / 'work/memory/libart-query01/toolchain.json', 'toolchain.json', 'db6ae131551701400ae59e98bb1c3ea42e3d3a2b85d9ab998f4dff28a0f0335b'),
        (ROOT / 'work/memory/libart-runtime-readelf01/runtime-container02.json', 'runtime-container02.json', '36a5f42172acab9732cdc09c81ce146084e3803aebee84a9fee97b1ab24fa566'),
        (ROOT / 'work/memory/reconstruction-source-inputs01/receipt.json', 'source-acquisition01.json', p.ACQUISITION_SHA),
        (ROOT / 'work/memory/reconstruction-source-inputs02/receipt.json', 'source-acquisition02.json', c.ACQUISITION2),
    ]
    for path, _, pin in receipts:
        if c.sha(path) != pin:
            raise ValueError('Receipt differs: ' + str(path))
    for number in ('01', '02'):
        base = ROOT / ('work/memory/reconstruction-source-inputs' + number)
        receipt = json.loads((base / 'receipt.json').read_text())
        for row in receipt['files']:
            if c.sha(base / 'source' / row['path']) != row['sha256']:
                raise ValueError('Acquired source/header drift')
            if row['compile03_read_input_sha256'] is not None and record['read_inputs'][c.HOST_ROOT + '/aosp/' + row['path']] != row['sha256']:
                raise ValueError('Compiled header receipt differs')
    commands = commands_path.read_text().splitlines()
    if len(commands) != 3:
        raise ValueError('Original three-command receipt differs')
    actual_first = (ROOT / 'work/memory/libart-compile03/compile.stdout').read_text().splitlines()[0]
    if c.compile_argv(actual_first.removeprefix('[1/3] ')) != c.compile_argv(commands[0]):
        raise ValueError('Recorded executed command differs from frozen query')
    sources = {}
    for image, (relative, pin) in p.SOURCES.items():
        path = ROOT / relative
        if c.sha(path) != pin:
            raise ValueError('Manager source differs')
        source, additions = p.transform(path.read_text(), image)
        expected = next(row for row in phase['sources'] if row['image'] == image)
        if __import__('hashlib').sha256(source.encode()).hexdigest() != expected['candidate_sha256']:
            raise ValueError('Reviewed phase source differs')
        projected = source
        for addition in reversed(additions):
            projected = projected.replace(addition, '', 1)
        if projected != path.read_text():
            raise ValueError('Diagnostics off changes original source')
        sources[image] = source
    plan = dict(
        classification='compile_only_handoff_not_executed', stage=c.NAME,
        backing=c.BACKING, builder=c.BUILDER, source_contract=phase,
        original_compile_environment={'PWD': '/proc/self/cwd'}, cwd='/build/aosp',
        runtime_environment={'TMPDIR': '/work/tmp', 'PYTHONDONTWRITEBYTECODE': '1'},
        roles={role: c.matrix(commands[0], role) for role in c.ROLES},
        resources=dict(cpus=[0, 1], cpu_quota=2, memory_bytes=8 * 1024**3,
                       memory_swap_total_bytes=8 * 1024**3, pids=512,
                       deadline_seconds=c.DEADLINE, growth_bytes=c.GROWTH,
                       root_and_external_free_floor_bytes=c.FLOOR),
        sequential_roles=list(c.ROLES), source_overlay_readonly=True,
        root_bind_recursive_readonly_required=True, actual_mount_probe_performed=False,
        shared_tree_and_outputs_readonly=True, cache_copy_required=False,
        ninja_invoked=False, link_or_strip_commands_included=False,
        executed=False, native_assembly_is_final_ThinLTO_lowering=False,
        unresolved=['Actual new dependency closure must be checked after each phase; any unreceipted header stops the job.',
                    'Cached time/heap implementation and ClassLinker/assistant compiled-TU provenance remain unproven.',
                    'Compile-only output cannot establish final ThinLTO linked code, ABI, runtime stability, or memory savings.',
                    'Fresh external bind, free space, host idleness, exact builder, and PID1 service identity require future host verification.'])
    output.mkdir(parents=True)
    for directory in ('sources', 'receipts', 'tools'):
        (output / directory).mkdir()
    for image, source in sources.items():
        (output / 'sources' / ('image' + image + '.cc')).write_bytes(source.encode())
    for path, name, _ in receipts:
        shutil.copyfile(path, output / 'receipts' / name)
    for name in ('services_phase_object_contract01.py', 'services_phase_object_job01.py'):
        shutil.copyfile(ROOT / 'tools' / name, output / 'tools' / name)
    c.dump(output / 'plan.json', plan)
    files = {path.relative_to(output).as_posix(): c.sha(path) for path in output.rglob('*') if path.is_file()}
    c.dump(output / 'manifest.json', dict(files=files, compile_only=True, executed=False))
    pin = c.sha(output / 'manifest.json')
    handoff = {}
    for role in c.ROLES:
        _, unit = c.identities(role)
        stage = c.HOST_ROOT + '/' + c.NAME
        watch = ['sudo', '-n', 'systemd-run', '--unit=' + unit, '--service-type=exec',
                 '--property=User=root', '--property=Group=root', '--property=StandardInput=null',
                 '--property=StandardOutput=append:' + stage + '/control/' + role + '/watchdog.log',
                 '--property=StandardError=append:' + stage + '/control/' + role + '/watchdog.log',
                 '--property=WorkingDirectory=' + stage, '--property=RuntimeMaxSec=1900',
                 '--property=MemoryMax=512M', '--property=TasksMax=32', '--', '/usr/bin/python3', '-B',
                 stage + '/inputs/tools/services_phase_object_job01.py', 'watch',
                 '--role', role, '--packet-sha', pin]
        handoff[role] = dict(docker_argv=c.docker_argv(role, pin), supervisor_argv=watch,
                            prelaunch_argv=['/usr/bin/python3', '-B', stage + '/inputs/tools/services_phase_object_job01.py', 'role-check', '--role', role, '--packet-sha', pin],
                            bind_argv_template=['/usr/bin/python3', '-B', stage + '/inputs/tools/services_phase_object_job01.py', 'bind', '--role', role, '--packet-sha', pin, '--container-id', 'EXACT_RETURNED_64_HEX_CID'],
                            required_order='host preflight; role-check; start exact container; bind returned CID; start PID1 service; follow same handles to terminal; no automatic relaunch')
    probe = c.docker_argv('55-off', pin)
    probe[probe.index('--name') + 1] += '-mountprobe'
    probe[probe.index('inside')] = 'mount-check'
    c.dump(output / 'handoff.json', dict(packet_sha256=pin, roles=handoff,
           host_preflight_argv=['/usr/bin/python3', '-B', c.HOST_ROOT + '/' + c.NAME + '/inputs/tools/services_phase_object_job01.py', 'preflight', '--packet-sha', pin],
           same_layout_mount_probe_argv=probe, mount_probe_must_pass_before_compile=True, executed=False))
    return dict(classification=plan['classification'], packet_sha256=pin,
                packet_directory=output.relative_to(ROOT).as_posix(),
                role_count=4, compiler_commands_per_role=3, executed=False, linked=False,
                ready_for_host_execution_without_review=False, handoff_sha256=c.sha(output / 'handoff.json'),
                generator_sha256=c.sha(Path(__file__)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output_dir)))

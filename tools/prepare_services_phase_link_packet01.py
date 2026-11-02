"""Freeze an offline link execution packet; generate argv data, execute nothing."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
from pathlib import Path
import shutil
import services_phase_link_contract01 as c


def prepare(source, output):
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.exists() or source == output or source in output.parents:
        raise ValueError('A fresh independent output directory is required')
    if c.sha(source / 'manifest.json') != c.FROZEN:
        raise ValueError('Only frozen plan04 may be wrapped')
    manifest = json.loads((source / 'manifest.json').read_text())
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
    if any(p.is_symlink() for p in source.rglob('*')) or actual != set(manifest['files']) | {'manifest.json'}:
        raise ValueError('Frozen source closure differs')
    for name, pin in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or c.sha(source / name) != pin:
            raise ValueError('Frozen source content differs')
    output.mkdir()
    for name in manifest['files']:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    shutil.copyfile(source / 'manifest.json', output / 'frozen-plan-manifest.json')
    (output / 'tools').mkdir()
    for name in ('services_phase_link_contract01.py', 'services_phase_link_job01.py'):
        shutil.copyfile(Path(__file__).parent / name, output / 'tools' / name)
    files = {p.relative_to(output).as_posix(): c.sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    c.dump(output / 'manifest.json', dict(files=files, frozen_plan_manifest_sha256=c.FROZEN,
                                        execution_driver_status='implemented_offline_unexecuted', executed=False))
    pin = c.sha(output / 'manifest.json')
    script = c.ROOT + '/' + c.NAME + '/inputs/tools/services_phase_link_job01.py'

    def host(mode, role=None):
        args = ['/usr/bin/python3', '-B', script, mode, '--packet-sha', pin]
        return args + (['--role', role] if role else [])

    jobs = {}
    for role in c.ROLES:
        name, unit = c.identity(role)
        control = c.ROOT + '/' + c.NAME + '/control/' + role
        watcher = ['sudo', '-n', 'systemd-run', '--unit=' + unit, '--service-type=exec',
                   '--property=User=root', '--property=RuntimeMaxSec=1900', '--property=MemoryMax=512M',
                   '--property=TasksMax=32', '--property=StandardInput=null',
                   '--property=StandardOutput=append:' + control + '/watch.stdout',
                   '--property=StandardError=append:' + control + '/watch.stderr'] + host('watch', role)
        jobs[role] = dict(container=name, unit=unit, role_check_argv=host('role-check', role),
                          docker_argv=c.docker(role, pin), bind_argv_prefix=host('bind', role) + ['--container-id'],
                          watcher_argv=watcher, read_only_mount_probe_argv=c.docker(role, pin, probe=True))
    handoff = dict(packet_sha256=pin, frozen_plan_manifest_sha256=c.FROZEN, stage=c.ROOT + '/' + c.NAME,
                   backing=c.BACKING, preflight_argv=host('preflight'), roles=list(c.ROLES), jobs=jobs,
                   procedure=['Parent alone stages inputs and exact external bind under the reviewed lease.',
                              'Run preflight once as UID1000; retain any failed stage without reset or deletion.',
                              'For each role in order, run role-check. Optionally run the separate mount probe after preflight and wait for its terminal exit; retain it.',
                              'Run docker_argv and capture its exact full CID; append CID to bind_argv_prefix.',
                              'Run watcher_argv. The container cannot link before the root PID1 barrier.',
                              'Wait for watcher terminal.json success before the next role. Never retry a used identity.',
                              'Export all control/work evidence. Perform final code and ABI review before any installation.'],
                   executed=False, final_code_ABI_review_complete=False, installed=False, savings_proven=False)
    c.dump(output / 'handoff.json', handoff)
    c.packet(output.resolve(), pin)
    return dict(path=str(output), packet_sha256=pin, handoff_sha256=c.sha(output / 'handoff.json'), executed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))

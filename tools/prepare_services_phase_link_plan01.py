"""Freeze local link recipes/RSP/payload inputs for review. No host or linker execution mode."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import sys

sys.dont_write_bytecode = True
from audit_services_phase_link_providers01 import ROOT, HOST, REL, TIME, STREAM, COMPARE, ACCESSORS, sha

NAME = 'memory-services-phase-link01'
BACKING = '/mnt/ext1/kaidroid-services-phase-link01'
ROLES = ('55-off', '55-on', '56-off', '56-on')
STATIC = '/build/' + REL + 'android_arm_armv7-a-neon_static_com.android.art.release/obj/art/runtime/oat_file_manager.o'
OLD_LINK = '/build/' + REL + 'android_arm_armv7-a-neon_shared_com.android.art.release/unstripped/libart.so'
OLD_STRIP = '/build/' + REL + 'android_arm_armv7-a-neon_shared_com.android.art.release/libart.so'
OLD_RSP = OLD_LINK + '.rsp'
TRACE = [TIME, STREAM, COMPARE] + ACCESSORS['oat.o'] + ACCESSORS['oat_file.o']
PINS = {
    'commands.stdout': '73a492f7b5cfe7b3b57048e09cbeff2fe607f1d5fd89206cbe960e4cead5ac2a',
    'libart.so.rsp': '644f74f0ddf43142a52b440e4c2a282048248b5d8ddf96c7b573aca1000d18bf',
    'strip.sh': '4ee69021598b68bb07ae4a14c07e1f369fec747d1af686c5557db4b48a2f5ff9',
}


def response(original, role):
    if role not in ROLES or original.count(STATIC) != 1:
        raise ValueError('Exactly one reviewed manager RSP slot required')
    before = shlex.split(original)
    if len(before) != 257 or len(set(before)) != 257 or any(not name.startswith('/build/' + REL) or not name.endswith('.o') for name in before):
        raise ValueError('Exact 257-object response shape required')
    target = '/inputs/payload/' + role + '/oat_file_manager.o'
    result = original.replace(STATIC, target, 1)
    after = shlex.split(result)
    if [i for i, pair in enumerate(zip(before, after)) if pair[0] != pair[1]] != [145]:
        raise ValueError('Only original manager slot145 may change')
    return result


def recipes(commands, role, help_text):
    if role not in ROLES or len(commands) != 3:
        raise ValueError('Exact role/three-command receipt required')
    link = shlex.split(commands[1])
    if link[0] != 'prebuilts/clang/host/linux-x86/clang-r383902b/bin/clang++' or link.count('@' + OLD_RSP) != 1 or link.count('-o') != 1 or link[link.index('-o') + 1] != OLD_LINK:
        raise ValueError('Original link invocation differs')
    for option in ('--no-threads', '--thinlto-jobs=<value>', '--Map=<value>', '--trace-symbol=<value>', '--no-demangle'):
        if option not in help_text:
            raise ValueError('Pinned LLD11 help does not support ' + option)
    for option in ('-flto=thin', '-fsplit-lto-unit', '-Wl,--no-undefined', '-Wl,--fatal-warnings', '-Wl,-soname,libart.so'):
        if option not in link:
            raise ValueError('Original link policy differs')
    link[link.index('@' + OLD_RSP)] = '@/inputs/rsp/' + role + '.rsp'
    link[link.index('-o') + 1] = '/work/unstripped/libart.so'
    additions = ['-Wl,--no-threads', '-Wl,--thinlto-jobs=1', '-Wl,--Map=/work/link.map', '-Wl,--no-demangle']
    additions += ['-Wl,--trace-symbol=' + symbol for symbol in TRACE]
    link += additions
    strip = shlex.split(commands[2])
    environment = dict(word.split('=', 1) for word in strip[:3])
    if set(environment) != {'CROSS_COMPILE', 'XZ', 'CLANG_BIN'} or strip[3:6] != ['build/soong/scripts/strip.sh', '--add-gnu-debuglink', '--keep-symbols-and-debug-frame']:
        raise ValueError('Original strip mode differs')
    strip = strip[3:]
    expected = {'-i': OLD_LINK, '-o': OLD_STRIP, '-d': OLD_STRIP + '.d'}
    rewritten = {'-i': '/work/unstripped/libart.so', '-o': '/work/stripped/libart.so', '-d': '/work/stripped/libart.so.d'}
    for key in expected:
        if strip.count(key) != 1 or strip[strip.index(key) + 1] != expected[key]:
            raise ValueError('Original strip input/output differs')
        strip[strip.index(key) + 1] = rewritten[key]
    return dict(cwd='/build/aosp', link=dict(argv=link, stdout='/work/link.stdout', stderr='/work/link.stderr',
                environment={'TMPDIR': '/work/tmp', 'PWD': '/build/aosp'}),
                strip=dict(argv=strip, environment={**environment, 'TMPDIR': '/work/tmp', 'PWD': '/build/aosp'},
                           stdout='/work/strip.stdout', stderr='/work/strip.stderr'),
                explicit_link_deviations=additions,
                strip_mode_unchanged=True, shell_command_strings_used=False)


def input_closure(commands, rsp, cache, read_inputs):
    result = {}
    for target in shlex.split(rsp):
        if target == STATIC:
            continue
        key = target[len('/build/' + REL):]
        row = cache[key]
        result[target] = dict(kind='unchanged-cache-object', sha256=row['sha256'], size=row['size'])
    original = shlex.split(commands[1])
    output = original[original.index('-o') + 1]
    for token in original[1:]:
        if token == output or token.startswith(('-', '@')) or not token.endswith(('.o', '.a', '.so')):
            continue
        target = token if token.startswith('/build/') else '/build/aosp/' + token
        host = HOST + target[len('/build'):]
        if host not in read_inputs:
            raise ValueError('Unreceipted explicit link input ' + target)
        result[target] = dict(kind='explicit-' + target.rsplit('.', 1)[1], sha256=read_inputs[host])
    if sum(row['kind'] == 'unchanged-cache-object' for row in result.values()) != 256 or len(result) != 280:
        raise ValueError('Link object/library closure count differs')
    return result


def prepare(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        raise ValueError('Fresh local workspace plan directory required')
    for protected in ('work/services-phase-matrix02-results', 'work/memory/services-phase-link-provider-inputs01',
                      'work/memory/services-phase-object-packet06'):
        if output.is_relative_to((ROOT / protected).resolve()):
            raise ValueError('Do not place derived plans inside original input trees')
    query = ROOT / 'work/memory/libart-query01'
    for name, pin in PINS.items():
        if sha(query / name) != pin:
            raise ValueError('Original query/strip receipt differs')
    compile_path = ROOT / 'work/memory/libart-compile03/compile-record.json'
    cache_path = ROOT / 'work/memory/libart-dryrun02/inputs/cache-before.json'
    if sha(compile_path) != '21ddab6bdeaa492338fe49002800a26a88be3c77beede1f5eb25cea16442f8bc' or sha(cache_path) != '6f8aae65041588b8e5a71c5c7fa1979cb7892f3a015c5c156f15c85148a37c33':
        raise ValueError('Original read/cache receipts differ')
    compile_record = json.loads(compile_path.read_text())
    cache = json.loads(cache_path.read_text())
    help_path = ROOT / 'work/memory/services-phase-link-tool-help01/receipt.json'
    if sha(help_path) != '7ed3716f10f07e3a1894fc4f4177e63cb16b9f5c801b371840b743a1cef9b8c4':
        raise ValueError('Exact LLD11 help receipt required')
    help_record = json.loads(help_path.read_text())
    if help_record['sha256'] != compile_record['read_inputs'][help_record['source']] or help_record['--help']['returncode'] or help_record['--version']['returncode']:
        raise ValueError('Tool-help provenance differs')
    provider_path = ROOT / 'experiments/memory/services-phase-link-providers01.json'
    provider = json.loads(provider_path.read_text())
    if provider['analyzer_sha256'] != sha(ROOT / 'tools/audit_services_phase_link_providers01.py') or not provider['all_nine_names_have_expected_byte_pinned_providers']:
        raise ValueError('Provider audit stale/incomplete')
    terminal_path = ROOT / 'docs/evidence/services-phase-matrix02-terminal01.json'
    terminal = json.loads(terminal_path.read_text())
    review_path = ROOT / 'experiments/memory/services-phase-matrix02-review01.json'
    reviewed = json.loads(review_path.read_text())
    if reviewed['evidence_sha256'] != sha(terminal_path) or not reviewed['source_and_counter_static_screen_completed']:
        raise ValueError('Actual object review does not bind parent terminal receipt')
    captures = ROOT / 'work/services-phase-matrix02-results'
    for row in terminal['artifacts']:
        path = captures / row['path']
        if sha(path) != row['sha256'] or path.stat().st_size != row['size']:
            raise ValueError('Actual matrix bytes changed')
    commands = (query / 'commands.stdout').read_text().splitlines()
    rsp = (query / 'libart.so.rsp').read_text()
    read_closure = input_closure(commands, rsp, cache, compile_record['read_inputs'])
    jobs = {}
    for role in ROLES:
        jobs[role] = recipes(commands, role, help_record['--help']['stdout'])
        jobs[role]['manager_input'] = dict(path='/inputs/payload/' + role + '/oat_file_manager.o',
            sha256=reviewed['roles'][role]['object_sha256'], source_sha256=reviewed['roles'][role]['source_sha256'])
    toolchain_path = query / 'toolchain.json'
    runtime_path = ROOT / 'work/memory/libart-runtime-readelf01/runtime-container02.json'
    if sha(toolchain_path) != 'db6ae131551701400ae59e98bb1c3ea42e3d3a2b85d9ab998f4dff28a0f0335b' or sha(runtime_path) != '36a5f42172acab9732cdc09c81ce146084e3803aebee84a9fee97b1ab24fa566':
        raise ValueError('Original direct-tool/runtime receipt differs')
    direct_tools = {row['path']: row for row in json.loads(toolchain_path.read_text())['files']
                    if Path(row['path']).name in ('clang++', 'ld.lld', 'llvm-objcopy', 'llvm-readelf')}
    if len(direct_tools) != 4 or any(compile_record['read_inputs'][path] != row['sha256'] for path, row in direct_tools.items()):
        raise ValueError('Actual direct link/strip tools differ')
    plan = dict(classification='offline_link_provider_closure_plan_not_executed', stage=NAME, backing=BACKING,
        builder='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d',
        roles=list(ROLES), jobs=jobs, original_rsp_entries=257, replaced_rsp_slot_zero_based=145,
        offline_gate_tools={name: sha(ROOT / 'tools' / name) for name in
            ('check_services_phase_link_elf01.py', 'audit_libart_surface54.py', 'audit_libart_code55.py')},
        unchanged_read_inputs=read_closure, required_direct_tools=direct_tools,
        historical_compile_read_inputs=compile_record['read_inputs'],
        current_source_or_graph_hash_is_not_an_unused_link_dependency=True,
        resource_policy=dict(cpus=[0, 1], cpu_quota=2, memory_bytes=8 * 1024**3, total_memory_swap_bytes=8 * 1024**3,
            pids=512, per_role_seconds=1800, PID1_service_runtime_seconds=1900,
            stage_incremental_budget_bytes=4 * 1024**3, root_and_external_floor_bytes=2 * 1024**3,
            sequential=True, lld_parallel_threads=False, thinlto_backend_jobs=1),
        execution_driver_status='New link-specific driver must be reviewed; object02 runner is not retargeted or reused.',
        mandatory_boundaries=['Fresh external bind/backing/inode and never-reused containers/units for this link identity.',
            'Root build bind uses explicit recursive readonly and rprivate; all nested build RW mounts rejected.',
            'Inputs/control/source bytes read-only; only per-role external work/tmp writable.',
            'Root PID1 MainPID/InvocationID/CID/packet/config proof before barrier; continuously fresh heartbeat.',
            'All host Python uses -B and disables bytecode before local imports; immutable input closure exact.',
            'Whole-stage growth and both free floors watched, independent container timeout, bounded child process group.',
            'No automatic retry, cache deletion, source rebuild, global graph invocation, package or install.'],
        write_closure=dict(persistent=['/work/unstripped/libart.so', '/work/stripped/libart.so',
            '/work/stripped/libart.so.d', '/work/link.map', '/work/link.stdout', '/work/link.stderr',
            '/work/strip.stdout', '/work/strip.stderr'],
            temporary=['/work/stripped/libart.so.tmp', '/work/tmp/**',
                       '/work/unstripped/** (tool-selected output-buffer temporaries; inventory exact names)',
                       '/work/stripped/** (objcopy/strip atomic temporaries; inventory exact names)'],
            wrapper_metadata=['per-role start/exit/outputs/input-before/input-after/file-inventory records',
                              'root watcher readiness/heartbeat/inspect/logs/terminal records under control'],
            excluded_modes=['no LTO persistent cache/pruning', 'no save-temps/reproduce archive',
                            'no mini-debug-info/symbol-list/remove-build-id strip branches']),
        final_gate=dict(interface='Exact baseline imports/exports/versions/object+TLS sizes, ordered NEEDED, SONAME, ARM attributes and protection flags.',
            paired_artifacts='CRC-bound GNU debuglink and equal build ID; enabled private counter/marker present; off absent.',
            provider_resolution='Actual map/trace plus all dynamic requirements resolved against exact selected shared providers, including version/visibility.',
            code='Final linked ARM32 counter retry/literal references, nonmatching paths, new helper calls, and all unrelated scope changes.',
            relocation_unwind='Account REL/RELR, GOT/PLT, ARM.exidx/EH frames, thunks and all source/diagnostic layout differences.',
            acceptance='No automatic ABI/layout, runtime, hardware, latency or RAM-saving acceptance.'),
        provenance_limits=['256 unchanged compiled objects have byte pins but not complete compiled-TU source receipts.',
            'Provider availability is proven offline; actual selected link resolution remains future evidence.',
            'Shell utilities are from the exact pinned builder image; separately record their resolved identities before strip.',
            'Original graph hash is historical provenance only; no Ninja/Soong graph is executed.',
            'Fresh off controls isolate new threading policy and source-line/debug shifts from enabled diagnostics.'],
        executed=False, linked=False, installed=False, savings_proven=False)
    output.mkdir(parents=True)
    for name in ('payload', 'rsp', 'receipts'):
        (output / name).mkdir()
    for role in ROLES:
        target = output / 'payload' / role
        target.mkdir()
        source = captures / 'work' / role / 'out/manager.thin.o'
        if sha(source) != jobs[role]['manager_input']['sha256']:
            raise ValueError('Actual role object differs')
        shutil.copyfile(source, target / 'oat_file_manager.o')
        (output / 'rsp' / (role + '.rsp')).write_bytes(response(rsp, role).encode())
    receipts = {'compile-record.json': compile_path, 'cache-before.json': cache_path,
                'lld11-help.json': help_path, 'provider-audit.json': provider_path,
                'matrix-terminal.json': terminal_path, 'matrix-review.json': review_path,
                'toolchain.json': toolchain_path, 'runtime-container02.json': runtime_path,
                **{name: query / name for name in PINS}}
    for name, source in receipts.items():
        shutil.copyfile(source, output / 'receipts' / name)
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    manifest = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    (output / 'manifest.json').write_text(json.dumps(dict(files=manifest, executed=False), indent=2) + '\n', encoding='utf-8')
    return dict(classification=plan['classification'], packet_directory=output.relative_to(ROOT).as_posix(),
        packet_sha256=sha(output / 'manifest.json'), plan_sha256=sha(output / 'plan.json'),
        jobs=4, unchanged_link_inputs=280, linker_help_sha256=sha(help_path), provider_audit_sha256=sha(provider_path),
        new_link_driver_implemented=False, linked=False, installed=False, ready_for_host_launch=False,
        generator_sha256=sha(Path(__file__)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output_dir)))

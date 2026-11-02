"""Offline integrity, object-symbol and diagnostic ARM assembly scope review."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
PACKET = '369bc16b3074318d53b1fd933d8978678928475da474e34b326f602dca6e506f'
ROLES = ('55-off', '55-on', '56-off', '56-on')
COUNTER = '_ZZN3art12_GLOBAL__N_119NextServicesPhaseIdEvE4next'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def uncomment(line):
    quoted = False
    escaped = False
    for i, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == '@' and not quoted:
            return line[:i].strip()
    return line.strip()


def assembly(text):
    """Keep instructions/constants/unwind directives; remove debug coordinates only."""
    functions, objects = {}, {}
    active = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = uncomment(raw)
        start = re.fullmatch(r'\.type\s+([^,]+),%(function|object)', line)
        if start:
            if active is not None:
                raise ValueError('Unclosed assembly entity ' + active[0] + ' before ' + start[1])
            active = [start[1], start[2], number, []]
        if active:
            alias = re.match(r'\.(?:set|equ|comm)\s+' + re.escape(active[0]) + ',', line)
            if alias:
                active[3].append(line)
            if alias or line.startswith('.size\t' + active[0] + ',') or re.match(r'\.size\s+' + re.escape(active[0]) + ',', line):
                destination = functions if active[1] == 'function' else objects
                destination[active[0]] = dict(start_line=active[2], end_line=number, lines=active[3])
                active = None
            elif line and not start:
                active[3].append(line)
    if active is not None:
        raise ValueError('Final assembly entity incomplete')
    strings = {}
    for name, row in objects.items():
        payload = [line for line in row['lines'] if line.startswith(('.asciz', '.ascii', '.byte', '.zero'))]
        if payload:
            strings[name] = hashlib.sha256('\n'.join(payload).encode()).hexdigest()
    for name, row in functions.items():
        lines = [line for line in row['lines'] if not line.startswith(('.loc', '.file'))]
        # Drop temporary debug labels only if nothing retained refers to them.
        kept = '\n'.join(line for line in lines if not re.fullmatch(r'\.Ltmp\d+:', line))
        lines = [line for line in lines if not (re.fullmatch(r'\.Ltmp\d+:', line) and not re.search(re.escape(line[:-1]) + r'\b', kept))]
        body = '\n'.join(lines)
        # Resolve string references by exact payload, not by a freely stripped number.
        for label in sorted(strings, key=len, reverse=True):
            body = re.sub(re.escape(label) + r'(?![A-Za-z0-9_.$])', 'STR_' + strings[label], body)
        body = re.sub(r'(\.L(?:BB|CPI|PC))\d+_', r'\1F_', body)
        body = re.sub(r'\.Lfunc_(begin|end)\d+', r'.Lfunc_\1F', body)
        # Debug-range temporaries that are actually used remain distinguishable.
        labels = {}
        body = re.sub(r'\.Ltmp\d+', lambda m: labels.setdefault(m[0], '.LtmpN' + str(len(labels))), body)
        row['normalized_sha256'] = hashlib.sha256(body.encode()).hexdigest()
        row['normalized'] = body
        row['call_targets'] = dict(collections.Counter(re.findall(r'^(?:bl|blx)(?:\.w)?\s+(\S+)', body, re.M)))
        row['instruction_lines'] = sum(not line.startswith('.') and not line.endswith(':') for line in lines)
        row['stack_pad_directives_bytes'] = [int(value) for value in re.findall(r'^\.pad\s+#(\d+)$', body, re.M)]
    return functions, objects


def delta(old, new):
    return {key: new.get(key, 0) - old.get(key, 0) for key in sorted(old.keys() | new.keys()) if new.get(key, 0) != old.get(key, 0)}


def parse_nm(text):
    result = collections.Counter()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 4 and len(parts[1]) == 1:
            result[(parts[0], parts[1])] += 1
        elif line.strip():
            raise ValueError('Unexpected llvm-nm format: ' + line[:100])
    return result


def counter_ir(text):
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if 'load atomic i32, ptr @' + COUNTER + ' monotonic' in line), None)
    if start is None:
        raise ValueError('Counter i32 relaxed load missing')
    end = next((i for i in range(start, len(lines)) if 'call i64 @_ZN3art8NanoTimeEv(' in lines[i]), None)
    if end is None:
        raise ValueError('Counter join/timestamp boundary missing')
    kept = [re.sub(r', !dbg !\d+', '', line) for line in lines[start:end + 1]
            if '@llvm.dbg.' not in line]
    body = '\n'.join(kept)
    cas = re.findall(r'(%\d+) = cmpxchg weak ptr @' + COUNTER + r', i32 (%\d+), i32 (%\d+) monotonic monotonic, align 4', body)
    bounds = re.findall(r'(%\d+) = icmp eq i32 (%\d+), 8\b', body)
    if len(cas) != 1 or len(bounds) != 1:
        raise ValueError('Counter weak i32 CAS / eight-attempt IR changed')
    result, expected, desired = cas[0]
    if not re.search(re.escape(desired) + r' = add nuw i32 ' + re.escape(expected) + r', 1\b', body):
        raise ValueError('Counter desired-value increment differs')
    if not re.search(re.escape(bounds[0][1]) + r' = add nuw nsw i32 %\d+, 1\b', body):
        raise ValueError('Attempt count does not increment')
    if len(re.findall(r'icmp eq i32 %\d+, -1\b', body)) != 2 or not re.search(r'phi i32 \[ -1, %\d+ \], \[ -1, %\d+ \], \[ ' + re.escape(expected) + r', %\d+ \]', body):
        raise ValueError('Saturation / invalid-ID return form differs')
    return dict(width=32, operation='weak cmpxchg', ordering='monotonic/monotonic (C++ relaxed)',
                attempt_limit=8, invalid_value=4294967295, source_lines=[start + 1, end + 1],
                structural_checks_pass=True, formal_control_flow_proof=False, text=body)


def counter_assembly(functions):
    candidates = [row for name, row in functions.items() if 'OpenDexFilesFromOatEPKc' in name]
    if len(candidates) != 1:
        raise ValueError('Expected single path-based loading function')
    lines = candidates[0]['lines']
    literal = next(i for i, line in enumerate(lines) if line.startswith('.long') and COUNTER in line)
    pool = lines[literal - 1].rstrip(':')
    if not re.fullmatch(r'\.LCPI\d+_\d+', pool):
        raise ValueError('Counter literal pool form differs')
    start = next(i for i, line in enumerate(lines) if re.match(r'ldr\s+\w+,\s*' + re.escape(pool) + r'$', line))
    seen = set()
    end = None
    for index in range(start, len(lines)):
        if re.fullmatch(r'\.LBB\d+_\d+:', lines[index]):
            seen.add(lines[index][:-1])
        branch = re.fullmatch(r'bne(?:\.w)?\s+(\.LBB\d+_\d+)', lines[index])
        if branch and branch[1] in seen:
            following = next(i for i in range(index + 1, len(lines))
                             if not lines[i].startswith('.loc') and not re.fullmatch(r'\.Ltmp\d+:', lines[i]))
            if not re.fullmatch(r'b(?:\.w)?\s+\.LBB\d+_\d+', lines[following]):
                raise ValueError('Counter exhaustion edge is not an explicit exit')
            end = following + 1
            break
    if end is None:
        raise ValueError('Counter bounded-loop backedge not located')
    body = [line for line in lines[start:end] if not line.startswith('.loc') and not re.fullmatch(r'\.Ltmp\d+:', line)]
    instructions = [line for line in body if not line.startswith('.') and not line.endswith(':')]
    opcodes = collections.Counter(line.split()[0] for line in instructions)
    if opcodes['ldrex'] != 1 or opcodes['strex'] != 1 or opcodes['clrex'] != 1 or any(opcodes.get(key) for key in ('ldrexd', 'strexd', 'bl', 'bl.w', 'blx', 'blx.w', 'dmb', 'dsb', 'isb')):
        raise ValueError('Counter inline 32-bit relaxed ARM sequence differs: ' + json.dumps(dict(opcodes)))
    compact = '\n'.join(instructions)
    for pattern in (r'movs\s+r1, #7\b', r'cmp\s+r1, #0\b', r'sub\.w\s+r1, r1, #1\b',
                    r'adds\s+r1, r3, #1\b', r'adds\s+r3, r2, #1\nsub\.w\s+r1, r1, #1\nmov\s+r3, r2\nbne\s+\.LBB\d+_\d+'):
        if not re.search(pattern, compact):
            raise ValueError('Observed bounded ARM retry/flags pattern changed')
    labels = {line[:-1] for line in body if line.endswith(':')}
    destinations = set(re.findall(r'\.LBB\d+_\d+', '\n'.join(body))) - labels
    exits = {}
    for destination in sorted(destinations):
        index = lines.index(destination + ':')
        stop = next((i for i in range(index + 1, len(lines)) if re.fullmatch(r'\.LBB\d+_\d+:', lines[i])), len(lines))
        exits[destination] = '\n'.join(line for line in lines[index:stop] if not line.startswith('.loc') and not re.fullmatch(r'\.Ltmp\d+:', line))
    return dict(counter_literal=pool, opcodes=dict(opcodes), text='\n'.join(body),
                external_exit_blocks=exits, no_call_in_retry_region=True,
                observed_eight_attempt_flags_pattern=True,
                final_link_lowering_proven=False)


def review(captures, packet, evidence, llvm, output):
    destination = output.resolve()
    if any(destination.is_relative_to(protected.resolve()) for protected in (captures, packet)):
        raise ValueError('Derived output must stay outside original captures and frozen packet')
    evidence_hash = sha(evidence)
    raw = json.loads(evidence.read_text())
    if raw['packet_sha256'] != PACKET or sha(packet / 'manifest.json') != PACKET:
        raise ValueError('Only exact packet06 matrix02 evidence is reviewed')
    manifest = json.loads((packet / 'manifest.json').read_text())
    for name, pin in manifest['files'].items():
        if sha(packet / name) != pin:
            raise ValueError('Packet changed: ' + name)
    expected = {}
    for row in raw['artifacts']:
        name = row['path']
        path = captures / name
        if Path(name).is_absolute() or '..' in Path(name).parts or name in expected or path.is_symlink() or path.stat().st_size != row['size'] or sha(path) != row['sha256']:
            raise ValueError('Raw download differs: ' + name)
        expected[name] = row
    actual = {p.relative_to(captures).as_posix() for p in captures.rglob('*') if p.is_file()}
    if actual != set(expected) or len(expected) != 96:
        raise ValueError('Expected exact 96-file terminal capture closure')
    spec = importlib.util.spec_from_file_location('frozen_phase_matrix02_contract', packet / 'tools/services_phase_object_contract01.py')
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    plan = json.loads((packet / 'plan.json').read_text())
    compile_record = json.loads((packet / 'receipts/compile-record.json').read_text())
    output.mkdir(parents=True, exist_ok=False)
    readers = {}
    for tool in ('llvm-nm.exe', 'llvm-dis.exe'):
        path = llvm / tool
        version = subprocess.run([str(path), '--version'], capture_output=True, text=True, timeout=15, check=True)
        readers[tool] = dict(path=str(path), sha256=sha(path), version=version.stdout.strip())
    roles = {}
    assemblies = {}
    symbols = {}
    for role in ROLES:
        root = captures / 'work' / role
        controls = captures / 'control' / role
        terminal = json.loads((controls / 'terminal.json').read_text())
        if not terminal['success'] or terminal['exit_code'] or terminal['oom_killed'] or terminal['stop_reason'] is not None or terminal['post_error'] is not None or terminal['packet_sha256'] != PACKET or terminal['role'] != role:
            raise ValueError('Failed/incorrect terminal role: ' + role)
        if terminal != raw['roles'][role] or terminal['uid'] != 0 or terminal['pid'] <= 0 or terminal['unit'] != contract.identities(role)[1] or not re.fullmatch('[a-f0-9]{32}', terminal['invocation_id']):
            raise ValueError('Terminal identity/source evidence inconsistent')
        inspect = json.loads((controls / 'container.inspect.json').read_text())
        contract.validate_container(inspect, role, PACKET, terminal['cid'])
        if inspect['State']['Running'] or inspect['State']['ExitCode'] or inspect['State']['OOMKilled']:
            raise ValueError('Container not successfully terminal')
        for name in ('ready.json', 'heartbeat.json', 'launch.json'):
            check = json.loads((controls / name).read_text())
            if any(check[key] != terminal[key] for key in ('packet_sha256', 'role', 'cid')):
                raise ValueError('Control identity differs')
            if name != 'launch.json' and any(check[key] != terminal[key] for key in ('unit', 'invocation_id', 'pid', 'uid')):
                raise ValueError('PID1 watchdog identity differs')
        inside = json.loads((root / 'inside-result.json').read_text())
        if not inside['success'] or not inside['known_read_inputs_unchanged'] or [r['label'] for r in inside['commands']] != [r['label'] for r in plan['roles'][role]] or any(r['exit'] for r in inside['commands']):
            raise ValueError('Compile phase/check evidence differs')
        source = packet / 'sources' / ('image' + role[:2] + '.cc')
        source_pin = sha(source)
        if source_pin != next(row['candidate_sha256'] for row in plan['source_contract']['sources'] if row['image'] == role[:2]):
            raise ValueError('Reviewed source identity differs')
        started = json.loads((root / 'started.json').read_text())
        if started['role'] != role or started['packet_sha256'] != PACKET or started['compile_only'] is not True:
            raise ValueError('Actual compile start binding differs')
        phases = {}
        for row in inside['commands']:
            label = row['label']
            dep_name = {'syntax': 'syntax.d', 'production-thin-object': 'manager.thin.o.d', 'nonlto-arm-assembly-review-only': 'manager.review.s.d'}[label]
            computed = contract.validate_dependencies((root / 'out' / dep_name).read_text(), compile_record['read_inputs'], source_pin)
            recorded = json.loads((root / (label + '.dependencies.json')).read_text())
            if computed != recorded or len(computed) != row['actual_dependencies']:
                raise ValueError('Dependency receipt differs')
            phases[label] = dict(exit=row['exit'], dependencies=len(computed))
        obj = root / 'out/manager.thin.o'
        with obj.open('rb') as stream:
            if stream.read(4) != b'BC\xc0\xde':
                raise ValueError('Unexpected production object format')
        role_symbols = {}
        for kind in ('defined', 'undefined'):
            process = subprocess.run([str(llvm / 'llvm-nm.exe'), '--' + kind + '-only', '--format=posix', str(obj)], capture_output=True, text=True, timeout=60, check=True)
            (output / (role + '-' + kind + '.txt')).write_text(process.stdout, encoding='utf-8')
            role_symbols[kind] = parse_nm(process.stdout)
        symbols[role] = role_symbols
        prefix = output / (role + '.ll')
        process = subprocess.run([str(llvm / 'llvm-dis.exe'), str(obj), '-o', str(prefix)], capture_output=True, text=True, timeout=60, check=True)
        (output / (role + '-reader.stderr')).write_text(process.stderr, encoding='utf-8')
        modules = sorted(output.glob(role + '.ll*'))
        if not modules:
            raise ValueError('No decoded split-LTO modules')
        ir_text = '\n'.join(p.read_text() for p in modules)
        targets = sorted(set(re.findall(r'^target triple = "([^"]+)"', ir_text, re.M)))
        if targets != ['thumbv7-unknown-linux-android10000']:
            raise ValueError('Unexpected object target')
        text = (root / 'out/manager.review.s').read_text()
        functions, objects = assembly(text)
        assemblies[role] = functions
        counters = [line.strip() for line in ir_text.splitlines() if COUNTER in line and not line.startswith('^')]
        roles[role] = dict(source_sha256=source_pin, phases=phases,
            object_sha256=sha(obj), object_bytes=obj.stat().st_size, object_format='split_ThinLTO_LLVM_bitcode',
            decoded_modules=[dict(path=p.name, sha256=sha(p)) for p in modules], target_triples=targets,
            assembly_sha256=sha(root / 'out/manager.review.s'), assembly_functions=len(functions),
            counter_IR_references=counters,
            counter_IR_review=counter_ir(ir_text) if role.endswith('-on') else None,
            counter_ARM_review=counter_assembly(functions) if role.endswith('-on') else None,
            counter_object=objects.get(COUNTER),
            function_inventory={name: {k: v for k, v in row.items() if k not in ('lines', 'normalized')} for name, row in functions.items()})
    comparisons = {}
    for image in ('55', '56'):
        old, new = image + '-off', image + '-on'
        a, b = assemblies[old], assemblies[new]
        changed = sorted(name for name in a.keys() & b.keys() if a[name]['normalized_sha256'] != b[name]['normalized_sha256'])
        details = {}
        for name in changed:
            details[name] = dict(call_target_delta=delta(a[name]['call_targets'], b[name]['call_targets']),
                                 instruction_line_delta=b[name]['instruction_lines'] - a[name]['instruction_lines'])
        undefined_old = {key[0] for key in symbols[old]['undefined']}
        undefined_new = {key[0] for key in symbols[new]['undefined']}
        defined_old = {key[0] for key in symbols[old]['defined']}
        defined_new = {key[0] for key in symbols[new]['defined']}
        comparisons[image] = dict(added_assembly_functions=sorted(b.keys() - a.keys()), removed_assembly_functions=sorted(a.keys() - b.keys()), changed_normalized_assembly_functions=changed,
            changed_function_details=details, new_undefined_symbols=sorted(undefined_new - undefined_old), removed_undefined_symbols=sorted(undefined_old - undefined_new),
            new_defined_symbols=sorted(defined_new - defined_old), removed_defined_symbols=sorted(defined_old - defined_new))
        # Review only this observed lambda renumbering, never erase arbitrary
        # mangled-name numbers. Require exact full-name pairing and body match.
        rename = {name: name.replace('$_32', '$_34') for name in a.keys() - b.keys()
                  if 'UnlinkLeastRecentlyUsedVdexIfNeeded' in name and '$_32' in name}
        if len(rename) != 3 or set(rename.values()) != b.keys() - a.keys():
            raise ValueError('Unexpected function-symbol scope outside reviewed lambda renaming')
        renamed_matches = {}
        for before, after in rename.items():
            transformed = a[before]['normalized']
            for x, y in rename.items():
                transformed = transformed.replace(x, y)
            renamed_matches[before] = dict(candidate_name=after, normalized_body_equal=transformed == b[after]['normalized'])
        remaining = []
        for name in changed:
            transformed = a[name]['normalized']
            for x, y in rename.items():
                transformed = transformed.replace(x, y)
            if transformed != b[name]['normalized']:
                remaining.append(name)
        comparisons[image]['exact_reviewed_lambda_renamings'] = renamed_matches
        comparisons[image]['changed_functions_after_exact_lambda_reference_mapping'] = remaining
        comparisons[image]['new_atomic_or_initialization_helper_references'] = [name for name in undefined_new - undefined_old if re.search(r'__atomic|__sync|__cxa_guard|GLOBAL__sub_I', name)]
    if sha(evidence) != evidence_hash:
        raise ValueError('Parent evidence changed during offline review')
    if any(sha(captures / name) != row['sha256'] for name, row in expected.items()):
        raise ValueError('Original evidence bytes changed during review')
    report = dict(classification='offline_compile_object_scope_review', packet_sha256=PACKET,
        evidence_sha256=evidence_hash, raw_files_verified=len(expected), readers=readers,
        roles=roles, off_on_comparisons=comparisons, linked=False, installed=False,
        full_ABI_or_runtime_acceptance=False, savings_proven=False,
        limits=['LLVM18 readers decode producer LLVM11 split-LTO modules; decoded IR is inspection evidence, not new target code.',
                'The ARM assembly was separately generated with LTO disabled; it is not final linked ThinLTO code.',
                'Normalization removes debug coordinates/comments/local function numbering and resolves exact string payloads; it is a scope diagnostic, not semantic equivalence proof.',
                'Host read-input postchecks are recorded terminal evidence; this offline review does not re-read host files.'],
        analyzer_sha256=sha(Path(__file__)))
    save(output / 'report.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--captures', type=Path, default=Path('work/services-phase-matrix02-results'))
    parser.add_argument('--packet', type=Path, default=Path('work/memory/services-phase-object-packet06'))
    parser.add_argument('--evidence', type=Path, default=Path('docs/evidence/services-phase-matrix02-terminal01.json'))
    parser.add_argument('--llvm-bin', type=Path, default=Path('/opt/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin'))
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    result = review(args.captures, args.packet, args.evidence, args.llvm_bin, args.output_dir)
    print(json.dumps({key: result[key] for key in ('classification', 'raw_files_verified', 'off_on_comparisons')}))

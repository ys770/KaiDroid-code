"""Prepare a new OFFLINE packet changing only the broad Docker idle rejection.

The original archive is read-only. This tool never connects to the build host.
Existing compiler/PID checks and all resource/build/cache controls are retained.
"""
import argparse
import ast
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

ORIGINAL = '06d9a22648c07a452b4a3e268495d500bc7052e169b5f1dae95b1523e3450f73'
MANIFEST = '894ff445d5e4d5b9cbf0137920392412fe98c40237e79de904e08ed273112ed3'
PREPARER = 'tools/prepare_tcl_scrollbar_stage.py'
HELPER = 'tools/scrollbar_host_reservation.py'
PROOF = 'proofs/reservation-amendment.json'
OLD = " if run(['sudo','-n','docker','ps','-q']).stdout.strip():raise ValueError('Container already active; do not duplicate')"
NEW = " from scrollbar_host_reservation import verify\n verify(c.ROOT,run)"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def amend_source(original):
    text = original.decode()
    require(text.count(OLD) == 1, 'Original broad idle check differs')
    changed = text.replace(OLD, NEW).encode()
    before = ast.parse(text, feature_version=(3, 8))
    after = ast.parse(changed.decode(), feature_version=(3, 8))
    names = lambda tree: {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    a, b = names(before), names(after)
    require(set(a) == set(b), 'Function declarations changed')
    different = [name for name in a if ast.dump(a[name]) != ast.dump(b[name])]
    require(different == ['idle'], 'Non-idle function body changed')
    require(ast.dump(ast.Module(body=a['idle'].body[:-1], type_ignores=[])) ==
            ast.dump(ast.Module(body=b['idle'].body[:-2], type_ignores=[])), 'Original PID/compiler checks changed')
    # Erase only the reviewed idle bodies before checking module-level identity.
    for tree in (before, after):
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == 'idle':
                node.body = [ast.Pass()]
    require(ast.dump(before) == ast.dump(after), 'Module metadata/control imports changed')
    return changed


def prepare(archive, helper, output):
    require(not output.exists() and not output.is_symlink(), 'Fresh output required')
    raw = archive.read_bytes()
    require(sha(raw) == ORIGINAL, 'Original archive changed')
    payload, infos = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts and
                    path.as_posix() == member.name and member.name not in payload, 'Unsafe original archive coverage')
            payload[member.name] = source.extractfile(member).read()
            infos[member.name] = copy.copy(member)
    require(sha(payload['packet.json']) == MANIFEST, 'Original manifest changed')
    meta = json.loads(payload['packet.json'])
    require(set(payload) == set(meta['files']) | {'packet.json'}, 'Original archive coverage differs')
    require(all(sha(payload[n]) == value for n, value in meta['files'].items()), 'Original payload hash differs')
    original_payload = dict(payload)
    payload[PREPARER] = amend_source(payload[PREPARER])
    payload[HELPER] = helper.read_bytes()
    require(b'\r' not in payload[HELPER], 'Helper must retain canonical LF')
    ast.parse(payload[HELPER].decode(), feature_version=(3, 8))
    proof = dict(scope='Only original idle Docker rejection replaced by fresh read-only reservation attestation',
                 original_archive_sha256=ORIGINAL, original_manifest_sha256=MANIFEST,
                 original_preparer_sha256=sha(original_payload[PREPARER]), amended_preparer_sha256=sha(payload[PREPARER]),
                 helper_sha256=sha(payload[HELPER]), changed_original_functions=['idle'],
                 original_pid_and_compiler_checks_byte_equivalent_ast=True,
                 all_other_original_non_manifest_payloads_bytes_modes_unchanged=True,
                 original_launch_template_and_all_resource_payloads_unchanged=True,
                 launcher_prelaunch_calls_amended_staged_preparer=True,
                 helper_copied_into_hashed_readonly_inputs_tools=True,
                 container_names_or_ids_allowlisted=False, host_operations=False, host_staged=False,
                 compiler_launched=False, parent_review_pending=True, full_parity=False)
    payload[PROOF] = encoded(proof)
    meta['files'] = {name: sha(data) for name, data in payload.items() if name != 'packet.json'}
    meta['reservation_amendment'] = dict(original_archive_sha256=ORIGINAL, original_manifest_sha256=MANIFEST,
                                          proof=PROOF, proof_sha256=sha(payload[PROOF]),
                                          no_host_attestation_performed=True, parent_review_pending=True)
    payload['packet.json'] = encoded(meta)
    require({n for n in original_payload if payload[n] != original_payload[n]} == {'packet.json', PREPARER},
            'Unexpected original payload modification')
    output.mkdir(parents=True)
    packet = output / 'packet'
    packet.mkdir()
    for name, data in payload.items():
        target = packet / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    target_archive = output / 'packet.tar.gz'
    with target_archive.open('xb') as stream:
        with gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as target:
                for name in sorted(payload):
                    member = infos.get(name, tarfile.TarInfo(name))
                    if name not in infos:
                        member.mode = 0o644
                        member.uid = member.gid = member.mtime = 0
                    member.size = len(payload[name])
                    target.addfile(member, io.BytesIO(payload[name]))
    with tarfile.open(target_archive) as check:
        require(set(check.getnames()) == set(payload), 'New archive coverage mismatch')
        for member in check.getmembers():
            require(member.isfile() and check.extractfile(member).read() == payload[member.name], 'New archive bytes/types mismatch')
            if member.name in infos:
                require(member.mode == infos[member.name].mode, 'Original archive mode changed')
    result = dict(original_archive_sha256=ORIGINAL, original_manifest_sha256=MANIFEST,
                  archive_sha256=sha(target_archive.read_bytes()), packet_manifest_sha256=sha(payload['packet.json']),
                  entries=len(payload), original_non_manifest_payloads_unchanged=len(original_payload)-2,
                  added_files=[HELPER, PROOF], proof=proof, original_archive_still_unchanged=sha(archive.read_bytes()) == ORIGINAL,
                  host_operations=False, compiler_launched=False)
    with (output/'result.json').open('xb') as stream:
        stream.write(encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--helper', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.archive, args.helper, args.output)))


if __name__ == '__main__':
    main()

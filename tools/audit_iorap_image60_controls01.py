"""Revalidate offline image60 IORAP binaries/config and copied switch sources."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'work/memory/iorap-image60-audit01'
RAW_SHA = 'b2f83a0a1c8bee8adbf79be9ccb8a27b7de066d8495242d2ab16d872e18511f3'
SOURCE_RECEIPTS = {
    'source-inputs01': '698cc9a7d9fbfd9804ffa0fe2c856868ed821f50a4f0204a4eb359cd5256829c',
    'source-inputs02': 'a6b0a2cbda648d9dda5978876bcd0cb1d21310d2eecc593bf8348afcc70a648c'}
FILES = {
    '/system/etc/prop.default': '1cc6f0e063383305be71c4d71f12d6806ee6873740f3e9570469b87bb0b1e576',
    '/system/etc/init/iorapd.rc': '93c9f182660694057ab7e1e2d20b025ea2263a708a966750b16bb74b0cf488c0',
    '/system/bin/iorapd': 'fd3f4b8dfeeb2f78ce1b00fa87c22d5c9f0e9196cc97f2860d7b1986e85ae542',
    '/system/framework/services.jar': '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d',
    '/system/lib/server_configurable_flags.so': '59a523cf5364514defd4efbd3192401e19ef238acc224555e44d3398ca81a999'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run():
    raw = ROOT / 'work/image60-verification01/candidate60.raw.img'
    with raw.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != RAW_SHA:
            raise ValueError('Exact installed60 raw required')
    sys.path.insert(0, str(ROOT / 'work/kyocera-extfs-python'))
    from dissect.extfs import ExtFS
    records = []
    with raw.open('rb') as stream:
        fs = ExtFS(stream)
        for name, expected in FILES.items():
            data = fs.get(name).open().read()
            if sha(data) != expected or (FOLDER / 'files' / name.lstrip('/')).read_bytes() != data:
                raise ValueError('Image/extracted input differs: ' + name)
            records.append(dict(path=name, sha256=expected, bytes=len(data)))
    sources = []
    for folder, expected in SOURCE_RECEIPTS.items():
        path = FOLDER / folder
        data = (path / 'acquisition.json').read_bytes()
        if sha(data) != expected:
            raise ValueError('Source receipt changed')
        receipt = json.loads(data)
        if receipt['absent']:
            raise ValueError('Source files missing')
        for row in receipt['files']:
            if not row['stable_stat'] or sha((path / 'source' / row['relative_path']).read_bytes()) != row['sha256']:
                raise ValueError('Source bytes changed')
            sources.append(dict(root=folder, **{k: row[k] for k in ('relative_path', 'sha256', 'bytes', 'mtime_ns')}))
    java = (FOLDER / 'IorapForwardingService.java').read_bytes()
    if sha(java) != 'c0ed94bf0dd603c45854655b8d260fda767e156d7b60cb4a6bd838a8c897caf6':
        raise ValueError('Current-JAR decompiled class changed')
    defaults = (FOLDER / 'files/system/etc/prop.default').read_text(encoding='utf-8')
    lines = [line for line in defaults.splitlines() if re.search(r'iorap|traced|low_ram', line)]
    return dict(classification='offline_image60_IORAP_switch_and_feature_scope_audit',
        raw_sha256=RAW_SHA, image_files=records, source_receipts_sha256=SOURCE_RECEIPTS,
        source_files=sources, source_leases_returned=True, host_mutations=False,
        decompiled_current_services_class_sha256=sha(java), decompiled_java_is_original_source=False,
        image_default_lines=lines,
        switches=[
            dict(key='ro.iorapd.enable', default='true', read_scope='framework class initialization and init trigger',
                 effect='framework forwarding/listeners/jobs plus daemon lifecycle; broader than recording'),
            dict(key='iorapd.perfetto.enable', default='true', namespace='runtime_native_boot',
                 server_key='iorap_perfetto_enable', precedence='server-configurable result over property fallback',
                 read_scope='constructor and explicit RefreshSystemProperties; per-event atomic flag sampling',
                 effect='new launch recording decisions; read-ahead independently controlled'),
            dict(key='iorapd.readahead.enable', default='true', namespace='runtime_native_boot',
                 server_key='iorap_readahead_enable', read_scope='same refresh mechanism',
                 effect='existing compiled-trace prefetch; keep unchanged in first experiment'),
            dict(key='iorapd.perfetto.buffer_size', default=4096, units='Perfetto size_kb',
                 read_scope='static local at CreateComponent first call; new daemon process to reread'),
            dict(key='iorapd.perfetto.trace_duration_ms', default=5000, units='ms',
                 read_scope='same CreateComponent static local'),
            dict(key='iorapd.perfetto.max_traces', consumer_default=5, raw_file_retention_default=10,
                 read_scope='two separately cached/static consumers',
                 effect='live handle pruning AND old raw trace/file/database retention; not a disable switch'),
        ],
        refresh_command='dumpsys iorapd --refresh-properties', refresh_is_state_changing=True,
        ordinary_dump_refreshes_properties=False, sysprop_callback_refreshes_flags=False,
        recording_flag_truth_rule='exact resulting string equals true',
        native_recording_events=['mm_filemap_add_to_page_cache', 'mm_filemap_delete_from_page_cache'],
        trace_not_started_when_existing_readahead_active=True,
        recording_off_still_keeps_daemon_listeners_db_history_and_maintenance=True,
        data_paths=dict(root_default='/data/misc/iorapd', root_override='IORAPD_ROOT_DIR env then iorapd.root.dir',
                        db_default='/data/misc/iorapd/sqlite.db', db_override='iorapd.db.location'),
        effective_runtime_values_captured=False, server_flag_library_storage_mapping_proven=False,
        copied_source_bytes_proven_to_build_current_native_binary=False,
        runtime_switch_tested=False, data_modified=False, experiment_executed=False,
        configured_buffer_resident_bytes=None, causal_role_in_startup_kills_proven=False,
        matched_physical_memory_saving_proven=False,
        remaining_inputs=['Allowlisted current properties/server overrides and quiescent native handle state',
                          'Current effective refreshed flags as an explicit baseline-conditioning action',
                          'Reviewed profile-only preservation/frozen-state procedure before a matched pair',
                          'Target runtime receipt that recording flag changes while read-ahead remains equal'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = run()
    result['analyzer_sha256'] = sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(files=len(result['image_files']), sources=len(result['source_files']),
                         runtime_switch_tested=False, experiment_executed=False)))

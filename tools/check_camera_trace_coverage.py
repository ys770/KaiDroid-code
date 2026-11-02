"""Check retained system-trace coverage against camera monotonic markers.

Writes an evidence report; nonzero exit means startup coverage is missing.
Parser warnings remain explicit even when time coverage passes.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
for name in ('trace', 'log', 'processor', 'output'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
markers = {}
for timestamp, name in re.findall(r'^\s*(\d+\.\d+)\s+\d+\s+\d+\s+I KaiCameraStartup: (recorder_enter|recorder_return)\s*$', a.log.read_text(encoding='utf-8', errors='replace'), re.MULTILINE):
    if name in markers:
        raise ValueError('Ambiguous repeated recorder marker: ' + name)
    markers[name] = float(timestamp)
if set(markers) != {'recorder_enter', 'recorder_return'}:
    raise ValueError('Both monotonic recorder markers required')

def query(sql):
    result = subprocess.run([sys.executable, str(a.processor), 'query', str(a.trace), sql],
                            capture_output=True, text=True, timeout=120)
    result.check_returncode()
    return list(csv.DictReader(io.StringIO(result.stdout))), result.stderr

rows, diagnostics = query('select start_ts/1e9 as start_s,end_ts/1e9 as end_s from trace_bounds')
start, end = float(rows[0]['start_s']), float(rows[0]['end_s'])
stats, _ = query("select name,value from stats where value>0 and (severity='error' or name like '%overrun%' or name like '%lost%')")
coverage = start <= markers['recorder_enter'] < markers['recorder_return'] <= end
report = dict(trace_sha256=hashlib.sha256(a.trace.read_bytes()).hexdigest(),
              log_sha256=hashlib.sha256(a.log.read_bytes()).hexdigest(),
              markers_seconds=markers, trace_bounds_seconds=[start, end],
              startup_coverage=coverage, nonzero_error_loss_stats=stats,
              parser_diagnostics=diagnostics,
              limitations=['Temporal coverage alone does not prove all events were retained.',
                           'Trace clock must match the log monotonic clock; no suspend/clock conversion is inferred.',
                           'Tracing overhead is not subtracted.'])
with a.output.open('x') as out:
    json.dump(report, out, indent=2)
    out.write('\n')
print(json.dumps(report))
sys.exit(0 if coverage else 2)


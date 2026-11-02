"""Summarize local Perfetto storage/reclaim evidence without inferring causality.

Pair with check_camera_trace_coverage.py: this tool does not establish startup
coverage, recording success, completed NAND transfers, or original fault owner.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys


def summarize(trace, processor):
    diagnostics = []

    def query(sql):
        result = subprocess.run(
            [sys.executable, str(processor), 'query', str(trace), sql],
            capture_output=True, text=True, timeout=120, check=True)
        if result.stderr.strip():
            diagnostics.append(result.stderr.strip())
        return list(csv.DictReader(io.StringIO(result.stdout)))

    bounds = query('select start_ts,end_ts from trace_bounds')[0]
    start, end = int(bounds['start_ts']), int(bounds['end_ts'])
    if end <= start:
        raise ValueError('Empty or invalid trace bounds')
    events = query("select name,count(*) as count from ftrace_event where name in "
                   "('block_rq_issue','block_rq_complete','mm_vmscan_direct_reclaim_begin',"
                   "'mm_vmscan_direct_reclaim_end','sched_blocked_reason') group by name")
    blocks = query("select extract_arg(arg_set_id,'dev') as device,"
                   "extract_arg(arg_set_id,'rwbs') as rwbs,count(*) as requests,"
                   "sum(extract_arg(arg_set_id,'nr_sector'))*512 as requested_bytes "
                   "from ftrace_event where name='block_rq_issue' group by device,rwbs")
    reclaim = query("select t.tid,t.name as thread_name,p.pid,p.name as process_name,"
                    "count(*) as begins from ftrace_event e left join thread t using(utid) "
                    "left join process p using(upid) "
                    "where e.name='mm_vmscan_direct_reclaim_begin' "
                    "group by t.utid order by begins desc")
    errors = query("select name,value from stats where value>0 and "
                   "(severity='error' or name like '%overrun%' or name like '%lost%')")
    retention = query("select name,severity,value from stats where value>0 and "
                      "(name like '%discard%' or name like '%drop%' or name like '%overwrite%')")
    return dict(trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
                trace_bounds_ns=[start,end], duration_seconds=(end-start)/1e9,
                events={row['name']:int(row['count']) for row in events},
                block_issue_groups=blocks, direct_reclaim_threads=reclaim,
                nonzero_error_loss_stats=errors, parser_diagnostics=diagnostics,
                nonzero_retention_stats=retention,
                limitations=[
                    'Whole retained trace window; verify recorder marker coverage separately.',
                    'Requested sector bytes include repeated reads, not completed NAND transfers.',
                    'Device numbers require the captured handset block-device map.',
                    'Reclaim begin counts do not measure duration or prove a specific cause.',
                    'Missing event groups mean no recorded events, not proof an activity never occurred.',
                    'Informational retention counters are preserved separately; empty error stats do not prove zero loss.',
                    'Thread/process names are trace metadata; block issuer is not necessarily original fault owner.',
                    'Tracing overhead and unequal workload ages are not corrected.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trace','processor','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    report = summarize(args.trace,args.processor)
    with args.output.open('x') as output:
        output.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

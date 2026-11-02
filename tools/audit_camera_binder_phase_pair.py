"""Explore recorded43/44 camera windows; missing43 marker gate stays failed."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys

SOURCE_HASHES={
 'frameworks/av/media/libmedia/IMediaRecorder.cpp':'cb85b3fe1999da53201c1df74866fcafc8b4fc55799600beb7d1804e7c4527fd',
 'frameworks/av/media/libmediaplayerservice/MediaRecorderClient.cpp':'08feae846750e3b2621304e56b877588035fd56303845e1a7f0323aaa989e23c',
 'frameworks/native/libs/binder/include/binder/IBinder.h':'138f372acf63a746f215cde7ccfa76d7073abed49442510d003871967fc5ef69'}
TRACES={'43':'bfc28b3dc7439f45393fb6e69975ab05ce2d9b8f3595327684c8dbac54789ad0',
        '44':'37a9ec3e8ec2f96308587a3483a25578f5a70897ea850e592d3aa33ea96b1286'}


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(processor,sources):
    for name,expected in SOURCE_HASHES.items():
        if digest(sources/name)!=expected:raise ValueError('Source gate changed: '+name)
    binder=(sources/'frameworks/native/libs/binder/include/binder/IBinder.h').read_text()
    if not re.search(r'FIRST_CALL_TRANSACTION\s*=\s*0x0*1\b',binder):raise ValueError('Binder base differs')
    recorder=(sources/'frameworks/av/media/libmedia/IMediaRecorder.cpp').read_text()
    enum=recorder.split('enum {',1)[1].split('};',1)[0]
    names=[entry.strip().split('=')[0].strip() for entry in enum.split(',') if entry.strip()]
    if names.index('START')+1!=8 or names.index('STOP')+1!=7:raise ValueError('Recorder transaction numbering differs')
    if 'remote()->transact(START, data, &reply)' not in recorder:raise ValueError('Native START proxy differs')
    arms={}
    for image,expected in TRACES.items():
        trace=Path('artifacts/runtime/image'+image+'-camera-pair-record01/startup.pftrace')
        if digest(trace)!=expected:raise ValueError('Trace identity differs')
        queries=[]
        def query(sql):
            result=subprocess.run([sys.executable,str(processor),'query',str(trace),sql],capture_output=True,text=True,check=True,timeout=120)
            rows=list(csv.DictReader(io.StringIO(result.stdout)))
            queries.append(dict(sql=sql,rows=rows,stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest()))
            return rows
        bounds=query('SELECT start_ts,end_ts FROM trace_bounds')[0]
        calls=query("""SELECT s.id,s.ts,s.dur,t.tid,n.int_value AS node,c.display_value AS code,d.int_value AS destpid
FROM slice s JOIN thread_track tt ON tt.id=s.track_id JOIN thread t ON t.utid=tt.utid
JOIN process p ON p.upid=t.upid JOIN args d ON d.arg_set_id=s.arg_set_id AND d.key='destination process'
JOIN process dest ON dest.pid=d.int_value JOIN args c ON c.arg_set_id=s.arg_set_id AND c.key='code'
JOIN args n ON n.arg_set_id=s.arg_set_id AND n.key='destination node'
WHERE s.name='binder transaction' AND p.name LIKE '%tcl.camera%' AND dest.name LIKE '%mediaserver%' ORDER BY s.ts""")
        starts=[call for call in calls if int(call['code'].split()[0],16)==8 and int(call['dur'])>0]
        if len(starts)!=1:raise ValueError('Ambiguous/missing complete START-correlated call')
        start=starts[0];ts=int(start['ts']);duration=int(start['dur']);lo,hi=ts-3_000_000_000,ts+10_000_000_000
        if not int(bounds['start_ts'])<=lo<hi<=int(bounds['end_ts']):raise ValueError('Common phase window outside trace')
        flow=query(f"SELECT s.id,s.ts,s.dur,s.name FROM flow f JOIN slice s ON s.id=f.slice_in WHERE f.slice_out={int(start['id'])}")
        retention=query("SELECT name,value,severity,source FROM stats WHERE value!=0 AND (severity IN ('error','data_loss') OR name LIKE '%lost%' OR name LIKE '%discard%' OR name LIKE '%overrun%')")
        reclaim=query(f"SELECT name,count(*) AS events FROM ftrace_event WHERE ts>={lo} AND ts<{hi} AND name IN ('mm_vmscan_direct_reclaim_begin','mm_vmscan_direct_reclaim_end') GROUP BY name")
        reads=query(f"SELECT extract_arg(arg_set_id,'rwbs') AS rwbs,count(*) AS requests,sum(extract_arg(arg_set_id,'nr_sector'))*512 AS requested_bytes FROM ftrace_event WHERE name='block_rq_issue' AND ts>={lo} AND ts<{hi} AND extract_arg(arg_set_id,'dev')=45824 AND extract_arg(arg_set_id,'rwbs') GLOB 'R*' GROUP BY rwbs")
        hotfile=Path('docs/evidence/memory-camera'+image+'-binder13s-hotfiles01.json');hot=json.loads(hotfile.read_text())
        if hot['trace_sha256']!=expected or hot['request_window_ns']!=[lo,hi]:raise ValueError('Hotfile report window/trace differs')
        parent_path=Path('docs/evidence/image'+image+'-camera-pair-record01.json');parent=json.loads(parent_path.read_text())
        if parent['system_trace_sha256']!=expected:raise ValueError('Parent evidence belongs to another trace')
        markers=None
        if image=='44':
            marker=parent['coverage']['markers_seconds'];enter=marker['recorder_enter'];returned=marker['recorder_return']
            if not enter*1e9<=ts<ts+duration<=returned*1e9:raise ValueError('44 Binder not inside known Java START bracket')
            markers=dict(java_enter_seconds=enter,java_return_seconds=returned,
                java_duration_ms=(returned-enter)*1000,binder_after_enter_ms=ts/1e6-enter*1000,
                java_return_after_binder_ms=returned*1000-(ts+duration)/1e6)
        arms[image]=dict(trace_sha256=expected,trace_bytes=trace.stat().st_size,trace_bounds=bounds,
            configured_file_cap_bytes=32*1024*1024,file_below_configured_cap=trace.stat().st_size<32*1024*1024,
            source_correlated_start_call=start,linked_handler_slices=flow,binder_duration_ms=duration/1e6,
            java_markers=markers,strict_java_marker_gate_pass=(image=='44'),request_window_ns=[lo,hi],
            nonzero_retention_stats=retention,reclaim_events=reclaim,mmc_read_groups=reads,
            mmc_requested_read_bytes=sum(int(row['requested_bytes']) for row in reads),
            mmc_read_requests=sum(int(row['requests']) for row in reads),
            system_requested_bytes=hot['requested_bytes'],system_unique_requested_sector_bytes=hot['unique_requested_sector_bytes'],
            exclusive_dex_requested_bytes=sum(row['requested_bytes'] for row in hot['exclusive_zip_payload_reads'] if row['category'].endswith('.dex')),
            hotfile_report=str(hotfile),hotfile_report_sha256=digest(hotfile),parent_evidence_sha256=digest(parent_path),
            encoded_video_timing=parent.get('video_timing'),av_timing=parent.get('av_timing'),queries=queries)
    before,after=arms['43'],arms['44']
    deltas={key:dict(baseline=before[key],candidate=after[key],candidate_minus_baseline=after[key]-before[key],
                    percent_change=100*(after[key]/before[key]-1)) for key in
        ('binder_duration_ms','mmc_requested_read_bytes','mmc_read_requests','system_requested_bytes',
         'system_unique_requested_sector_bytes','exclusive_dex_requested_bytes')}
    return dict(scope='POSTHOC exploratory source-correlated Binder-aligned windows; not a passed strict startup-marker comparison.',
        source_hashes=SOURCE_HASHES,analysis_tool_sha256=digest(Path(__file__)),processor_sha256=digest(processor),
        inferred_interface='IMediaRecorder.START=8, inferred from source/route and 44 Java-marker bracket; no interface token in trace.',
        selection=dict(before_start_seconds=3,after_start_seconds=10,duration_seconds=13,posthoc=True),
        arms=arms,descriptive_changes=deltas,strict_marker_comparison_pass=False,camera_smoothness_improvement_established=False,
        net_physical_ram_saving_established=False,limits=[
            '43 Java startup markers remain missing. Source-correlated Binder timing is not complete Java API or key-to-record latency.',
            '44 STOP is incomplete and 43 STOP absent from these traces; no stop-latency comparison.',
            '43 reports two informational discarded chunks. Below-cap size/trace bounds do not prove complete event retention.',
            'Common phase window was chosen after capture to fit both bounds, before evaluating its totals; exploratory only.',
            'Read requests are neither completed NAND traffic nor resident RAM; unique sector unions are not a working-set denominator.',
            'More/smaller read requests can trade bytes for IOPS/CPU. Reclaim begin/end can straddle window boundaries.',
            'One44-to43 pair, pretrial ages366.02/372.61s and differing clip lengths; mutable cache/data/thermal conditions not fully frozen.',
            '43 whole-clip FPS/max-gap are better in this one pair, audio onset is similar; no camera smoothness or full hardware acceptance claim.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--processor',type=Path,required=True);parser.add_argument('--source-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    report=analyze(args.processor,args.source_dir)
    with args.output.open('x') as output:output.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['descriptive_changes'],indent=2))

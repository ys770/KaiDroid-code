"""Measure a saved video's packet cadence without changing it or the phone."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--video', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
q = subprocess.run(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
                    '-show_packets', '-show_entries', 'packet=pts_time,duration_time,size',
                    '-of', 'json', str(a.video)], capture_output=True, check=True, timeout=45)
packets = json.loads(q.stdout)['packets']
pts = [float(row['pts_time']) for row in packets]
assert len(pts) > 1 and all(y > x for x, y in zip(pts, pts[1:])), 'Non-increasing video PTS'
gaps = [y-x for x, y in zip(pts, pts[1:])]
ordered = sorted(gaps)
def percentile(f):
    index = (len(ordered)-1)*f
    lo = int(index)
    hi = min(lo+1, len(ordered)-1)
    return ordered[lo] + (ordered[hi]-ordered[lo])*(index-lo)
report = dict(sha256=hashlib.sha256(a.video.read_bytes()).hexdigest(),
              packets=len(packets), first_pts=pts[0], last_pts=pts[-1],
              interval_fps=(len(pts)-1)/(pts[-1]-pts[0]),
              gap_ms=dict(min=min(gaps)*1000, median=statistics.median(gaps)*1000,
                          p90=percentile(.9)*1000, p99=percentile(.99)*1000,
                          max=max(gaps)*1000),
              gaps_above_100ms=sum(g>.100 for g in gaps),
              gaps_above_250ms=sum(g>.250 for g in gaps),
              limits=['Encoded packet timing, not sensor or wall-clock instrumentation',
                      'One clip does not establish a reproducible causal bottleneck'])
with a.output.open('x') as out:
    json.dump(report, out, indent=2)
    out.write('\n')
print(json.dumps(report))

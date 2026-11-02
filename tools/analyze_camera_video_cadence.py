"""Analyze retained camera metadata and ffprobe packets without device actions."""
import argparse,hashlib,json,re,statistics
from pathlib import Path

def analyze(metadata,packets):
    result=metadata.split('Latest received frame:',1)[1].split('Last request sent:',1)[0]
    request=metadata.split('Last request sent:',1)[1]
    def fields(text):
        out={}
        for tag in ('android.control.aeTargetFpsRange','android.sensor.exposureTime','android.sensor.frameDuration'):
            match=re.search(re.escape(tag)+r' \([^\n]+\n\s*\[([0-9 ]+)\]',text)
            if not match:raise ValueError('Missing numeric camera metadata: '+tag)
            out[tag]=[int(x) for x in match[1].split()]
        return out
    pts=[float(p['pts_time']) for p in packets['packets']]
    if len(pts)<2:raise ValueError('Need multiple video packets')
    gaps=[(b-a)*1000 for a,b in zip(pts,pts[1:])]
    if min(gaps)<=0:raise ValueError('Nonmonotonic packet timestamps')
    return dict(packet_count=len(pts),gap_ms=dict(min=min(gaps),median=statistics.median(gaps),max=max(gaps)),gaps_over_250ms=sum(g>250 for g in gaps),latest_result=fields(result),last_request=fields(request),physical_lighting_controlled=False,limits=['One result metadata sample, not a per-frame exposure trace.','Packet regularity does not prove physical smoothness or isolate light, tuning, driver or memory causes.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('metadata','packets','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=analyze(a.metadata.read_text(),json.loads(a.packets.read_text(encoding='utf-8-sig')))
    r['inputs_sha256']={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in (a.metadata,a.packets)}
    with a.output.open('x',encoding='utf-8') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))

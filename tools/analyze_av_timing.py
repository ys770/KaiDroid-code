"""Measure encoded audio/video coverage; does not establish acoustic synchronization."""
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--video', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run([
        'ffprobe', '-v', 'error', '-show_streams', '-show_packets',
        '-show_entries', 'stream=index,codec_type,codec_name:packet=stream_index,pts_time,duration_time',
        '-of', 'json', str(args.video)], capture_output=True, check=True, timeout=45)
    data = json.loads(result.stdout)
    coverage = {}
    for kind in ('video', 'audio'):
        streams = [s for s in data['streams'] if s['codec_type'] == kind]
        if len(streams) != 1:
            raise ValueError('Expected one ' + kind + ' stream')
        stream = streams[0]
        packets = [p for p in data['packets'] if p['stream_index'] == stream['index']]
        spans = sorted((Decimal(p['pts_time']), Decimal(p['duration_time'])) for p in packets)
        if not spans or any(duration <= 0 for _, duration in spans):
            raise ValueError('Missing packets or nonpositive packet duration')
        gaps = [b[0] - (a[0] + a[1]) for a, b in zip(spans, spans[1:])]
        coverage[kind] = dict(codec=stream['codec_name'], packets=len(spans),
                              first_pts_seconds=float(spans[0][0]),
                              end_pts_seconds=float(max(p+d for p, d in spans)),
                              max_internal_gap_ms=float(max([Decimal(0)] + gaps)*1000))
    report = dict(sha256=hashlib.sha256(args.video.read_bytes()).hexdigest(), streams=coverage,
                  audio_start_after_video_ms=round(1000*(coverage['audio']['first_pts_seconds']-coverage['video']['first_pts_seconds']), 6),
                  audio_end_before_video_ms=round(1000*(coverage['video']['end_pts_seconds']-coverage['audio']['end_pts_seconds']), 6),
                  limitations=['Encoded presentation timestamps only; no acoustic or visual synchronization reference.',
                               'Packet coverage does not prove microphone quality or identify startup latency cause.'])
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

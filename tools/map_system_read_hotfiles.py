"""Attribute recorded block-read requests to an exact raw ext4 image, offline.

Sector counts are requests, not completed transfers, faults or retained RAM.
Requires dissect.extfs and an existing Perfetto trace processor wrapper.
"""
import argparse
import bisect
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import zipfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def union_size(ranges):
    total = 0
    end = -1
    for lo, hi in sorted(ranges):
        if hi > max(lo, end):
            total += hi - max(lo, end)
        end = max(end, hi)
    return total


def overlaps(extents, starts, lo, hi):
    index = max(0, bisect.bisect_right(starts, lo) - 1)
    while index < len(extents) and extents[index]['start'] < hi:
        extent = extents[index]
        left, right = max(lo, extent['start']), min(hi, extent['end'])
        if right > left:
            yield extent, left, right
        index += 1


def allocation_segments(extents):
    """Keep shared ext4 data blocks ambiguous rather than double-counting them."""
    events = {}
    for index, extent in enumerate(extents):
        events.setdefault(extent['start'], []).append((index, True))
        events.setdefault(extent['end'], []).append((index, False))
    active, segments, previous = set(), [], None
    for position, changes in sorted(events.items()):
        if active and previous is not None and position > previous:
            owners = sorted({extents[index]['inode'] for index in active})
            segments.append(dict(start=previous, end=position, owners=tuple(owners)))
        for index, add in changes:
            if add:
                active.add(index)
            else:
                active.remove(index)
        previous = position
    if active:
        raise ValueError('Unclosed allocation interval')
    return segments


def zip_layout(node):
    ranges = []
    with node.open() as data, zipfile.ZipFile(data) as archive:
        for entry in archive.infolist():
            data.seek(entry.header_offset)
            header = data.read(30)
            if len(header) != 30 or header[:4] != b'PK\x03\x04':
                raise ValueError('Invalid ZIP local header')
            names, extra = struct.unpack_from('<HH', header, 26)
            start = entry.header_offset + 30 + names + extra
            end = start + entry.compress_size
            if not 0 <= start <= end <= node.size:
                raise ValueError('ZIP payload outside inode')
            if end > start:
                category = entry.filename if entry.filename.endswith('.dex') or entry.filename == 'resources.arsc' else 'other_zip_payload'
                ranges.append(dict(start=start, end=end, category=category,
                                   compression=entry.compress_type,
                                   uncompressed_size=entry.file_size))
    ranges.sort(key=lambda row:row['start'])
    if any(a['end'] > b['start'] for a,b in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping ZIP payloads')
    return ranges


def inventory(image):
    from dissect.extfs import ExtFS
    rows, extents, zips = {}, [], {}
    with image.open('rb') as stream:
        fs = ExtFS(stream)
        block = fs.block_size
        ro_compat = int(fs.sb.s_feature_ro_compat)

        def visit(node, path):
            if node.inum in rows:
                rows[node.inum]['paths'].append(path)
                return
            kind = node.filetype
            row = dict(inode=node.inum, paths=[path], size=node.size,
                       kind='file' if kind == stat.S_IFREG else
                       'directory' if kind == stat.S_IFDIR else 'other',
                       requested_bytes=0, request_overlaps=0, ranges=[])
            rows[node.inum] = row
            if kind == stat.S_IFREG and node.size and path.endswith(('.jar','.apk','.apex')):
                zips[node.inum] = zip_layout(node)
            if kind in (stat.S_IFREG, stat.S_IFDIR) and node.size:
                logical = 0
                for physical, count in node.dataruns():
                    if count <= 0:
                        raise ValueError('Nonpositive data run')
                    if physical is not None:
                        start, end = physical * block, (physical + count) * block
                        if not 0 <= start < end <= image.stat().st_size:
                            raise ValueError('Extent outside raw image')
                        extents.append(dict(start=start, end=end, inode=node.inum,
                                            logical_start=logical))
                        # Independently check physical/logical translation at both ends.
                        with node.open() as data:
                            for offset in {0, min(count*block, node.size-logical)-1}:
                                if offset < 0:
                                    continue
                                data.seek(logical+offset)
                                expected = data.read(1)
                                stream.seek(start+offset)
                                if stream.read(1) != expected:
                                    raise ValueError('Data-run translation mismatch')
                    logical += count * block
            if kind == stat.S_IFDIR:
                for child in node.iterdir():
                    if child.filename not in ('.', '..'):
                        visit(child, path.rstrip('/') + '/' + child.filename)

        visit(fs.get('/'), '/')
    extents.sort(key=lambda e:e['start'])
    segments = allocation_segments(extents)
    if any(len(e['owners']) > 1 for e in segments) and not ro_compat & 0x4000:
        raise ValueError('Shared allocations without ext4 SHARED_BLOCKS feature')
    return block, ro_compat, rows, extents, segments, zips


def analyze(args):
    if digest(args.image) != args.image_sha256:
        raise ValueError('Image hash mismatch')
    trace_sha256 = digest(args.trace)
    if trace_sha256 != args.trace_sha256:
        raise ValueError('Trace hash mismatch')
    raw = args.partition_map.read_bytes()
    text = raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig')
    devices = re.findall(r'\ssystem -> /dev/block/(mmcblk0p\d+)', text)
    if len(devices) != 1:
        raise ValueError('Require one named system partition')
    matches = re.findall(r'PARTITION '+devices[0]+r'\s+(\d+)\s+(\d+)', text)
    if len(matches) != 1:
        raise ValueError('Require one system extent')
    sector_start, sectors = map(int, matches[0])
    if sectors*512 != args.image.stat().st_size:
        raise ValueError('Raw image and system partition lengths differ')
    sql = """SELECT ts, extract_arg(arg_set_id,'sector') AS sector,
extract_arg(arg_set_id,'nr_sector') AS sectors,
extract_arg(arg_set_id,'rwbs') AS rwbs FROM ftrace_event
WHERE name='block_rq_issue' AND extract_arg(arg_set_id,'dev')=45824
AND extract_arg(arg_set_id,'rwbs') GLOB 'R*' ORDER BY ts"""
    if args.start_ns is not None:
        if args.end_ns is None or not 0 <= args.start_ns < args.end_ns:
            raise ValueError('Require a positive half-open request time window')
        sql=sql.replace(' ORDER BY ts',f' AND ts>={args.start_ns} AND ts<{args.end_ns} ORDER BY ts')
    elif args.end_ns is not None:
        raise ValueError('Both request time-window bounds are required')
    query = subprocess.run([sys.executable, str(args.processor), 'query', str(args.trace), sql],
                           capture_output=True, text=True, check=True, timeout=120)
    block, ro_compat, rows, extents, segments, zips = inventory(args.image)
    starts = [e['start'] for e in segments]
    groups = {}
    by_inode = {}
    for extent in extents:
        by_inode.setdefault(extent['inode'], []).append(extent)
    zip_reads = {}
    zip_exclusive_bytes = zip_attributed_bytes = 0
    requested = 0
    system_ranges, unmapped_ranges = [], []
    system_requests = 0
    for request in csv.DictReader(io.StringIO(query.stdout)):
        sector, count = int(request['sector']), int(request['sectors'])
        lo = max(sector, sector_start) - sector_start
        hi = min(sector+count, sector_start+sectors) - sector_start
        if hi <= lo:
            continue
        lo, hi = lo*512, hi*512
        system_requests += 1
        requested += hi-lo
        system_ranges.append((lo, hi))
        cursor = lo
        touched = set()
        for extent, left, right in overlaps(segments, starts, lo, hi):
            if left > cursor:
                unmapped_ranges.append((cursor, left))
            key = extent['owners']
            row = groups.setdefault(key, dict(inodes=list(key),
                owners=[{k:rows[inode][k] for k in ('inode','paths','size','kind')} for inode in key],
                shared_allocation=len(key)>1, requested_bytes=0, request_overlaps=0, ranges=[]))
            row['requested_bytes'] += right-left
            row['ranges'].append((left, right))
            touched.add(key)
            if len(key) == 1 and key[0] in zips:
                zip_exclusive_bytes += right-left
                inode = key[0]
                sources = [e for e in by_inode[inode] if e['start'] <= left and e['end'] >= right]
                # Duplicate physical blocks can have multiple logical offsets even within one inode.
                if len(sources) == 1:
                    zip_attributed_bytes += right-left
                    source = sources[0]
                    logical_left = source['logical_start'] + left-source['start']
                    logical_right = logical_left + right-left
                    covered = 0
                    layout = zips[inode]
                    for payload, lo, hi in overlaps(layout, [e['start'] for e in layout], logical_left, logical_right):
                        category = payload['category']
                        ziprow = zip_reads.setdefault((inode,category), dict(inode=inode,
                            paths=rows[inode]['paths'], category=category,
                            compression_types=set(), requested_bytes=0, ranges=[]))
                        ziprow['compression_types'].add(payload['compression'])
                        ziprow['requested_bytes'] += hi-lo
                        physical_lo = left+lo-logical_left
                        ziprow['ranges'].append((physical_lo,physical_lo+hi-lo))
                        covered += hi-lo
                    meta = zip_reads.setdefault((inode,'container_metadata_or_eof_padding'),
                        dict(inode=inode,paths=rows[inode]['paths'],
                             category='container_metadata_or_eof_padding',requested_bytes=0,
                             compression_types=set(),ranges=[]))
                    meta['requested_bytes'] += right-left-covered
            cursor = right
        if cursor < hi:
            unmapped_ranges.append((cursor, hi))
        for key in touched:
            groups[key]['request_overlaps'] += 1
    ranked = []
    for row in groups.values():
        row['unique_requested_allocation_bytes'] = union_size(row.pop('ranges'))
        if row['requested_bytes']:
            row['request_to_unique_ratio'] = row['requested_bytes']/row['unique_requested_allocation_bytes']
            ranked.append(row)
    ranked.sort(key=lambda row:row['requested_bytes'], reverse=True)
    zip_ranked = []
    for row in zip_reads.values():
        ranges = row.pop('ranges')
        row['unique_requested_payload_bytes'] = union_size(ranges) if row['category'] != 'container_metadata_or_eof_padding' else None
        row['compression_types'] = sorted(row['compression_types'])
        if row['requested_bytes']:
            zip_ranked.append(row)
    zip_ranked.sort(key=lambda row:row['requested_bytes'],reverse=True)
    if sum(row['requested_bytes'] for row in zip_ranked) != zip_attributed_bytes:
        raise ValueError('ZIP requested-byte accounting failed')
    unmapped = sum(hi-lo for lo, hi in unmapped_ranges)
    unique = union_size(system_ranges)
    if sum(row['requested_bytes'] for row in ranked)+unmapped != requested:
        raise ValueError('Requested-byte accounting failed')
    if sum(row['unique_requested_allocation_bytes'] for row in ranked)+union_size(unmapped_ranges) != unique:
        raise ValueError('Unique-sector accounting failed')
    return dict(image=str(args.image), image_sha256=args.image_sha256,
        trace=str(args.trace), trace_sha256=trace_sha256,
        partition_map_sha256=hashlib.sha256(raw).hexdigest(),
        system_partition_start_sector=sector_start, block_size=block,
        ext4_ro_compat=hex(ro_compat), shared_blocks_feature=bool(ro_compat & 0x4000),
        inventoried_inodes=len(rows), data_extents=len(extents), allocation_segments=len(segments),
        system_read_request_overlaps=system_requests, requested_bytes=requested,
        request_window_ns=[args.start_ns,args.end_ns] if args.start_ns is not None else None,
        unique_requested_sector_bytes=unique, unassigned_requested_bytes=unmapped,
        unassigned_unique_requested_sector_bytes=union_size(unmapped_ranges),
        hot_allocations=ranked, exclusive_zip_payload_reads=zip_ranked,
        zip_exclusive_requested_bytes=zip_exclusive_bytes,
        zip_attributed_requested_bytes=zip_attributed_bytes,
        zip_ambiguous_logical_offset_requested_bytes=zip_exclusive_bytes-zip_attributed_bytes,
        tool_sha256=digest(Path(__file__)),
        query=sql, processor_sha256=digest(args.processor),
        processor_diagnostics=query.stderr,
        limits=['Read request issue events are not completed/physical NAND transfers or retained RAM.',
                'Inode data allocations include EOF block padding; directory data is identified separately.',
                'Unassigned bytes include filesystem metadata, extent-tree blocks and AVB/free space; not automatically file data.',
                'ZIP attribution identifies stored payload ranges only where a physical block has one inode and one logical-offset interpretation; ambiguous shared blocks are excluded.',
                'ZIP payload requests do not identify class/method execution or the initiating task.',
                'SHARED_BLOCKS ext4 allocations have multiple valid inode owners; shared groups are counted once and not assigned to one file.',
                'Repeated sectors alone do not prove readahead waste or reclaim causality.',
                'Trace device45824 is pinned to the captured handset mmcblk0; image/layout identity must be established separately.',
                'Tracing adds memory and I/O overhead; this is not a tracing-neutral baseline.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image','trace','partition-map','processor','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--trace-sha256', required=True)
    parser.add_argument('--start-ns',type=int)
    parser.add_argument('--end-ns',type=int)
    args = parser.parse_args()
    report = analyze(args)
    with args.output.open('x') as output:
        output.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('requested_bytes','unique_requested_sector_bytes','unassigned_requested_bytes')}))
    print(json.dumps(report['hot_allocations'][:12], indent=2))

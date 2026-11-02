"""Reclassify guarded historical smaps; file names containing stack are not stack allocations."""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from summarize_memory_maps import HEADER, METRICS, category, summarize

OLD_COMMIT='5209942'
OLD_SHA='1c9b3cb75cd44f676430e67e1803da6a7c7196b9640fc50819785bbab1fe76bf'
CAPTURES=['image38-memory-maps01','image43-memory-madvise-vmas-after01',
          'image44-memory-madvise-vmas-after01','image43-camera-conditioning-vmas-after01']


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def old_parser():
    raw=subprocess.run(['git','show',OLD_COMMIT+':tools/summarize_memory_maps.py'],capture_output=True,check=True).stdout
    if hashlib.sha256(raw).hexdigest()!=OLD_SHA: raise ValueError('Prior parser identity mismatch')
    namespace={'__name__':'prior_smaps_attribution'}
    exec(compile(raw,'prior_smaps_attribution.py','exec'),namespace)
    return namespace


def mapping_rows(text):
    rows=[]
    for line in text.splitlines():
        if header:=HEADER.fullmatch(line):
            rows.append(dict(name=header[4] or '',permissions=header[3],metrics={}))
        elif rows:
            match=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
            if match and (match[1] in METRICS or match[1]=='Size'): rows[-1]['metrics'][match[1]]=int(match[2])
    if not rows or any('Pss' not in r['metrics'] or 'Size' not in r['metrics'] for r in rows): raise ValueError('Incomplete maps')
    return rows


def capture(root,old):
    manifest=json.loads((root/'manifest.json').read_text())
    if not manifest['complete']: raise ValueError('Incomplete capture')
    records=manifest['reads']
    if len({r['name'] for r in records})!=len(records): raise ValueError('Duplicate capture read')
    for record in records:
        if record.get('returncode')!=0 or sha(root/(record['name']+'.txt'))!=record['sha256']:
            raise ValueError('Capture hash/exit mismatch')
    for label in ['identity-before','identity-after']:
        if (root/(label+'.txt')).read_text().splitlines()!=[manifest['image'],manifest['boot'],'0']:
            raise ValueError('Image/boot/root mismatch')
    result=[]
    for process in manifest['processes']:
        pid=str(process['pid'])
        for label in ['stat-before','stat-after']:
            stat=(root/(pid+'-'+label+'.txt')).read_text()
            if int(stat.rsplit(')',1)[1].split()[19])!=process['start_ticks']: raise ValueError('PID lifetime mismatch')
        if (root/(pid+'-cmdline.txt')).read_bytes().split(b'\0')[0].decode().strip()!=process['command']:
            raise ValueError('Command mismatch')
        path=root/(pid+'-smaps.txt');text=path.read_text();before=old['summarize'](text);after=summarize(text)
        if before['total_KiB']!=after['total_KiB'] or before['largest_backings_KiB']!=after['largest_backings_KiB']:
            raise ValueError('Classification changed backing/accounting totals')
        rows=mapping_rows(text);moved={};stack_parts=Counter();stack_tids=set();main_names=set();signal_maps=0;virtual=0
        for row in rows:
            name=row['name'];previous=old['category'](name);current=category(name)
            if previous!=current:
                key=(name,previous,current)
                group=moved.setdefault(key,dict(name=name,previous_category=previous,corrected_category=current,mappings=0,
                                               **{metric:0 for metric in METRICS}))
                group['mappings']+=1
                for metric in METRICS:group[metric]+=row['metrics'].get(metric,0)
            if current=='stack_labelled':
                virtual+=row['metrics']['Size']
                match=re.fullmatch(r'\[anon:stack_and_tls:(\d+)\]',name)
                if match:
                    stack_tids.add(match[1]);kind='numeric_stack_and_tls_label'
                elif name=='[anon:stack_and_tls:main]':main_names.add(name);kind='main_stack_and_tls_label'
                elif name=='[anon:thread signal stack]':signal_maps+=1;kind='alternate_signal_stack_label'
                else:kind='other_stack_label'
                stack_parts[(kind,row['permissions'])]+=1
        result.append(dict(process=process,smaps_sha256=sha(path),mapping_count=len(rows),
            total_KiB=after['total_KiB'],all_total_and_largest_backing_metrics_unchanged=True,
            old_stack_group=before['groups_KiB'].get('stack_labelled'),corrected_stack_group=after['groups_KiB'].get('stack_labelled'),
            moved_backings=list(moved.values()),stack_virtual_reservation_KiB=virtual,
            distinct_numeric_stack_labels=len(stack_tids),main_stack_labels=len(main_names),signal_stack_mappings=signal_maps,
            stack_mapping_parts=[dict(label_kind=kind,permissions=permissions,mappings=count) for (kind,permissions),count in sorted(stack_parts.items())]))
    return dict(capture=str(root),image=manifest['image'],boot=manifest['boot'],processes=result)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-capture',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    old=old_parser();sources=json.loads((args.source_capture/'source-manifest.json').read_text())
    for source in sources:
        if sha(args.source_capture/'source'/source['path'])!=source['sha256']: raise ValueError('Bionic source capture changed')
    captures=[capture(Path('artifacts/runtime')/name,old) for name in CAPTURES]
    report=dict(prior_parser=dict(commit=OLD_COMMIT,sha256=OLD_SHA),
                corrected_parser_sha256=sha(Path(__file__).with_name('summarize_memory_maps.py')),
                captures=captures,bionic_source_context=sources,
                limits=['Historical guarded captures; no phone command, allocation change, binary rewrite or saving.',
                        'Category corrections preserve process totals and reported largest-backing metrics; old committed evidence is retained as historical and superseded for stack labels.',
                        'Mapping counts and virtual reservation are not thread counts or physical bytes; permission splits and alternate stacks can produce several VMAs per thread.',
                        'Numeric label counts are not a live task-list/lifetime census and do not establish stack-cache retention or leaks.',
                        'Bionic source shows separate guarded signal/stack+TLS mappings and exit-time unmapping; source context does not prove exact binary provenance or every runtime path.',
                        'Resident PSS and logical SwapPss stay separate; no sum is a physical zram/whole-device working-set baseline.'])
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps([dict(capture=c['capture'],process=p['process']['command'],old_stack_Pss=p['old_stack_group']['Pss'],
                           corrected_stack_Pss=p['corrected_stack_group']['Pss'],numeric_stack_labels=p['distinct_numeric_stack_labels'],
                           signal_maps=p['signal_stack_mappings']) for c in captures for p in c['processes']],indent=2))

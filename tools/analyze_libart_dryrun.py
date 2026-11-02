"""Offline audit of actual private Ninja dry-run and baseline header closure; no execution."""
import argparse,hashlib,json,re
from pathlib import Path
from review_libart_closure import graph_path,parse_query,pin,TREE,SOURCE,GRAPH,STATIC,LINK,STRIP
OAT_HEADER='47bf486dac1069ba5c602b571d3bf5a0f14eed235f6a5a68282570cb5ec4c245'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def header_deps(text):
    lines=text.splitlines();m=re.fullmatch(re.escape(STATIC)+r': #deps (\d+), deps mtime (\d+) \(VALID\)',lines[0]) if lines else None
    if not m:raise ValueError('Missing/invalid baseline dependency record')
    paths=[]
    for line in lines[1:]:
        if not line:continue
        if not line.startswith('    '):raise ValueError('Malformed/truncated header path')
        paths.append(graph_path(line[4:]))
    if len(paths)!=int(m[1]) or len(set(paths))!=len(paths) or SOURCE not in paths:raise ValueError('Header count/uniqueness/source differs')
    return paths,int(m[2])

def analyze(a):
    result=json.loads((a.capture/'dryrun.result.json').read_text())
    if not result['complete'] or not result['dryrun_only'] or result['compiler_executed'] or result['ready_for_compile'] or not result['shared_cache_unchanged'] or not result['private_object_libraries_unchanged'] or result['plan_action_count']!=3 or not result['plan_matches_reviewed_three_commands']:raise ValueError('Actual dry-run failed/changed artifacts/plan')
    expected=['query-manager','query-link','query-strip','commands','baseline-header-deps','dry-run']
    if [r['name'] for r in result['commands']]!=expected or any(r['exit']!=0 for r in result['commands']):raise ValueError('Ninja read closure differs')
    verified=[];not_downloaded=[]
    for row in result['commands']:
        for suffix in ('stdout','stderr'):
            name=row['name']+'.'+suffix;p=a.capture/name
            if p.exists():
                if sha(p)!=row[suffix+'_sha256']:raise ValueError('Downloaded raw payload hash differs: '+name)
                verified.append(name)
            else:not_downloaded.append(name)
    commands=json.loads(a.commands_review.read_text());query=json.loads(a.query_review.read_text())
    edges={e['target']:e for e in query['edges']}
    for name,target in [('query-manager',STATIC),('query-link',LINK),('query-strip',STRIP)]:
        parsed=parse_query((a.capture/(name+'.stdout')).read_text(),target)
        if any(parsed[k]!=edges[target][k] for k in ('rule','inputs','input_groups')):raise ValueError('Actual stage query differs from reviewed graph')
    if sha(a.capture/'commands.stdout')!=commands['commands_sha256']:raise ValueError('Reviewed/actual command export differs')
    actual=[re.sub(r'^\[[0-9]+/[0-9]+\] ','',l) for l in (a.capture/'dry-run.stdout').read_text().splitlines() if re.match(r'^\[[0-9]+/[0-9]+\] ',l)]
    if actual!=(a.capture/'commands.stdout').read_text().splitlines():raise ValueError('Actual dry-run actions differ')
    paths,mtime=header_deps((a.capture/'baseline-header-deps.stdout').read_text())
    explain=(a.capture/'dry-run.stderr').read_text().splitlines()
    if any(not line.startswith('ninja explain: ') for line in explain):raise ValueError('Unexpected non-explain dry-run stderr')
    reason=re.search(re.escape(STATIC)+r' older than most recent input art/runtime/oat_file_manager.cc \((\d+) vs (\d+)\)', '\n'.join(explain))
    if not reason or int(reason[1])!=mtime or int(reason[2])<=mtime:raise ValueError('Source timestamp does not explain the planned compile')
    if sha(a.oat_header)!=OAT_HEADER:raise ValueError('Retained OAT header source changed')
    includes=re.findall(r'^#include [<"]([^>"]+)[>"]$',a.oat_header.read_text(),re.M)
    resolved={inc:[p for p in paths if p.endswith('/'+inc)] for inc in includes}
    if len(includes)!=5 or any(len(v)!=1 for v in resolved.values()):raise ValueError('New OAT header includes not uniquely covered by baseline deps')
    new_header='/build/aosp/art/runtime/oat.h';required_headers=sorted(set(paths)|{new_header})
    desired=set(required_headers)|set(query['paths_requiring_readonly_host_hash_receipts'])|set(commands['additional_receipt_paths_including_depfile_tools'])|{STATIC,LINK,STRIP,GRAPH}
    known=set(commands['direct_tool_receipts'])|{SOURCE,GRAPH}
    copy_covered=sorted(p for p in desired if p.startswith(TREE+'/'))
    manifest=json.loads((a.capture/'inputs/manifest.json').read_text());cache=json.loads((a.capture/'inputs/cache-before.json').read_text())
    if sha(a.capture/'inputs/cache-before.json')!=manifest['input_sha256']['cache-before.json'] or len(cache)!=manifest['cache_files'] or sum(r['size'] for r in cache.values())!=manifest['cache_bytes']:raise ValueError('Actual copied-cache inventory hash/count/bytes differs')
    if manifest['input_sha256']['runner.py']!='b5e088207375bf33c1a6569da26c9a664177cd338a742e1be751d43e77383975' or not manifest['dryrun_only'] or manifest['compile_authorized']:raise ValueError('Unexpected actual runner/authorization')
    if manifest['source_sha256']!=query['parent_reported_source_sha256'] or manifest['graph_sha256']!=query['parent_reported_graph_sha256']:raise ValueError('Stage source/graph differs from query receipts')
    for path in copy_covered:
        name=path[len(TREE)+1:]
        if name not in cache:raise ValueError('Required cache input missing from actual inventory')
        pin(cache[name]['sha256'])
    if cache[STATIC[len(TREE)+1:]]['mtime_ns']!=mtime or cache[STRIP[len(TREE)+1:]]['sha256']!=manifest['baseline_libart_sha256']:raise ValueError('Header database/cache object/library binding differs')
    receipts=json.loads((a.capture/'header-receipts.json').read_text());headers={};hostroot='/opt/kaidroid/kaidroid-build-20261023'
    if receipts['baseline_count']!=len(paths) or receipts['added']!=['art/runtime/oat.h'] or receipts['candidate_preprocessed']:raise ValueError('Header export scope differs')
    for row in receipts['files']:
        path=graph_path(row['dependency'])
        if path in headers or not row['path'].startswith(hostroot+'/') or '/build'+row['path'][len(hostroot):]!=path or not row['resolved'].startswith(hostroot+'/') or '..' in row['resolved'].split('/'):raise ValueError('Header receipt path/duplicate/resolution differs')
        if row['size']<0 or not 0<=int(row['mode'],8)<=0o7777:raise ValueError('Header metadata differs')
        headers[path]=pin(row['sha256'])
    if set(headers)!=set(required_headers) or headers[new_header]!=OAT_HEADER or headers[SOURCE]!=manifest['source_sha256']:raise ValueError('Header set/primary source/newOAT hash differs')
    known.update(headers)
    pending=sorted(desired-known-set(copy_covered))
    unresolved_nodes=[p for p in pending if p.endswith('/genrule-phony')]
    pending=[p for p in pending if p not in unresolved_nodes]
    extra=json.loads((a.capture/'remaining-input-receipts03.json').read_text());external={}
    if extra['graph_sha256']!=manifest['graph_sha256'] or extra['compiler_executed'] or extra['node_file_exists'] or unresolved_nodes!=[extra['node']]:raise ValueError('External receipt/virtual-node scope differs')
    edge=re.fullmatch(r'build\s+(\S+?)\s*:\s*(\S+)(?:\s+(.*))?',extra['node_edge'])
    if not edge or edge[1]!=extra['node'] or edge[2]!='phony':raise ValueError('Missing actual phony edge declaration')
    phony_inputs=[graph_path(p) for p in (edge[3] or '').split()]
    if not phony_inputs:raise ValueError('Truncated actual phony prerequisites')
    for row in extra['files']:
        path=graph_path(row['path'])
        if path in external or not row['resolved'].startswith(hostroot+'/') or '..' in row['resolved'].split('/') or row['size']<0:raise ValueError('External input receipt path/metadata differs')
        external[path]=pin(row['sha256'])
    if set(external)!=set(pending) or len(external)!=74:raise ValueError('Remaining74file receipt set differs')
    known.update(external);pending=[];unresolved_nodes=[]
    expected_metadata={p[len(TREE)+1:] for p in (STATIC+'.d',LINK+'.rsp',STRIP+'.d')}
    if set(result['private_ninja_metadata_changes'])!=expected_metadata:raise ValueError('Actual private metadata changes differ')
    return dict(status='actual_private_dryrun_pass_header_input_analysis_compile_still_gated',result_sha256=sha(a.capture/'dryrun.result.json'),python_version=result['python_version'],elapsed_seconds=result['elapsed_seconds'],
        raw_payloads_verified_here=verified,raw_payloads_not_downloaded_here=not_downloaded,all_raw_payloads_revalidated_here=not not_downloaded,
        actual_actions_equal_reviewed=True,actual_query_edges_equal_reviewed=True,planned_compile_explained_by_candidate_mtime_ns=int(reason[2]),compiler_executed=False,ready_for_compile=False,baseline_dependency_count=len(paths),baseline_object_mtime_ns=mtime,
        baseline_header_paths=paths,new_explicit_heap_header_already_covered='/build/aosp/art/runtime/gc/heap.h' in paths,new_oat_header_already_covered=new_header in paths,
        new_oat_header_expected_sha256=OAT_HEADER,new_oat_header_literal_includes_covered=resolved,required_candidate_header_path_count=len(required_headers),
        parent_verified_cache_copy_covered_paths=copy_covered,copy_inventory_locally_revalidated=True,copy_inventory_sha256=sha(a.capture/'inputs/cache-before.json'),copy_file_count=len(cache),copy_bytes=manifest['cache_bytes'],stage_manifest_sha256=sha(a.capture/'inputs/manifest.json'),candidate_sha256=manifest['candidate_sha256'],header_receipts_sha256=sha(a.capture/'header-receipts.json'),header_receipt_count=len(headers),header_receipt_file_contents_rehashed_here=False,remaining_readonly_file_hash_request_paths=pending,graph_nodes_requiring_rule_classification_not_blind_file_hash=unresolved_nodes,
        external_input_receipt_count=len(external),external_input_receipts_sha256=sha(a.capture/'remaining-input-receipts03.json'),static_file_receipt_catalog_complete=True,classified_virtual_node=dict(path=extra['node'],rule='phony',file_exists=False,prerequisites=phony_inputs),
        known_direct_tool_hash_receipt_count=commands['direct_tool_receipt_count'],private_ninja_metadata_changes=result['private_ninja_metadata_changes'],
        compiler_runtime_requests=['No further hash request for the reconciled static catalog:520cachefiles,467headers,74externalfiles and direct10tool receipts are covered.','Real clang++.real -> clang.real -> clang-11 resolution/hash receipt (parent reported519638ab...) plus PT_INTERP/DT_NEEDED/RPATH/RUNPATH for real clang, lld and executed LLVM tools.','Resolve/hash those dynamic libraries and /lib64/ld-linux-x86-64.so.2 INSIDE verified builder image, not against host libraries; do not execute ldd.','Accepted current-framework services/preopt rebind, then separate parent-reviewed actual compile job with source/input before-after checks.'],
        analyzer_sha256=sha(Path(__file__)),limits=['Parent actual runner reports unchanged shared cache/private object-library bytes and only three known private rsp/dep metadata changes. Downloaded raw payloads are independently hash-checked against that report.','Header deps describe the baseline object. Literal include overlap plus one pinned oat.h is source coverage evidence, not candidate preprocessor execution or proof that macro/include-order behavior cannot change.','Actual520file cache inventory,467header and74external file receipts are locally reconciled, not an independent rehash of their host file bytes or proof of atomic snapshot. Before/after input checks remain for any real compile.','The confirmed phony node is not a file or new compiler read. Its prerequisites are graph dependencies; the actual three-action dry-run did not schedule their regeneration.','Tool receipts and headers do not establish ABI, code scope, runtime functionality or memory savings. ThinLTO can change multiple linked functions.','No host/device call, copy, Ninja invocation or compilation by this analysis.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('capture','commands-review','query-review','oat-header','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=analyze(a)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(baseline_deps=r['baseline_dependency_count'],required_candidate_headers=r['required_candidate_header_path_count'],copy_covered=len(r['parent_verified_cache_copy_covered_paths']),remaining_hash_receipts=len(r['remaining_readonly_file_hash_request_paths']),missing_local_payloads=r['raw_payloads_not_downloaded_here'],ready_for_compile=False),indent=2))

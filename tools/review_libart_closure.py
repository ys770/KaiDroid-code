"""Offline consistency review of exported libart graph/copy/write receipts; never executes them."""
import argparse,hashlib,json,posixpath,re
from pathlib import Path

TREE='/build/out-eng-02/soong/.intermediates/art/runtime/libart'
SOURCE='/build/aosp/art/runtime/oat_file_manager.cc'
GRAPH='/build/out-eng-02/soong/build.ninja'
STATIC=TREE+'/android_arm_armv7-a-neon_static_com.android.art.release/obj/art/runtime/oat_file_manager.o'
LINK=TREE+'/android_arm_armv7-a-neon_shared_com.android.art.release/unstripped/libart.so'
STRIP=TREE+'/android_arm_armv7-a-neon_shared_com.android.art.release/libart.so'
HASH=re.compile('[a-f0-9]{64}')

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def pin(value):
    if not isinstance(value,str) or not HASH.fullmatch(value):raise ValueError('Malformed SHA256')
    return value
def absolute(path):
    if not isinstance(path,str) or not path.startswith('/') or '\\' in path or '\0' in path or posixpath.normpath(path)!=path or path.startswith('//'):raise ValueError('Noncanonical POSIX path')
    return path
def within(path,root):return path==root or path.startswith(root+'/')
def leaf(path,root):
    absolute(path)
    if not within(path,root) or path==root:raise ValueError('Path escapes required root')
    return path

def graph_path(path,cwd='/build/aosp'):
    if not isinstance(path,str) or not path or '$' in path or '\\' in path or '\0' in path:raise ValueError('Unresolved/invalid Ninja path')
    if path.startswith('/'):return absolute(path)
    result=posixpath.normpath(posixpath.join(cwd,path))
    if not within(result,'/build'):raise ValueError('Relative Ninja input escapes build root')
    return absolute(result)

def parse_query(text,target):
    lines=text.splitlines()
    if not lines or lines[0]!=target+':' or len(lines)<3 or not lines[1].startswith('  input: '):raise ValueError('Unexpected raw Ninja query header')
    rule=lines[1][len('  input: '):];inputs=[];closed=False;groups={'explicit':[],'implicit':[],'order_only':[]};downstream=[]
    for line in lines[2:]:
        if line=='  outputs:':
            if closed:raise ValueError('Repeated outputs section')
            closed=True;continue
        if not line and closed:continue
        if not line.startswith('    '):raise ValueError('Unexpected/truncated raw Ninja input query')
        value=line[4:]
        if closed:downstream.append(graph_path(value));continue
        kind='explicit'
        for prefix,label in [('|| ','order_only'),('| ','implicit')]:
            if value.startswith(prefix):value=value[len(prefix):];kind=label;break
        value=graph_path(value);inputs.append(value);groups[kind].append(value)
    if not rule or not inputs or not closed:raise ValueError('Incomplete raw Ninja input query')
    return dict(target=target,rule=rule,inputs=inputs,input_groups=groups,downstream_users=downstream)

def query_inputs(text,target):
    parsed=parse_query(text,target);return parsed['rule'],parsed['inputs']

def validate_graph(s,original_hash,candidate_hash,baseline_hash):
    if s['schema']!=1 or s['snapshot_complete'] is not True or s['phase']!='graph_readonly':raise ValueError('Wrong graph-only snapshot')
    if s['cwd']!='/build/aosp' or s['container_root_read_only'] is not True or s['network']!='none' or s['user']!='1000:1000':raise ValueError('Read-only graph environment differs')
    before=s['shared_input_sha256_before']
    if before!=s['shared_input_sha256_after']:raise ValueError('Shared inputs changed during graph capture')
    for path,h in before.items():absolute(path);pin(h)
    if before.get(SOURCE)!=original_hash or before.get(STRIP)!=baseline_hash or GRAPH not in before or s['candidate_sha256']!=candidate_hash:raise ValueError('Graph source/baseline/candidate binding differs')
    edges=s['edges']
    if len(edges)!=3 or {e['target'] for e in edges}!={STATIC,LINK,STRIP}:raise ValueError('Graph target closure differs')
    inputs={e['target']:e['inputs'] for e in edges}
    if SOURCE not in inputs[STATIC] or STATIC not in inputs[LINK] or LINK not in inputs[STRIP]:raise ValueError('Manager compile/link/strip dependencies absent')
    for edge in edges:
        if not edge['complete'] or edge['outputs']!=[edge['target']] or not edge['rule']:raise ValueError('Incomplete graph edge')
        if set(edge['input_groups'])!={'explicit','implicit','order_only'} or [p for k in ('explicit','implicit','order_only') for p in edge['input_groups'][k]]!=edge['inputs']:raise ValueError('Graph dependency groups differ')
        for path in edge['inputs']:
            absolute(path)
            if path not in {SOURCE,STATIC,LINK,STRIP} and path not in before:raise ValueError('Unhashed graph input')
    records=s['read_records']
    if len(records)!=4 or {r['name'] for r in records}!={'query-manager','query-link','query-strip','commands'} or any(r['exit']!=0 for r in records):raise ValueError('Wrong graph-only reads')
    for row in records:
        if any(not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*',row[k]) for k in ('stdout_file','stderr_file')):raise ValueError('Invalid raw graph filename')
        pin(row['stdout_sha256']);pin(row['stderr_sha256'])
    return dict(graph_receipts_consistent=True,declared_closure_consistent=False,copied_file_count=None,graph_sha256=before[GRAPH],candidate_sha256=candidate_hash,
        ready_for_launch=False,command_semantics_proven=False,host_file_contents_independently_rehashed=False,synthetic_snapshot=bool(s.get('synthetic',False)),
        limits=['Read-only graph/source receipts only; no private copy, dry-run or write closure reviewed.','Raw query hashes and dependency receipts are checked; command/script semantics and host export completeness need parent review.','No services OAT checksum is used. Actual accepted-image candidate/raw binding and later prelaunch review remain mandatory.'])

def validate(s,original_hash,candidate_hash,baseline_hash):
    if s['schema']!=1 or s['snapshot_complete'] is not True or s['phase']!='prelaunch_review':raise ValueError('Wrong/incomplete review snapshot')
    stage=absolute(s['stage'])
    if not re.fullmatch('/build/memory-services-art-build[0-9]{2}',stage):raise ValueError('Unreviewed stage name')
    if s['cwd']!='/build/aosp' or s['container_root_read_only'] is not True or s['network']!='none' or s['user']!='1000:1000' or s['jobs']!=1:raise ValueError('Container isolation differs')
    before=s['shared_input_sha256_before'];after=s['shared_input_sha256_after']
    if before!=after:raise ValueError('Shared inputs changed during snapshot')
    for path,h in before.items():absolute(path);pin(h)
    if before.get(SOURCE)!=original_hash or before.get(STRIP)!=baseline_hash or GRAPH not in before:raise ValueError('Source/baseline/graph receipts missing or different')
    if s['candidate_sha256']!=candidate_hash:raise ValueError('Candidate receipt differs')
    if s['candidate_container_resolved_path']!=stage+'/inputs/candidate.cc':raise ValueError('Candidate resolved path escapes stage')
    mounts=s['mounts'];targets=[m['target'] for m in mounts]
    if len(set(targets))!=len(targets):raise ValueError('Duplicate mount destination')
    expected={'/build':('ro','shared_root'),stage:('rw','private_stage'),TREE:('rw','private_libart_copy'),SOURCE:('ro','candidate_source')}
    if len(mounts)!=4 or set(targets)!=set(expected):raise ValueError('Unexpected/missing mount')
    for m in mounts:
        if (m['mode'],m['role'])!=expected[m['target']]:raise ValueError('Mount mode/role differs')
        if m['role']=='private_libart_copy' and m['backing_container_path']!=stage+'/libart-copy':raise ValueError('Writable cache does not use private copy')
        if m['role']=='candidate_source' and m['backing_container_path']!=stage+'/inputs/candidate.cc':raise ValueError('Source does not use read-only candidate')
    copies=s['copy_inventory'];left=copies['source'];right=copies['copy']
    if copies['complete'] is not True or not left or left!=right:raise ValueError('Incomplete or changed cache copy')
    if copies['source_root']!=TREE or copies['copy_root']!=stage+'/libart-copy':raise ValueError('Copy roots differ')
    for name,row in left.items():
        if not name or name.startswith('/') or posixpath.normpath(name)!=name or '..' in name.split('/') or '\\' in name:raise ValueError('Invalid cache relative path')
        if set(row)!={'sha256','size','mode','mtime_ns','kind'} or row['kind']!='file' or type(row['size']) is not int or row['size']<0 or type(row['mtime_ns']) is not int or row['mtime_ns']<0 or type(row['mode']) is not int:raise ValueError('Incomplete/nonregular copy receipt; symlinks require separate review')
        pin(row['sha256'])
        if TREE+'/'+name in before and row['sha256']!=before[TREE+'/'+name]:raise ValueError('Copy inventory disagrees with shared input hash')
    for target in (STATIC,LINK,STRIP):
        if target[len(TREE)+1:] not in left:raise ValueError('Cache lacks reviewed object/link/strip baseline')
    if s['bookkeeping']['complete'] is not True or s['bookkeeping']['root']!=stage+'/ninja' or s['temporary_root']!=stage+'/tmp':raise ValueError('Bookkeeping/temp not private')
    for row in s['bookkeeping']['files']:
        leaf(row['destination'],stage+'/ninja')
        if pin(row['source_sha256'])!=pin(row['copy_sha256']):raise ValueError('Bookkeeping copy differs')
    edges=s['edges']
    if len(edges)!=3 or {e['target'] for e in edges}!={STATIC,LINK,STRIP}:raise ValueError('Graph edge closure differs')
    inputs={e['target']:e['inputs'] for e in edges}
    if SOURCE not in inputs[STATIC] or STATIC not in inputs[LINK] or LINK not in inputs[STRIP]:raise ValueError('Manager compile/link/strip dependencies not established')
    for e in edges:
        if e['complete'] is not True or e['outputs']!=[e['target']] or not e['rule'] or not e['inputs']:raise ValueError('Truncated/unresolved edge')
        if set(e['input_groups'])!={'explicit','implicit','order_only'} or [p for k in ('explicit','implicit','order_only') for p in e['input_groups'][k]]!=e['inputs']:raise ValueError('Graph dependency groups differ')
        for path in e['inputs']:
            absolute(path)
            if path not in {STATIC,LINK,STRIP,SOURCE} and path not in before:raise ValueError('Unhashed graph input')
    actions=s['actions']
    if len(actions)!=3 or [a['role'] for a in actions]!=['manager_compile','libart_link','libart_strip']:raise ValueError('Dry-run must show exactly reviewed compile/link/strip; no zero-work or regeneration')
    allowed=(TREE,stage)
    all_writes=[]
    for action,target in zip(actions,(STATIC,LINK,STRIP)):
        if action['target']!=target or not action['argv'] or not all(isinstance(v,str) and v for v in action['argv']):raise ValueError('Command/target missing')
        absolute(action['argv'][0])
        if action['argv'][0] not in before:raise ValueError('Unhashed command executable or wrapper')
        if not action['declared_writes'] or target not in [w['path'] for w in action['declared_writes']]:raise ValueError('Missing command output receipt')
        for write in action['declared_writes']:
            for path in (write['path'],write['resolved_path']):
                absolute(path)
                if not any(within(path,r) and path!=r for r in allowed):raise ValueError('Command write or symlink resolution escapes private output mounts')
            all_writes.append(write)
        for response in action['response_files']:
            absolute(response['path']);pin(response['sha256'])
            if response['path'] not in before and response['path'] not in [w['path'] for a in actions for w in a['declared_writes']]:raise ValueError('Unbound response file')
    required={'query-manager','query-link','query-strip','commands','dry-run'}
    records=s['read_records']
    if len(records)!=5 or {r['name'] for r in records}!=required or any(r['exit']!=0 for r in records):raise ValueError('Missing/failed graph/command/plan reads')
    if len({r['stdout_file'] for r in records})!=5 or len({r['stderr_file'] for r in records})!=5:raise ValueError('Reused raw evidence filename')
    for row in records:
        if any(not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*',row[k]) for k in ('stdout_file','stderr_file')):raise ValueError('Snapshot filename escapes directory')
        pin(row['stdout_sha256'])
        pin(row['stderr_sha256'])
    return dict(stage=stage,declared_closure_consistent=True,copied_file_count=len(left),shared_hashed_input_count=len(before),declared_writes=all_writes,
        candidate_sha256=candidate_hash,baseline_source_sha256=original_hash,baseline_library_sha256=baseline_hash,graph_sha256=before[GRAPH],
        command_semantics_proven=False,host_file_contents_independently_rehashed=False,ready_for_launch=False,synthetic_snapshot=bool(s.get('synthetic',False)),
        limits=['Offline validation of exported receipts and raw log hashes only; it cannot attest that the host exporter truthfully or completely enumerated files/commands/writes.','Declared writes are not inferred shell/script semantics. Parent must inspect full raw commands, response files, wrappers and the real read-only mount/dry-run closure before a launch.','Source checksum is supplied from candidate bytes, not a services OAT fingerprint; reuses after explicit accepted-image rebind. This tool does not re-prove helper source scope; use the reviewed per-image generator/controls/raw binding.','No host command, filesystem copy, container launch, device action, ABI/code/runtime or saving proof.'])

def review(snapshot,candidate_dir,baseline_hash):
    s=json.loads(snapshot.read_text());original=sha(candidate_dir/'original.cc');candidate=sha(candidate_dir/'candidate.cc')
    manifest=json.loads((candidate_dir/'candidate.json').read_text())
    if manifest['original_sha256']!=original or manifest['candidate_sha256']!=candidate or sha(candidate_dir/'candidate.patch')!=manifest['patch_sha256']:raise ValueError('Candidate source/patch manifest changed')
    expected=manifest.get('baseline_libart_sha256',manifest.get('expected_baseline_libart_sha256'))
    if expected!=baseline_hash:raise ValueError('Accepted baseline library differs from candidate binding')
    reviewer=validate_graph if s['phase']=='graph_readonly' else validate
    result=reviewer(s,original,candidate,pin(baseline_hash))
    for row in s['read_records']:
        err=snapshot.parent/row['stderr_file']
        if sha(snapshot.parent/row['stdout_file'])!=row['stdout_sha256'] or sha(err)!=row['stderr_sha256'] or (row['name']!='dry-run' and err.read_bytes()):raise ValueError('Raw query/command/plan hash or stderr differs')
    by_name={r['name']:r for r in s['read_records']};edges={e['target']:e for e in s['edges']}
    for name,target in [('query-manager',STATIC),('query-link',LINK),('query-strip',STRIP)]:
        parsed=parse_query((snapshot.parent/by_name[name]['stdout_file']).read_text(),target)
        if any(parsed[k]!=edges[target][k] for k in ('rule','inputs','input_groups')):raise ValueError('Raw query disagrees with edge receipt')
    if s['phase']=='prelaunch_review':
        plan=(snapshot.parent/by_name['dry-run']['stdout_file']).read_text()
        if not plan.strip() or 'no work to do' in plan.lower():raise ValueError('Empty/zero-work raw plan')
    return dict(**result,snapshot_sha256=sha(snapshot),reviewer_sha256=sha(Path(__file__)))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('snapshot','candidate-dir','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--baseline-library-sha256',required=True);a=p.parse_args();r=review(a.snapshot,a.candidate_dir,a.baseline_library_sha256)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(declared_closure_consistent=r['declared_closure_consistent'],graph_receipts_consistent=r.get('graph_receipts_consistent'),ready_for_launch=False,copied_files=r['copied_file_count'])))

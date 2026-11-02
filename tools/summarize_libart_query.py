"""Parse the parent's combined readonly Ninja queries; no host call or command plan."""
import argparse,hashlib,json,re
from pathlib import Path
from review_libart_closure import parse_query,pin,SOURCE,STATIC,LINK,STRIP,TREE

def analyze(stdout,stderr,graph_sha,source_sha):
    if stderr.read_bytes():raise ValueError('Query stderr is not empty')
    raw=stdout.read_bytes();text=raw.decode().replace('\r\n','\n');headers=list(re.finditer(r'^(/[^\n]+):$',text,re.M))
    if [m[1] for m in headers]!=[STATIC,LINK,STRIP] or headers[0].start()!=0:raise ValueError('Wrong/missing combined query targets')
    edges=[]
    for i,match in enumerate(headers):
        block=text[match.start():headers[i+1].start() if i+1<len(headers) else len(text)]
        edge=parse_query(block,match[1]);edges.append(edge)
    by={e['target']:e for e in edges}
    if SOURCE not in by[STATIC]['input_groups']['explicit'] or STATIC not in by[LINK]['inputs'] or LINK not in by[STRIP]['input_groups']['explicit']:raise ValueError('Compile/link/strip dependency chain differs')
    if [e['rule'] for e in edges]!=['g.cc.cc','g.cc.ld','g.cc.strip']:raise ValueError('Unexpected libart rules')
    requested=sorted({p for e in edges for p in e['inputs'] if p not in (STATIC,LINK,STRIP)})
    return dict(status='actual_parent_readonly_query_parsed_command_copy_write_review_pending',query_stdout_sha256=hashlib.sha256(raw).hexdigest(),query_stderr_sha256=hashlib.sha256(stderr.read_bytes()).hexdigest(),
        parent_reported_graph_sha256=pin(graph_sha),parent_reported_source_sha256=pin(source_sha),graph_bytes_rehashed_here=False,source_bytes_rehashed_here=False,
        dependency_counts=[dict(target=e['target'],rule=e['rule'],**{k:len(v) for k,v in e['input_groups'].items()},downstream_users=len(e['downstream_users'])) for e in edges],edges=edges,
        paths_requiring_readonly_host_hash_receipts=requested,outside_libart_order_only=sorted({p for e in edges for p in e['input_groups']['order_only'] if not p.startswith(TREE+'/')}),
        commands_reviewed=False,copy_reviewed=False,dry_run_reviewed=False,write_closure_reviewed=False,ready_for_launch=False,
        parser_sha256=hashlib.sha256(Path(__file__).with_name('review_libart_closure.py').read_bytes()).hexdigest(),analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Parent captured actual queries in a read-only container. This tool only reads the downloaded logs; graph/source SHA values are parent-provided receipts, not new host reads.','Relative paths normalize under /build/aosp; explicit, implicit and order-only dependencies retain separate groups.','Ninja query outputs section lists downstream users, not outputs written by the selected edge or a requested APEX build.','Full commands/response files/wrappers, ThinLTO/temp/cache/depfile writes, complete input hashes and actual private-copy dry-run still require review. No copy/compile/launch authorization.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('stdout','stderr','output'):p.add_argument('--'+n,type=Path,required=True)
    for n in ('graph-sha256','source-sha256'):p.add_argument('--'+n,required=True)
    a=p.parse_args();r=analyze(a.stdout,a.stderr,a.graph_sha256,a.source_sha256)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(counts=r['dependency_counts'],hash_receipts_needed=len(r['paths_requiring_readonly_host_hash_receipts']),ready_for_launch=False),indent=2))

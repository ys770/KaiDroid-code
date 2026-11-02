"""Review exported actual libart commands and pinned strip branch; no execution."""
import argparse,hashlib,json,re,shlex
from pathlib import Path
from review_libart_closure import graph_path,pin,STATIC,LINK,STRIP,SOURCE,TREE,GRAPH

STRIP_SCRIPT='4ee69021598b68bb07ae4a14c07e1f369fec747d1af686c5557db4b48a2f5ff9'
COMMANDS='73a492f7b5cfe7b3b57048e09cbeff2fe607f1d5fd89206cbe960e4cead5ac2a'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def command(line):
    if '$(' in line or '`' in line:raise ValueError('Unreviewed shell expansion in command')
    tokens=shlex.split(line);env={}
    while tokens and re.fullmatch('[A-Z_][A-Z_0-9]*=.*',tokens[0]):
        key,value=tokens.pop(0).split('=',1)
        if key in env:raise ValueError('Duplicate command environment assignment')
        env[key]=value
    if not tokens or any(t in {'&&','||','|',';','>','<','2>','2>&1'} for t in tokens):raise ValueError('Compound shell requires separate review')
    tokens[0]=graph_path(tokens[0]);return env,tokens
def option(tokens,key):
    if tokens.count(key)!=1 or tokens.index(key)+1>=len(tokens):raise ValueError('Missing/repeated command option '+key)
    return tokens[tokens.index(key)+1]

def analyze(root,query):
    if (root/'commands.stderr').read_bytes():raise ValueError('Commands export stderr')
    if sha(root/'commands.stdout')!=COMMANDS:raise ValueError('Actual command bytes changed; explicit re-review required')
    lines=(root/'commands.stdout').read_text().splitlines()
    if len(lines)!=3:raise ValueError('Require exact selected compile/link/strip commands')
    (ce,cc),(le,ld),(se,strip)=[command(line) for line in lines]
    compiler='/build/aosp/prebuilts/clang/host/linux-x86/clang-r383902b/bin/clang++'
    if ce!={'PWD':'/proc/self/cwd'} or le or cc[0]!=compiler or ld[0]!=compiler:raise ValueError('Unreviewed compiler/environment')
    if '-c' not in cc or graph_path(cc[-1])!=SOURCE or graph_path(option(cc,'-o'))!=STATIC or graph_path(option(cc,'-MF'))!=STATIC+'.d' or '-MD' not in cc:raise ValueError('Compile paths/dependency mode differ')
    if '-O3' not in cc or any(f not in cc or f not in ld for f in ('-flto=thin','-fsplit-lto-unit')):raise ValueError('Optimization/LTO flags changed')
    if graph_path(option(ld,'-o'))!=LINK or [t for t in ld if t.startswith('@')]!=['@'+LINK+'.rsp']:raise ValueError('Link output/response differs')
    if any('cache-dir' in t or 'save-temps' in t or 'ftime-trace' in t or t.startswith('-Wl,-Map') for t in cc+ld):raise ValueError('Additional compiler/linker outputs require review')
    if set(se)!={'CROSS_COMPILE','XZ','CLANG_BIN'} or strip[0]!='/build/aosp/build/soong/scripts/strip.sh' or sha(root/'strip.sh')!=STRIP_SCRIPT:raise ValueError('Unknown strip script/environment')
    if len(strip)!=9 or set(t for t in strip[1:] if t.startswith('--'))!={'--add-gnu-debuglink','--keep-symbols-and-debug-frame'} or graph_path(option(strip,'-i'))!=LINK or graph_path(option(strip,'-o'))!=STRIP or graph_path(option(strip,'-d'))!=STRIP+'.d':raise ValueError('Strip selected branch changed')
    clangbin=graph_path(se['CLANG_BIN'])
    if clangbin!=compiler.rsplit('/',1)[0]:raise ValueError('Strip LLVM directory changed')
    rsp=shlex.split((root/'libart.so.rsp').read_text())
    if any(not p.startswith('/') or not p.endswith('.o') or not p.startswith(TREE+'/') for p in rsp):raise ValueError('Unexpected response flag/path/nested response')
    q=json.loads(query.read_text());edges={e['target']:e for e in q['edges']}
    rules=json.loads((root/'rules.json').read_text())
    if rules['graph_sha256']!=q['parent_reported_graph_sha256'] or len(rules['blocks'])!=6:raise ValueError('Rule metadata graph/block closure differs')
    assignments={}
    for name in ('g.cc.cc','g.cc.ld','g.cc.strip'):
        block=rules['blocks']['rule '+name]
        if block[0]!='rule '+name:raise ValueError('Rule header changed')
        values={}
        for line in block[1:]:
            if not line:continue
            m=re.fullmatch(r'\s+(\w+) = (.*)',line)
            if not m or m[1] in values:raise ValueError('Unsupported/truncated rule assignment')
            values[m[1]]=m[2]
        assignments[name]=values
    for name in ('g.cc.cc','g.cc.strip'):
        if assignments[name].get('depfile')!='${out}.d' or assignments[name].get('deps')!='gcc':raise ValueError('Dependency output mode changed')
    if assignments['g.cc.ld'].get('rspfile')!='${out}.rsp' or assignments['g.cc.ld'].get('rspfile_content')!='${in}' or assignments['g.cc.ld'].get('restat')!='true':raise ValueError('Ninja response binding changed')
    for target in (STATIC,LINK,STRIP):
        if 'build '+target+' :' not in rules['blocks']:raise ValueError('Missing exported selected edge block')
    if rsp!=edges[LINK]['input_groups']['explicit']:raise ValueError('Response contents disagree with actual query object inputs')
    graph_inputs={p for e in edges.values() for p in e['inputs']}
    link_reads=[]
    for i,t in enumerate(ld[1:],1):
        if t.startswith('/') and (i==0 or ld[i-1]!='-o'):link_reads.append(graph_path(t))
        elif t.startswith('prebuilts/'):link_reads.append(graph_path(t))
    strip_tools=[clangbin+'/llvm-readelf',clangbin+'/llvm-objcopy']
    strip_depfile_tools=[graph_path(se['CROSS_COMPILE']+'objcopy'),clangbin+'/llvm-nm',clangbin+'/llvm-objcopy',clangbin+'/llvm-readelf',clangbin+'/llvm-strip']
    driver_tools=[compiler.rsplit('/',1)[0]+'/ld.lld']
    reads=sorted(set(link_reads+rsp+strip_tools+driver_tools+[compiler,strip[0]]))
    hostroot='/opt/kaidroid/kaidroid-build-20261023';tools=json.loads((root/'toolchain.json').read_text())['files'];tool_receipts={}
    for tool in tools:
        for key in ('path','resolved'):
            if not tool[key].startswith(hostroot+'/') or '..' in tool[key].split('/'):raise ValueError('Tool resolution escapes reviewed build root')
        path='/build'+tool['path'][len(hostroot):];resolved='/build'+tool['resolved'][len(hostroot):]
        if path in tool_receipts or int(tool['mode'],8)!=0o755 or tool['bytes']<=0:raise ValueError('Duplicate/nonexecutable tool receipt')
        pin(tool['sha256']);tool_receipts[path]=dict(resolved=resolved,sha256=tool['sha256'],bytes=tool['bytes'],mode=tool['mode'],symlink=tool['symlink'])
    direct_required=set(strip_tools+strip_depfile_tools+driver_tools+[compiler,strip[0],graph_path(se['XZ']),'/build/aosp/prebuilts/build-tools/linux-x86/bin/ninja'])
    if set(tool_receipts)!=direct_required or len(tool_receipts)!=10 or tool_receipts[strip[0]]['sha256']!=STRIP_SCRIPT:raise ValueError('Direct tool receipts incomplete/different')
    include_dirs=[];forced_headers=[]
    for i,t in enumerate(cc):
        if t in ('-I','-isystem','-iquote','-include','-imacros'):
            if i+1>=len(cc):raise ValueError('Incomplete include flag')
            (forced_headers if t in ('-include','-imacros') else include_dirs).append(graph_path(cc[i+1]))
        elif t.startswith('-I') and len(t)>2:include_dirs.append(graph_path(t[2:]))
    desired=set(q['paths_requiring_readonly_host_hash_receipts'])|set(reads)|set(strip_depfile_tools)|{STATIC,LINK,STRIP,GRAPH}
    pending_hashes=sorted(desired-set(tool_receipts)-{SOURCE})
    writes=[dict(role='manager_compile',paths=[STATIC,STATIC+'.d']),dict(role='libart_link',paths=[LINK,LINK+'.rsp']),dict(role='libart_strip',paths=[STRIP,STRIP+'.tmp',STRIP+'.d'])]
    return dict(status='actual_commands_and_pinned_strip_source_reviewed_private_dryrun_pending',commands_sha256=sha(root/'commands.stdout'),strip_script_sha256=STRIP_SCRIPT,response_sha256=sha(root/'libart.so.rsp'),query_review_sha256=sha(query),
        command_environment=[ce,le,se],canonical_command_argv=[cc,ld,strip],response_object_count=len(rsp),explicit_output_and_wrapper_write_paths=writes,ninja_rule_assignments=assignments,rules_export_sha256=sha(root/'rules.json'),ninja_rsp_and_depfile_bindings_reviewed=True,
        direct_tool_receipts=tool_receipts,toolchain_export_sha256=sha(root/'toolchain.json'),direct_tool_receipt_count=10,tool_file_contents_rehashed_here=False,
        pending_readonly_host_file_hash_paths=pending_hashes,compile_include_search_directories=sorted(set(include_dirs)),compile_forced_header_paths=sorted(set(forced_headers)),
        newly_explicit_candidate_headers=['/build/aosp/art/runtime/gc/heap.h','/build/aosp/art/runtime/oat.h'],
        selected_strip_branch='keep_symbols_and_debug_frame then add_gnu_debuglink then final mv and depfile',
        strip_tools_on_selected_branch=strip_tools,strip_depfile_named_tools=strip_depfile_tools,link_driver_tool_resolution_to_verify=driver_tools,additional_command_read_paths_not_query_inputs=sorted(set(reads)-graph_inputs),additional_receipt_paths_including_depfile_tools=sorted((set(reads)|set(strip_depfile_tools))-graph_inputs),
        unused_strip_branch_outputs=['.symbolList','.dynsyms','.funcsyms','.keep_symbols','.debug','.mini_debuginfo','.mini_debuginfo.xz','.tmp.no-build-id'],
        lto=dict(mode='thin',split_lto_unit=True,manager_object_may_be_bitcode=True,explicit_thinlto_cache_flag_present=False,source_helper_does_not_bound_linked_code_changes=True),
        missing_review=['Compiler included-header dependency receipts, including cached Ninja discovered deps rather than only query graph inputs; include newly explicit gc/heap.h and oat.h closure.','Direct10 tool receipts are present, but clang++ regular file may be a wrapper. Export bin/clang*/.real resolution metadata and ELF interpreter/NEEDED records; do not assume complete compiler/runtime closure.','Hashes for pending input list and actual tool dynamic loader/libraries; shell/helper tools bound to verified builder image.','Complete cache before/copy inventories and private Ninja bookkeeping.','Private dry-run action/output/rsp/dep/temp closure; force TMPDIR into private stage and keep shared root/container root read-only.','Actual target build, normalized full libart code/relocation/ABI audit and runtime trials.'],
        ready_for_launch=False,copy_reviewed=False,dry_run_reviewed=False,abi_proven=False,
        analyzer_sha256=sha(Path(__file__)),
        limits=['This executes no compiler/script/host/device call. Write paths derive from actual exported command flags and one exact manually inspected strip.sh source branch, not observed filesystem operations.','GNU debuglink reads unstripped input and updates outfile.tmp in place; it does not create a separate debug file on this branch. Depfile lists extra tools that need not execute on the selected branch.','Ninja generates/cleans link rsp as bound by actual rule metadata. Absence of an explicit cache flag is not proof of all LLVM internal temporary-write behavior.','Query .so.toc dependencies are not the actual .so files consumed by linker. Additional read list closes that normalization gap but still needs host hashes.','ThinLTO can change other linked functions; no one-helper-only binary-body claim is permitted.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('capture','query-review','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=analyze(a.capture,a.query_review)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(response_objects=r['response_object_count'],writes=r['explicit_output_and_wrapper_write_paths'],extra_read_receipts=len(r['additional_command_read_paths_not_query_inputs']),ready_for_launch=False),indent=2))

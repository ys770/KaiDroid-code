"""Strict structural/body gate for a two-scope candidate against installed lazy-WiFi SystemUI.

Reject unfamiliar optimizer changes for manual review. Signing, class/field
metadata, runtime behavior, startup latency and memory require separate checks.
"""
import argparse
import hashlib
import gzip
import json
import re
from pathlib import Path
from verify_lazy_wifi_apk import inspect
from compare_dexdump_methods import methods,fold_service_loader_names

BASELINE='f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'
OWNER='Lcom/android/systemui/bubbles/BubbleDataRepository;'
SCOPE='Lkotlinx/coroutines/CoroutineScope;'
LAMBDAS={OWNER[:-1]+'$'+kind+'Scope$2;' for kind in ('io','ui')}


def class_metadata(dump):
    result={};owner=None;mode=None;field=None
    def finish():
        nonlocal field
        if field is None:return
        if not {'name','type','access','kind'}<=field.keys():raise ValueError('Incomplete field metadata')
        name=field.pop('name')
        if name in result[owner]['fields']:raise ValueError('Duplicate field name')
        result[owner]['fields'][name]=field;field=None
    with gzip.open(dump,'rt',encoding='latin1',newline='') as stream:
        for line in stream:
            line=line.rstrip('\r\n')
            match=re.match(r"\s+Class descriptor\s+: '([^']+)'$",line)
            if match:
                finish();owner=match[1];mode=None
                if owner in result:raise ValueError('Duplicate class metadata')
                result[owner]=dict(fields={},interfaces=[]);continue
            if owner is None:continue
            match=re.match(r'\s+Access flags\s+: (0x[0-9a-f]+)',line)
            if match:result[owner]['access']=int(match[1],16);continue
            match=re.match(r"\s+Superclass\s+: '([^']*)'",line)
            if match:result[owner]['superclass']=match[1];continue
            match=re.match(r'  (Interfaces|Static fields|Instance fields|Direct methods|Virtual methods)\s+-',line)
            if match:finish();mode=match[1];continue
            if mode=='Interfaces':
                match=re.match(r"\s+#\d+\s+: '([^']+)'",line)
                if match:result[owner]['interfaces'].append(match[1])
            if mode not in ('Static fields','Instance fields'):continue
            if re.match(r'\s+#\d+\s+: \(in ',line):
                finish();field=dict(kind='static' if mode=='Static fields' else 'instance');continue
            if field is None:continue
            match=re.match(r"\s+(name|type)\s+: '(.*)'$",line)
            if match:field[match[1]]=match[2];continue
            match=re.match(r'\s+access\s+: (0x[0-9a-f]+)',line)
            if match:field['access']=int(match[1],16);continue
            match=re.match(r'\s+value\s+: (.*)',line)
            if match:field['value']=match[1]
    finish()
    if any(not {'access','superclass'}<=row.keys() for row in result.values()):raise ValueError('Incomplete class metadata')
    return result


def verify(original,candidate,before_dump,before_dex,after_dump,after_dex,manual=False):
    if hashlib.sha256(original.read_bytes()).hexdigest()!=BASELINE:raise ValueError('Unexpected installed baseline')
    old_classes,old_methods,old_entries,old_dex=inspect(original)
    new_classes,new_methods,new_entries,new_dex=inspect(candidate)
    if old_entries!=new_entries:raise ValueError('Non-code payload/compression changed')
    if old_classes-new_classes or new_classes-old_classes!=(set() if manual else LAMBDAS):
        raise ValueError('Unexpected class changes; inspect optimizer output before proceeding')
    if old_methods-new_methods:raise ValueError('Existing concrete methods removed')
    getters={(OWNER,'getIoScope','()'+SCOPE),(OWNER,'getUiScope','()'+SCOPE)}
    added=new_methods-old_methods
    if not getters<=added or any(key not in getters and (manual or key[0] not in LAMBDAS) for key in added):
        raise ValueError('Unexpected added concrete methods')
    for dex_rows,path in ((old_dex,before_dex),(new_dex,after_dex)):
        if len(dex_rows)!=1 or hashlib.sha256(path.read_bytes()).hexdigest()!=dex_rows[0]['sha256']:
            raise ValueError('Supplied DEX differs from APK')
    before=methods(before_dump,before_dex);after=methods(after_dump,after_dex)
    if set(before)!=old_methods or set(after)!=new_methods:raise ValueError('Dump method coverage differs from APK')
    folded,renames=fold_service_loader_names(before,after)
    changed=[key for key in before if before[key]!=folded[key]]
    allowed={'<init>','persistToDisk','loadBubbles','access$getUiScope$p'}
    if any(key[0]!=OWNER or key[1] not in allowed for key in changed):
        raise ValueError('Unrelated existing body changes; require explicit review')
    constructors=[key for key in after if key[0]==OWNER and key[1]=='<init>']
    if len(constructors)!=1:raise ValueError('Unexpected repository constructor set')
    constructor=after[constructors[0]]['instructions']
    if any('Lkotlinx/coroutines/Dispatchers;.' in instruction or 'Lkotlinx/coroutines/CoroutineScopeKt;.CoroutineScope:' in instruction for instruction in constructor):
        raise ValueError('Repository constructor still eagerly initializes dispatchers/scopes')
    if manual:
        if any('Lkotlin/Lazy' in instruction or 'Lkotlin/jvm/internal/Reflection;' in instruction for instruction in constructor):
            raise ValueError('Manual constructor adds lazy/reflection initialization')
    elif sum('Lkotlin/LazyKt;.lazy:' in instruction for instruction in constructor)!=2:
        raise ValueError('Expected two default synchronized lazy initializers')
    for getter in getters:
        instructions=after[getter]['instructions']
        if not manual and sum('Lkotlin/Lazy;.getValue:' in instruction for instruction in instructions)!=1:
            raise ValueError('Scope getter is not a single lazy-value access')
        if manual:
            access=int(after[getter]['access'],16)
            if not access&2 or not access&(0x20|0x20000):raise ValueError('Manual getter is not private/declared synchronized')
            if not any(i.startswith('monitor-enter ') for i in instructions) or not any(i.startswith('monitor-exit ') for i in instructions):
                raise ValueError('Missing explicit DEX getter monitor')
            field=OWNER+'.'+('ioScopeValue' if getter[1]=='getIoScope' else 'uiScopeValue')+':'+SCOPE
            if sum(i.startswith('iget-object ') and field in i for i in instructions)!=1 or sum(i.startswith('iput-object ') and field in i for i in instructions)!=1:
                raise ValueError('Getter no longer reads/stores exactly one cached scope')
    factories=[]
    for kind,dispatcher in [('io','getIO'),('ui','getMain')]:
        owner=OWNER if manual else OWNER[:-1]+'$'+kind+'Scope$2;'
        key=(owner,'getIoScope' if kind=='io' else 'getUiScope','()'+SCOPE) if manual else (owner,'invoke','()'+SCOPE)
        if key not in after:raise ValueError('Expected typed lazy scope factory')
        calls=[i for i in after[key]['instructions'] if i.startswith('invoke-')]
        if len(calls)!=2 or 'Lkotlinx/coroutines/Dispatchers;.'+dispatcher+':' not in calls[0] or 'Lkotlinx/coroutines/CoroutineScopeKt;.CoroutineScope:' not in calls[1]:
            raise ValueError('Lazy factory changes dispatcher or scope creation')
        factories.append(dict(method=key,body=after[key]))
    metadata_changes=[]
    if manual:
        old_meta=class_metadata(before_dump);new_meta=class_metadata(after_dump)
        if old_meta.keys()!=old_classes or new_meta.keys()!=new_classes:raise ValueError('Class metadata coverage differs')
        for owner in old_meta:
            if old_meta[owner]==new_meta[owner]:continue
            if owner!=OWNER:raise ValueError('Unrelated class/field metadata changed')
            expected=dict(old_meta[owner]);expected['fields']=dict(expected['fields'])
            for kind in ('io','ui'):
                removed=expected['fields'].pop(kind+'Scope',None)
                if removed!=dict(kind='instance',type=SCOPE,access=0x12):raise ValueError('Unexpected old scope field')
                expected['fields'][kind+'ScopeValue']=dict(kind='instance',type=SCOPE,access=2)
            if expected!=new_meta[owner]:raise ValueError('Unexpected repository class/field metadata')
            metadata_changes.append(dict(owner=owner,before=old_meta[owner],after=new_meta[owner]))
        if len(metadata_changes)!=1:raise ValueError('Expected exactly the scope cache field changes')
    return dict(baseline_sha256=BASELINE,candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
                initialization_mode='explicit synchronized cached getters' if manual else 'Kotlin lazy delegates',
                retained_class_count=len(old_classes),added_classes=sorted(new_classes-old_classes),
                retained_concrete_methods=len(old_methods),added_concrete_methods=sorted(added),
                changed_existing_methods=[dict(method=key,before=before[key],after=after[key]) for key in changed],
                service_loader_body_bijection=renames,constructor_body=after[constructors[0]],
                getter_bodies=[dict(method=key,body=after[key]) for key in sorted(getters)],lazy_factories=factories,
                added_method_bodies=[dict(method=key,body=after[key]) for key in sorted(added)],
                class_and_field_metadata_changes=metadata_changes,
                noncode_entries_preserved=len(old_entries),
                inputs={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (before_dump,before_dex,after_dump,after_dex)},
                scope='Structural/decoded method-body gate; manual mode also compares class access/hierarchy/interfaces and fields/static values. Debug metadata/annotations, signing, lifecycle and measured behavior remain separate; no runtime or savings claim.',
                runtime_verified=False,savings_measured=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('original','candidate','before-dump','before-dex','after-dump','after-dex','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--manual',action='store_true')
    args=parser.parse_args()
    report=verify(args.original,args.candidate,args.before_dump,args.before_dex,args.after_dump,args.after_dex,args.manual)
    with args.output.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('candidate_sha256','retained_class_count','retained_concrete_methods','noncode_entries_preserved')}))

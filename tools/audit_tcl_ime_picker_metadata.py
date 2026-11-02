"""Complement the native picker method audit with declared classes/fields/access."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import struct
import zipfile
from audit_tcl_target_api import parse
from audit_tcl_ime_picker_dex import BASE, OWNER, PICKER, ALERT, CALLBACKS
from audit_resolver_title_dex import sha

FRAMEWORK='efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb'
SOURCE='027507c72249681c2eabd5b4fb47a65e613dfb62a81a9c3ecf84e91d1998077b'
METHOD_AUDIT='98d7a5584371f16f1d8c4882ce771afe7a7a3a3a1943a0ee28f2dbd03066743b'


def canonical(value):
    import hashlib
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def metadata(path):
    result={}
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not re.fullmatch(r'classes\d*\.dex',name):continue
            data=archive.read(name);classes,methods,fields,_=parse(data)
            def u32(p):return struct.unpack_from('<I',data,p)[0]
            def uleb(p):
                value=0
                for shift in range(0,35,7):
                    byte=data[p];p+=1;value|=(byte&127)<<shift
                    if not byte&128:return value,p
                raise ValueError('Bad member data')
            for i,(owner,row) in enumerate(classes.items()):
                if owner in result:raise ValueError('Duplicate target class')
                pos=u32(100)+32*i
                entry=dict(superclass=row['superclass'],interfaces=row['interfaces'],
                    access=u32(pos+4),fields={},methods={})
                cursor=u32(pos+24)
                if cursor:
                    counts=[]
                    for _ in range(4):n,cursor=uleb(cursor);counts.append(n)
                    for section,count in enumerate(counts):
                        index=0
                        for _ in range(count):
                            delta,cursor=uleb(cursor);index+=delta
                            flags,cursor=uleb(cursor)
                            table=fields if section<2 else methods
                            actual,member,descriptor=table[index]
                            if actual!=owner:raise ValueError('Member owner mismatch')
                            entry['fields' if section<2 else 'methods'][(member,descriptor)]=(flags,section)
                            if section>=2:_,cursor=uleb(cursor)
                result[owner]=entry
    return result


def compare(before,after,audit):
    removed=set(before)-set(after);added=set(after)-set(before)
    expected_removed=set(audit['old_picker_wrapper_classes'])
    expected_added={row[0] for row in audit['added']}-set(before)
    owner=deepcopy(before[OWNER])
    field=owner['fields'].pop(('picker',ALERT))
    owner['fields'][('picker',PICKER)]=field
    for old,new in CALLBACKS.items():
        owner['methods'][new[1:]]=owner['methods'].pop(old[1:])
    unrelated=[name for name in before.keys()&after.keys() if name!=OWNER and before[name]!=after[name]]
    expected_fields={('list','Landroid/widget/ListView;'):(0x12,1),
        ('footer','Landroid/widget/MenuBar;'):(0x12,1),
        ('selected','Ljava/util/function/IntConsumer;'):(0x12,1),('digits','[Z'):(0x12,1),
        ('selection','I'):(0x2,1),('dispatched','Z'):(0x2,1)}
    helper=after.get(PICKER,{})
    helper_ok=(helper.get('fields')==expected_fields and helper.get('superclass')=='Landroid/app/Dialog;'
               and helper.get('interfaces')==[] and helper.get('access')==0x10)
    passed=(removed==expected_removed and added==expected_added and after.get(OWNER)==owner
            and not unrelated and helper_ok)
    return dict(before_classes=len(before),after_classes=len(after),added_classes=sorted(added),removed_classes=sorted(removed),
        unrelated_changed_classes=sorted(unrelated),controller_only_picker_field_and_three_callback_signatures=after.get(OWNER)==owner,
        new_helper_six_source_fields_access_superclass_match=helper_ok,expected_metadata_delta_only=passed,
        scope='Declared classes/superclasses/interfaces/access, field types/access/kind, all declared methods including native/abstract/access/kind',
        exclusions=['Annotations','Debug/source metadata','Runtime behavior'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['baseline','candidate','source','method-audit','output']:p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    if sha(args.baseline)!=BASE or sha(args.candidate)!=FRAMEWORK or sha(args.source)!=SOURCE:
        raise ValueError('Unreviewed framework/source bytes')
    audit=json.loads(args.method_audit.read_text(encoding='utf-8'))
    if canonical(audit)!=METHOD_AUDIT or not audit.get('expected_picker_delta_only'):
        raise ValueError('Unreviewed compiled method proof')
    report=compare(metadata(args.baseline),metadata(args.candidate),audit)
    report.update(baseline_sha256=BASE,candidate_sha256=FRAMEWORK,source_sha256=SOURCE,
                  method_audit_canonical_sha256=METHOD_AUDIT,native_runtime_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))
    if not report['expected_metadata_delta_only']:raise ValueError('Unexpected field/class metadata delta')


if __name__=='__main__':main()

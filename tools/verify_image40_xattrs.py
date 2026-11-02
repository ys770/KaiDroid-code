"""Compare all raw ext4 xattrs between exact image39/40, including SELinux labels."""
import argparse
import hashlib
import json
import stat
from collections import Counter
from pathlib import Path
from dissect.extfs import ExtFS

BASE='c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b'
NEW='82ce8d6041effb571108704c2c51f6d039eabaeaf02cedb3a2e05dd7ae33c604'


def inventory(path):
    rows={};counts=Counter()
    with path.open('rb') as stream:
        fs=ExtFS(stream)
        def visit(node,name):
            attrs={}
            for attr in node.xattr:
                if attr.name in attrs:raise ValueError('Duplicate xattr: '+name)
                attrs[attr.name]=attr.value.hex();counts[attr.name]+=1
            rows[name]=attrs
            if node.filetype==stat.S_IFDIR:
                for child in node.iterdir():
                    if child.filename not in ('.','..'):
                        visit(child,name.rstrip('/')+'/'+child.filename)
        visit(fs.get('/'),'/')
    return rows,counts


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    for path,expected in ((a.baseline,BASE),(a.candidate,NEW)):
        if path.stat().st_size!=834666496:raise ValueError('Wrong image size')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=expected:raise ValueError('Wrong image digest')
    before,bc=inventory(a.baseline);after,ac=inventory(a.candidate)
    if before.keys()!=after.keys():raise ValueError('Filesystem path set changed')
    changed=[name for name in before if before[name]!=after[name]]
    if changed:raise ValueError('Extended attributes changed: '+repr(changed))
    critical={}
    for name in ('/system/system_ext/priv-app/SystemUI/SystemUI.apk','/system/build.prop',
                 '/system/bin/init','/system/priv-app/TelephonyProvider/TelephonyProvider.apk'):
        attrs=after[name]
        if 'security.selinux' not in attrs:raise ValueError('Missing critical SELinux label: '+name)
        critical[name]=bytes.fromhex(attrs['security.selinux']).rstrip(b'\0').decode('ascii')
    result=dict(baseline_sha256=BASE,candidate_sha256=NEW,filesystem_entries=len(before),
        compared_xattrs=sum(ac.values()),counts_by_name=dict(ac),all_extended_attributes_identical=True,
        critical_selinux_labels=critical,installed=False,
        scope='Exact decoded xattr name/value equality for every filesystem entry. Does not verify kernel enforcement, runtime labeling, boot or functionality.')
    with a.output.open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()

"""Verify exact retained APKs for hardware-owned persistent Contacts delivery."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

FILES = [
    ('contacts', 'work/contacts-dialog-width01/signed/FPContacts.apk', '20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248'),
    ('controller', 'work/permission-controller-build02/PermissionController.apk', '3da34d2d40ba964502ad680d8e63d2e51f3f90f670692a5cbf32992a8e8b2655'),
    ('contacts_original', 'artifacts/runtime/tcl-contacts-preflight01/Contacts.original.apk', '7cc2c14fe371adf7c98900ffda85fbfc274b8cb8da7e33fc4d0bf79d8a746e0d'),
    ('controller_original', 'artifacts/runtime/permission-controller-preflight01/PermissionController.original.apk', 'b94c069e92ff1ccfdf80c15f25b4155d8647d520f8a47834f71dedff2bfdfb30')]


def verify(root):
    results=[]
    for name, relative, expected in FILES:
        path=root/relative
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Hash mismatch: '+name)
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None:raise ValueError('ZIP CRC failure: '+name)
            info=z.getinfo('resources.arsc')
            name_len, extra_len=struct.unpack_from('<HH',data,info.header_offset+26)
            offset=info.header_offset+30+name_len+extra_len
            if info.compress_type!=0 or offset%4:raise ValueError('Unaligned/compressed resources: '+name)
        results.append(dict(name=name,path=relative,sha256=expected,bytes=len(data),resource_data_offset=offset))
    return dict(files=results,local_payload_verification=True,device_commands_issued=False,
                image34_installed=False,image34_runtime_verified=False,
                historical_runtime='image33 width02 passed title visibility, sort cancel and full rollback',
                permission_policy='Normal permission UI only; do not reuse image33-bound helper on image34',
                delivery_policy='Hardware owner installs verified pair and retains it on successful acceptance; rollback only for observed failures or recovery needs',
                expected_packages={'contacts':{'package':'com.android.contacts','uid':10073,'version':122209261},'controller':{'package':'com.android.permissioncontroller','uid':10094,'version':300000000}},
                reference_states={'empty':'005-contacts','settings':'006-contacts-settings','sort':'007-contacts-sort'},
                reference_root='artifacts/tcl-ui-reference/20261026',reference_density=160)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    report=verify(a.root)
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report))

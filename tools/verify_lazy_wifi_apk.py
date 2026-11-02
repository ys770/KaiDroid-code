"""Check a standalone lazy-WifiTracker APK's scope; no runtime or savings claim."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from audit_dex_references import read_dex
from compress_apk_dex import is_signature

BASELINE = '203f2f316c48a354fc5ee2e0477da35b97b78604e63a2ae5e9ca9778719e5586'
OWNER = 'Lcom/android/systemui/statusbar/policy/AccessPointControllerImpl;'
GETTER = (OWNER, 'getWifiTracker', '()Lcom/android/settingslib/wifi/WifiTracker;')
DEX = re.compile(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex')
NETWORK = 'Lcom/android/systemui/statusbar/policy/NetworkController;'
BRIDGES = {(NETWORK,name,'(Ljava/lang/Object;)V') for name in ('addCallback','removeCallback')}


def verify_bridges(candidate, dexdump):
    if dexdump is None:
        raise ValueError('DEX disassembler required to verify compiler-generated bridges')
    with zipfile.ZipFile(candidate) as package, tempfile.TemporaryDirectory() as scratch:
        selected = []
        for name in package.namelist():
            if not DEX.fullmatch(name):
                continue
            data=package.read(name)
            _,classes,_,_=read_dex(data,definitions_only=True)
            if NETWORK in classes:
                selected.append(data)
        if len(selected)!=1:
            raise ValueError('Expected one NetworkController definition')
        path=Path(scratch)/'classes.dex'
        path.write_bytes(selected[0])
        result=subprocess.run([str(dexdump),'-d',str(path)],check=True,capture_output=True,
                              timeout=120)
    # DEX string constants elsewhere may contain non-UTF8/MUTF8 bytes in this
    # tool's textual output. The selected class and instruction checks are ASCII.
    dump=result.stdout.decode('utf-8',errors='replace')
    marker="Class descriptor  : '"+NETWORK+"'"
    if dump.count(marker)!=1:
        raise ValueError('Ambiguous NetworkController disassembly')
    block=dump.split(marker,1)[1].split('\nClass #',1)[0]
    checks=[]
    for name in ('addCallback','removeCallback'):
        methods=[m for m in re.split(r'(?m)^    #\d+',block)
                 if re.search(r"name\s+: '"+name+"'",m)
                 and "'(Ljava/lang/Object;)V'" in m]
        if len(methods)!=1 or 'access        : 0x1041 (PUBLIC BRIDGE SYNTHETIC)' not in methods[0]:
            raise ValueError('Expected one public synthetic bridge: '+name)
        instructions=[line.split(' // ',1)[0].strip() for line in
                      re.findall(r'\|[0-9a-f]+: (.+)',methods[0])]
        expected=['check-cast v1, '+NETWORK[:-1]+'$SignalCallback;',
                  'invoke-interface {v0, v1}, '+NETWORK+'.'+name+':('
                  +NETWORK[:-1]+'$SignalCallback;)V','return-void']
        if instructions!=expected or 'catches       : (none)' not in methods[0]:
            raise ValueError('Unexpected compiler bridge body: '+name)
        checks.append(dict(method=name,access_flags='0x1041',instructions=instructions))
    return checks


def inspect(path):
    classes, methods, entries, dex = set(), set(), {}, []
    with zipfile.ZipFile(path) as package:
        if len(package.namelist()) != len(set(package.namelist())):
            raise ValueError('Duplicate APK entries')
        for info in package.infolist():
            if info.is_dir() or is_signature(info.filename):
                continue
            data = package.read(info.filename)
            if DEX.fullmatch(info.filename):
                _, defined, concrete, _ = read_dex(data, definitions_only=True)
                if classes & defined:
                    raise ValueError('Duplicate class definitions across DEX files')
                classes.update(defined)
                methods.update(concrete)
                dex.append(dict(name=info.filename,sha256=hashlib.sha256(data).hexdigest()))
            else:
                entries[info.filename] = dict(sha256=hashlib.sha256(data).hexdigest(),
                                              compression=info.compress_type)
    if not dex:
        raise ValueError('No valid DEX')
    return classes, methods, entries, dex


def verify(original, candidate, dexdump=None):
    if hashlib.sha256(original.read_bytes()).hexdigest() != BASELINE:
        raise ValueError('Unexpected baseline APK')
    before, old_methods, old_entries, old_dex = inspect(original)
    after, new_methods, new_entries, new_dex = inspect(candidate)
    if before != after:
        raise ValueError('Class definition set changed')
    if old_entries != new_entries:
        raise ValueError('Non-code payload or compression changed')
    if GETTER in old_methods or GETTER not in new_methods:
        raise ValueError('Expected a new concrete lazy tracker accessor')
    added = new_methods-old_methods
    if old_methods - new_methods or added not in ({GETTER},{GETTER}|BRIDGES):
        raise ValueError('Unexpected concrete method additions/removals')
    bridges=verify_bridges(candidate,dexdump) if added & BRIDGES else []
    return dict(baseline_sha256=BASELINE,
        candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
        class_count=len(before),concrete_methods_preserved=len(old_methods),
        added_concrete_methods=sorted(added),compiler_generated_bridge_checks=bridges,
        noncode_entries_preserved=len(old_entries),
        baseline_dex=old_dex,candidate_dex=new_dex,
        scope='Structural code/payload scope check. Existing method bodies, signing identity, lifecycle behavior, latency and physical memory require separate verification.',
        runtime_verified=False,savings_measured=False)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','candidate','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dexdump',type=Path)
    a=p.parse_args()
    report=verify(a.original,a.candidate,a.dexdump)
    with a.output.open('x') as output:
        output.write(json.dumps(report,indent=2)+'\n')

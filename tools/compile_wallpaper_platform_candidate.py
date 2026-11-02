"""Compile the held wallpaper sources locally against captured real platform jars."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from prepare_wallpaper_buffer_candidate import PINS, candidate

JARS={'framework.jar':'946330de780feb9b25f8b77e9a1f18a5490cc07f087ef0dda04fca9edaecd4ff',
      'SystemUI-core.jar':'53472958238398059955baf10d10ab568abee67b2ec9bc011cd3f9991020bbbb',
      'jsr330.jar':'6f0c09e1f5060dd329b9576b4611687861506c2973c9204105df4a9385658e39'}
EXPECTED={'com.android.systemui.ImageWallpaper','com.android.systemui.ImageWallpaper$GLEngine',
          'com.android.systemui.glwallpaper.ImageWallpaperRenderer',
          'com.android.systemui.glwallpaper.ImageWallpaperRenderer$1',
          'com.android.systemui.glwallpaper.ImageWallpaperRenderer$WallpaperTexture'}


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def methods(text):
    rows={};current=None
    for line in text.splitlines():
        if re.match(r'^  \S.*\);$',line) or line=='  static {};':
            current=line.strip();rows[current]=[]
        elif current is not None:
            if line=='}': current=None
            elif line.strip():
                code,separator,comment=line.strip().partition('//')
                rows[current].append(re.sub(r'#\d+','#REF',code)+(separator+comment if separator else ''))
    return rows


def canonical_encoding(lines):
    """Accept only straight instruction listings; preserve resolved operands/branch graph."""
    instructions=[];descriptor=[]
    for line in lines:
        if line.startswith('descriptor:'): descriptor.append(line);continue
        if line=='Code:':continue
        match=re.fullmatch(r'(\d+):\s+(\w+)(?:\s+(.*))?',line)
        if not match: raise ValueError('Unsupported encoding-only listing: '+line)
        instructions.append((int(match[1]),match[2],match[3] or ''))
    offsets={offset:index for index,(offset,_,_) in enumerate(instructions)}
    if len(offsets)!=len(instructions): raise ValueError('Duplicate instruction offset')
    result=list(descriptor)
    for _,opcode,operands in instructions:
        if opcode=='ldc_w': opcode='ldc'
        if opcode.startswith('if') or opcode in ['goto','goto_w','jsr','jsr_w']:
            if not operands.isdecimal() or int(operands) not in offsets: raise ValueError('Unresolved branch target')
            operands='instruction:'+str(offsets[int(operands)])
        before,separator,comment=operands.partition('//')
        # Constant-pool operand numbers were normalized by methods(); resolved comments remain exact.
        result.append((opcode,' '.join(before.split()),comment if separator else ''))
    return result


def compile_pair(source_root,candidate_root,jars,output):
    output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((jars/'manifest.json').read_text())
    if {r['name']:r['sha256'] for r in manifest['files']}!=JARS: raise ValueError('Unexpected jar capture')
    for name,pin in JARS.items():
        if sha(jars/name)!=pin: raise ValueError('Platform jar changed')
    for name,pin in PINS.items():
        if sha(source_root/name)!=pin or (candidate_root/name).read_bytes().decode()!=candidate(name,(source_root/name).read_bytes().decode()):
            raise ValueError('Source candidate changed')
    reports=[];apis={};bodies={}
    for label,root in [('baseline',source_root),('candidate',candidate_root)]:
        classes=output/label;classes.mkdir()
        command=['javac','-source','8','-target','8','-proc:none','-implicit:none',
                 '-classpath',os.pathsep.join(str((jars/name).resolve()) for name in JARS),
                 '-d',str(classes),*[str(root/name) for name in PINS]]
        result=subprocess.run(command,capture_output=True,text=True)
        (output/(label+'.stdout')).write_text(result.stdout)
        (output/(label+'.stderr')).write_text(result.stderr)
        if result.returncode: raise RuntimeError(result.stderr)
        files=sorted(classes.rglob('*.class'))
        names={p.relative_to(classes).as_posix()[:-6].replace('/','.') for p in files}
        if names!=EXPECTED: raise ValueError('Unexpected compiled class closure')
        apis[label]={};bodies[label]={}
        for name in sorted(names):
            signature=subprocess.run(['javap','-p','-s','-classpath',str(classes),name],capture_output=True,text=True,check=True)
            disasm=subprocess.run(['javap','-p','-c','-s','-classpath',str(classes),name],capture_output=True,text=True,check=True)
            (output/(label+'-'+name+'.javap')).write_text(disasm.stdout)
            apis[label][name]=[line.strip() for line in signature.stdout.splitlines() if line.startswith('  ') and line.endswith(';')]
            bodies[label][name]=methods(disasm.stdout)
        reports.append(dict(label=label,command=command,exit=result.returncode,stderr=result.stderr,
                            classes=[dict(path=p.relative_to(classes).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in files]))
    for name in EXPECTED:
        expected=apis['baseline'][name]
        if name.endswith('.ImageWallpaperRenderer'):
            expected=expected+['private int mViewportWidth;','private int mViewportHeight;']
        if sorted(expected)!=sorted(apis['candidate'][name]): raise ValueError('Unexpected member signature delta: '+name)
        if bodies['baseline'][name].keys()!=bodies['candidate'][name].keys(): raise ValueError('Unexpected method closure: '+name)
    marker=Path('com/android/systemui/glwallpaper/ImageWallpaperRenderer$1.class')
    if (output/'baseline'/marker).read_bytes()!=(output/'candidate'/marker).read_bytes():
        raise ValueError('Existing empty synthetic constructor marker changed')
    raw_changed=[dict(class_name=name,method=method) for name in sorted(EXPECTED) for method in bodies['baseline'][name]
                 if bodies['baseline'][name][method]!=bodies['candidate'][name][method]]
    changed=[];encoding_only=[]
    for row in raw_changed:
        name,method=row['class_name'],row['method']
        if canonical_encoding(bodies['baseline'][name][method])==canonical_encoding(bodies['candidate'][name][method]): encoding_only.append(row)
        else: changed.append(row)
    expected_changes=[dict(class_name='com.android.systemui.ImageWallpaper$GLEngine',method='private void updateSurfaceSize();'),
                      dict(class_name='com.android.systemui.glwallpaper.ImageWallpaperRenderer',method='public void onSurfaceChanged(int, int);'),
                      dict(class_name='com.android.systemui.glwallpaper.ImageWallpaperRenderer',method='public void onDrawFrame();')]
    if sorted(changed,key=str)!=sorted(expected_changes,key=str): raise ValueError('Unexpected bytecode method delta: '+repr(changed))
    report=dict(jar_capture=manifest,javac_version=subprocess.run(['javac','-version'],capture_output=True,text=True,check=True).stdout.strip(),
                runs=reports,member_scope_pass=True,raw_changed_methods=raw_changed,
                encoding_only_changed_methods=encoding_only,changed_existing_methods=changed,
                source_hashes=[dict(path=name,original_sha256=sha(source_root/name),candidate_sha256=sha(candidate_root/name)) for name in PINS],
                limits=['Local Java8-source/target javac against copied real framework/SystemUI/JSR330 jars; Java runtime bootstrap classes come from host JDK.',
                        'Original/candidate five-class closure and member declarations checked; existing empty Java8 synthetic constructor marker is byte-identical.',
                        f'{len(raw_changed)} raw method differences reduce to {len(changed)} intended changes; {len(encoding_only)} prove equivalent after ldc/ldc_w and instruction-index branch-target normalization.',
                        'Comparison excludes debug/annotations/classfile metadata and is not DEX/R8/APK/signing/Soong integration, target execution, image installation or measured saving.',
                        'Captured shared jars are baseline build inputs, not a claim they equal the newest isolated image46 framework artifacts.',
                        'No host AOSP/output change, shared build launch or phone command.'])
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ['source-root','candidate-root','jars','output']: parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    report=compile_pair(args.source_root,args.candidate_root,args.jars,args.output)
    print(json.dumps(dict(member_scope_pass=report['member_scope_pass'],changed_existing_methods=report['changed_existing_methods'],javac_version=report['javac_version']),indent=2))

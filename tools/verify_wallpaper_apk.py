"""Fail-closed full SystemUI class/field/body scope gate for the held wallpaper patch.

No candidate has passed until this runs against a real built APK. Signing,
zip alignment, target runtime, visual behavior and physical savings stay separate.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from compare_dexdump_methods import methods,fold_service_loader_names
from verify_lazy_bubbles_apk import class_metadata
from verify_lazy_wifi_apk import inspect
from audit_dex_references import read_dex

BASELINE='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
ENGINE='Lcom/android/systemui/ImageWallpaper$GLEngine;'
RENDERER='Lcom/android/systemui/glwallpaper/ImageWallpaperRenderer;'
EXPECTED={(ENGINE,'updateSurfaceSize','()V'),(RENDERER,'onSurfaceChanged','(II)V'),(RENDERER,'onDrawFrame','()V')}
FIELDS={'mViewportWidth':dict(kind='instance',type='I',access=2),
        'mViewportHeight':dict(kind='instance',type='I',access=2)}


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def load(apk,folder):
    manifest=json.loads((folder/'manifest.json').read_text())
    if not manifest.get('complete') or manifest.get('returncode')!=0 or manifest['apk_sha256']!=sha(apk):
        raise ValueError('Incomplete/mismatched disassembly capture')
    for name in ['classes.dex','classes.dump.gz','dexdump.stderr']:
        if sha(folder/name)!=manifest['files'][name]: raise ValueError('Disassembly raw hash mismatch')
    classes,defined,entries,dex=inspect(apk)
    if len(dex)!=1 or dex[0]['sha256']!=sha(folder/'classes.dex'): raise ValueError('DEX differs from APK')
    bodies=methods(folder/'classes.dump.gz',folder/'classes.dex')
    metadata=class_metadata(folder/'classes.dump.gz')
    declarations={}
    read_dex((folder/'classes.dex').read_bytes(),definitions_only=True,declarations=declarations)
    if set(bodies)!=defined or set(metadata)!=classes: raise ValueError('Disassembly definition coverage mismatch')
    return dict(manifest=manifest,classes=classes,defined=defined,entries=entries,bodies=bodies,metadata=metadata,declarations=declarations)


def model_scope(before,after):
    """Pure scope comparison also used by clearly labeled synthetic guard controls."""
    if before['classes']!=after['classes'] or before['defined']!=after['defined']:
        raise ValueError('Class/concrete method set changed')
    if before['entries']!=after['entries']: raise ValueError('Non-code payload/compression changed')
    if before['declarations']!=after['declarations']:
        raise ValueError('Encoded method declaration/kind/access/code-presence changed')
    if not EXPECTED.issubset(before['bodies']): raise ValueError('Expected three existing methods absent')
    old=before['metadata'];new=deepcopy(after['metadata'])
    if old.keys()!=new.keys(): raise ValueError('Class metadata set changed')
    for field,expected in FIELDS.items():
        if field in old[RENDERER]['fields'] or new[RENDERER]['fields'].pop(field,None)!=expected:
            raise ValueError('Expected exactly one new private integer field: '+field)
    if old!=new: raise ValueError('Unrelated class/field/access/interface/static value metadata changed')
    folded,renames=fold_service_loader_names(before['bodies'],after['bodies'])
    changed={key for key in before['bodies'] if before['bodies'][key]!=folded[key]}
    if changed!=EXPECTED: raise ValueError('Existing decoded method scope differs: '+repr(sorted(changed)))
    return folded,renames


def mechanism(bodies):
    size=bodies[(ENGINE,'updateSurfaceSize','()V')]['instructions']
    required=['Landroid/app/ActivityManager;.isLowRamDeviceStatic:()Z',
              'Landroid/view/Display;.getDisplayId:()I','Landroid/view/Display;.getSupportedModes:()[Landroid/view/Display$Mode;',
              'Landroid/view/Display$Mode;.getPhysicalWidth:()I','Landroid/view/Display$Mode;.getPhysicalHeight:()I',
              'Landroid/content/res/Resources;.getFloat:(I)F','Ljava/lang/Float;.compare:(FF)I',
              'Landroid/view/SurfaceHolder;.setFixedSize:(II)V']
    for target in required:
        if not any(isinstance(i,str) and i.startswith('invoke-') and i.endswith(', '+target) for i in size):
            raise ValueError('Expected sizing API absent: '+target)
    changed=bodies[(RENDERER,'onSurfaceChanged','(II)V')]['instructions']
    for name in FIELDS:
        if sum(isinstance(i,str) and i.startswith('iput ') and i.endswith(', '+RENDERER+'.'+name+':I') for i in changed)!=1:
            raise ValueError('Viewport field not written exactly once')
    draw=bodies[(RENDERER,'onDrawFrame','()V')]['instructions']
    expected=['Landroid/opengl/GLES20;.glClear:(I)V','Landroid/opengl/GLES20;.glViewport:(IIII)V',
              'Lcom/android/systemui/glwallpaper/ImageGLWallpaper;.useTexture:()V',
              'Lcom/android/systemui/glwallpaper/ImageGLWallpaper;.draw:()V']
    positions=[]
    for target in expected:
        found=[index for index,i in enumerate(draw) if isinstance(i,str) and i.startswith('invoke-') and i.endswith(', '+target)]
        if len(found)!=1: raise ValueError('Expected one ordered draw operation: '+target)
        positions.append(found[0])
    if positions!=sorted(positions): raise ValueError('Draw sequence changed')
    return dict(required_sizing_calls=required,ordered_draw_calls=expected,
                limit='Presence/order checks plus source/host controls are not a formal proof of every target branch or pixel equality.')


def verify(original,candidate,before_folder,after_folder):
    if sha(original)!=BASELINE: raise ValueError('Unexpected installed SystemUI baseline')
    if sha(candidate)==BASELINE: raise ValueError('Candidate APK is unchanged')
    before=load(original,before_folder);after=load(candidate,after_folder)
    if before['manifest']['dexdump_sha256']!=after['manifest']['dexdump_sha256']:
        raise ValueError('Disassembler binary differs between captures')
    folded,renames=model_scope(before,after)
    return dict(baseline_sha256=BASELINE,candidate_sha256=sha(candidate),retained_classes=len(before['classes']),
        retained_concrete_methods=len(before['defined']),noncode_payload_and_compression_entries_preserved=len(before['entries']),
        retained_all_method_declarations=len(before['declarations']),
        exactly_added_fields=FIELDS,service_loader_full_body_bijection=renames,
        changed_existing_methods=[dict(method=key,before=before['bodies'][key],after=folded[key]) for key in sorted(EXPECTED)],
        mechanism_checks=mechanism(folded),
        source_captures=[dict(path=str(folder),manifest_sha256=sha(folder/'manifest.json')) for folder in [before_folder,after_folder]],
        limits=['Full decoded instructions/register frames/catches/payloads and class/field metadata checked; annotations/debug metadata excluded.',
                'Signing/certificate/zipalign/version/UID/image closure and runtime/visual/memory results remain separate required gates.',
                'A pass establishes reviewed structural/body scope, not actual thread lifecycle, smoothness, RAM saving or80percent completion.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['original','candidate','before-folder','after-folder','output']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    report=verify(args.original,args.candidate,args.before_folder,args.after_folder)
    with args.output.open('x') as file:file.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ['candidate_sha256','retained_classes','retained_concrete_methods']},indent=2))

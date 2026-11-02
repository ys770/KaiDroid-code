"""Prepare an isolated two-source SystemUI candidate, retaining installed lazy Wi-Fi.

Run on Linux only after the hardware/UI owner assigns a build slot. Never launches
Docker or changes shared source/output trees. Reuses reviewed Wi-Fi build isolation.
"""
import argparse
import json
import shutil
import subprocess
from pathlib import Path
from prepare_lazy_wifi_build import prepare,sha

BUBBLES='frameworks/base/packages/SystemUI/src/com/android/systemui/bubbles/BubbleDataRepository.kt'
ORIGINAL='3f84f19dca7e4bb137634fed6b7393f50147ad04ee8ab4a92110e12cb7cb3ee9'
CANDIDATE='69eef3bee16372154975c29a22403ff327df47631cf5293f4343821c4d3bcb21'
MANUAL_CANDIDATE='1dabead7099acf7536275df2a81b7f753cd3f303da95195b9934e904e5acd51c'
PROGUARD='frameworks/base/packages/SystemUI/proguard.flags'
PROGUARD_ORIGINAL='b376baeed70297b70219eea0dff87e2797f52bc2d6591e8bb1a701e9dfea2a3e'
BRIDGE_RULE='''

# Preserve the erased interface bridges present in the installed SystemUI APK.
-keepclassmembers interface com.android.systemui.statusbar.policy.NetworkController {
    public void addCallback(java.lang.Object);
    public void removeCallback(java.lang.Object);
}
'''
WIFI='c3bea9e1ff44340757d19c3dda932e3c5dc3e407b8acf30bfff9dac220f4e6a5'
INSTALLED_APK='f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'


def stage_bubbles(root,candidate,wifi,stage,dependencies,manual=False):
    root=root.resolve(strict=True);stage=stage.absolute()
    expected=MANUAL_CANDIDATE if manual else CANDIDATE
    if sha(root/'aosp'/BUBBLES)!=ORIGINAL or sha(candidate)!=expected or sha(wifi)!=WIFI:
        raise ValueError('Source pins differ from reviewed two-source candidate')
    if manual and sha(root/'aosp'/PROGUARD)!=PROGUARD_ORIGINAL:
        raise ValueError('Optimizer baseline policy changed')
    for process in ('ninja','soong_build'):
        status=subprocess.run(['pgrep','-x',process],capture_output=True)
        if status.returncode!=1:raise ValueError('Build active or status ambiguous; stop before staging')
    prepare(root,wifi,stage,dependencies)
    # An interrupted wrapper must never leave the base launcher usable as-is.
    launcher=(stage/'launch.sh').read_text()
    marker='test ! -e "$stage/container-id"'
    if launcher.count(marker)!=1:raise ValueError('Unexpected base launcher guard')
    launcher=launcher.replace(marker,'test -f "$stage/bubbles-staging.complete"\n'+marker)
    (stage/'launch.sh').write_text(launcher)
    inputs=stage/'inputs'
    shutil.copy2(root/'aosp'/BUBBLES,inputs/'BubbleDataRepository.original.kt')
    shutil.copy2(candidate,inputs/'BubbleDataRepository.kt')
    manifest=json.loads((stage/'staging.json').read_text())
    manifest['additional_source']=dict(path=BUBBLES,original_sha256=ORIGINAL,candidate_sha256=expected)
    manifest['scope_initialization']='explicit synchronized getters' if manual else 'Kotlin lazy delegates'
    manifest['installed_comparison_apk_sha256']=INSTALLED_APK
    manifest['inputs'].update({name:sha(inputs/name) for name in ('BubbleDataRepository.original.kt','BubbleDataRepository.kt')})
    if manual:
        shutil.copy2(root/'aosp'/PROGUARD,inputs/'SystemUI.proguard.original.flags')
        (inputs/'SystemUI.proguard.flags').write_bytes((root/'aosp'/PROGUARD).read_bytes()+BRIDGE_RULE.encode())
        manifest['optimizer_policy']=dict(path=PROGUARD,original_sha256=PROGUARD_ORIGINAL,candidate_sha256=sha(inputs/'SystemUI.proguard.flags'))
        manifest['inputs'].update({name:sha(inputs/name) for name in ('SystemUI.proguard.original.flags','SystemUI.proguard.flags')})
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    build=(stage/'build.sh').read_text()
    marker="assert hashlib.sha256(Path('/build/aosp/"+manifest['source']+"').read_bytes()).hexdigest()==m['candidate_source_sha256']"
    if build.count(marker)!=1:raise ValueError('Unexpected base build validation')
    build=build.replace(marker,marker+"\nassert hashlib.sha256(Path('/build/aosp/"+BUBBLES+"').read_bytes()).hexdigest()==m['additional_source']['candidate_sha256']")
    if manual:
        build=build.replace(marker,marker+"\nassert hashlib.sha256(Path('/build/aosp/"+PROGUARD+"').read_bytes()).hexdigest()==m['optimizer_policy']['candidate_sha256']")
    (stage/'build.sh').write_text(build)
    launcher=(stage/'launch.sh').read_text();marker='  kaidroid-build:20261023 bash '
    if launcher.count(marker)!=1:raise ValueError('Unexpected base Docker launcher')
    launcher=launcher.replace(marker,'  -v "$stage/inputs/BubbleDataRepository.kt:/build/aosp/'+BUBBLES+':ro" \\\n'+marker)
    if manual:
        launcher=launcher.replace(marker,'  -v "$stage/inputs/SystemUI.proguard.flags:/build/aosp/'+PROGUARD+':ro" \\\n'+marker)
    (stage/'launch.sh').write_text(launcher)
    (stage/'bubbles-staging.complete').write_text(sha(stage/'staging.json')+'\n')
    print(json.dumps(manifest))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','candidate','wifi','stage','dependencies'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--manual',action='store_true')
    args=parser.parse_args();stage_bubbles(args.root,args.candidate,args.wifi,args.stage,args.dependencies,args.manual)

"""Inventory exact image47 PiP callers; static references do not prove execution."""
import argparse
import hashlib
import json
from pathlib import Path

from compare_dexdump_methods import methods

APK = '2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
PINS = {'classes.dex': 'b54589765a47fe59d58a9aefc2dcaa4ef7852b6050291addc7359b0bf7c3ea9f',
        'classes.dump.gz': '68642e6c76dafe53ee5a2e511915ccea7dba6fb4be36097e1790bd52c2d6818e'}
OWNER = 'Lcom/android/systemui/pip/PipUI;'


def audit(root):
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('complete') is not True or manifest['apk_sha256'] != APK or manifest['returncode'] != 0:
        raise ValueError('Wrong APK/capture completion')
    for name, pin in PINS.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != pin or manifest['files'][name] != pin:
            raise ValueError('Wrong captured DEX/disassembly')
    bodies = methods(root / 'classes.dump.gz', root / 'classes.dex')
    if len(bodies) != 49453:
        raise ValueError('Decoded method coverage differs')
    defined = [k for k in bodies if k[0] == OWNER]
    callers = []
    for key, body in bodies.items():
        for index, instruction in enumerate(body['instructions']):
            if not isinstance(instruction, str) or not instruction.startswith('invoke-'):
                continue
            direct = ', ' + OWNER + '.' in instruction
            callback = 'Lcom/android/systemui/statusbar/CommandQueue$Callbacks;.showPictureInPictureMenu:' in instruction
            if direct or callback:
                callers.append(dict(caller=list(key), kind='typed_PipUI' if direct else 'CommandQueue_callback_dispatch',
                    instruction_index=index, instruction=instruction,
                    context=body['instructions'][max(0, index-6):index+7],
                    normalized_body_sha256=hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()))
    return dict(apk_sha256=APK, raw_files_sha256=PINS, decoded_concrete_methods=len(bodies),
        pipui_defined_methods=[list(k) for k in sorted(defined)], callers=callers,
        absent_source_methods=[name for name in ['expandPip', 'hidePipMenu'] if not any(k[1] == name for k in defined)],
        limits=['Complete decoded code reference scan of this exact APK only; not execution or retained-object proof.',
                'Generic SystemUI start/configuration/dump dispatch, reflection, resources, native callers and other APKs are not a closed-world call graph.',
                'Instruction excerpts do not prove caller reachability or all branch conditions. Existing manager/provider dependencies can have other owners.',
                'expandPip/hidePipMenu source methods absent from this APK cannot be presented as current runtime callers. Future builds may retain them.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    report = audit(a.capture)
    with a.output.open('x') as file: file.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(decoded_methods=report['decoded_concrete_methods'],
                         caller_sites=len(report['callers']), absent_source_methods=report['absent_source_methods'])))

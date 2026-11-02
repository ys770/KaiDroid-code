"""Full APK scope gate for the held PiP candidate; not a behavior or RAM verifier."""
import argparse
import json
from pathlib import Path

from compare_dexdump_methods import fold_service_loader_names
from verify_wallpaper_apk import load, sha

BASELINE = '2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
OWNER = 'Lcom/android/systemui/pip/PipUI;'
OLD = (OWNER, '<init>', '(Landroid/content/Context;Lcom/android/systemui/statusbar/CommandQueue;Lcom/android/systemui/pip/BasePipManager;)V')
NEW = (OWNER, '<init>', '(Landroid/content/Context;Lcom/android/systemui/statusbar/CommandQueue;Ldagger/Lazy;)V')
PROVIDE = ('Lcom/android/systemui/pip/PipUI_Factory;', 'provideInstance', '(Ljavax/inject/Provider;Ljavax/inject/Provider;Ljavax/inject/Provider;)Lcom/android/systemui/pip/PipUI;')
EXPECTED = {NEW, (OWNER, 'showPictureInPictureMenu', '()V'), PROVIDE}


def rename_key(key): return NEW if key == OLD else key


def model_scope(before, after):
    if OLD not in before['defined'] or NEW in before['defined'] or OLD in after['defined'] or NEW not in after['defined']:
        raise ValueError('Require exactly the reviewed constructor replacement')
    if before['classes'] != after['classes'] or before['metadata'] != after['metadata']:
        raise ValueError('Class/hierarchy/interface/field metadata changed')
    if {rename_key(k) for k in before['defined']} != after['defined']:
        raise ValueError('Unexpected concrete method set')
    if {rename_key(k): v for k, v in before['declarations'].items()} != after['declarations']:
        raise ValueError('Method kind/access/code presence changed')
    if before['entries'] != after['entries']:
        raise ValueError('Non-code payload/compression changed')
    original = {rename_key(k): v for k, v in before['bodies'].items()}
    if original.keys() != after['bodies'].keys() or not EXPECTED.issubset(original):
        raise ValueError('Decoded method closure differs')
    folded, renames = fold_service_loader_names(original, after['bodies'])
    changed = {key for key in original if original[key] != folded[key]}
    if changed != EXPECTED:
        raise ValueError('Unexpected semantic method delta: ' + repr(sorted(changed)))
    return renames


def verify(original, candidate, baseline_capture, candidate_capture):
    if sha(original) != BASELINE or sha(candidate) == BASELINE:
        raise ValueError('Wrong baseline or unchanged candidate')
    before = load(original, baseline_capture); after = load(candidate, candidate_capture)
    if before['manifest']['dexdump_sha256'] != after['manifest']['dexdump_sha256']:
        raise ValueError('Disassembler binary differs')
    renames = model_scope(before, after)
    return dict(baseline_sha256=BASELINE, candidate_sha256=sha(candidate),
        retained_classes=len(before['classes']), retained_concrete_methods=len(before['defined']),
        retained_all_method_declarations=len(before['declarations']),
        noncode_payload_and_compression_entries_preserved=len(before['entries']),
        constructor_replacement=dict(before=OLD, after=NEW), changed_methods=sorted(EXPECTED),
        service_loader_full_body_bijection=renames, metadata_preserved=True,
        limits=['A passing result restricts scope only; changed method bodies still require source/control-flow review and Android tests.',
                'Dagger factory correctness, unsupported/provider construction, callbacks, active startup selection and allocations are not proved by allowed method names.',
                'Debug/annotation metadata, signing/alignment, image closure, installation, hardware, smoothness and physical savings are separate gates.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'baseline-capture', 'candidate-capture', 'output']: p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); result = verify(a.baseline, a.candidate, a.baseline_capture, a.candidate_capture)
    with a.output.open('x') as file: file.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

"""Prepare an opt-in first-present-fence backlight patch; never install it."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = 'ca49741c30830aacda00d91f24c48e3e410211737a43d1372656436aa8532860'
BLUEPRINT_SHA = '581fe4f8eabaaa88b50adb5a604599d84b43e59d155a049040d72561c6dbb738'


def prepare(source: Path, output: Path):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Unreviewed SurfaceFlinger input')
    blueprint = source.with_name('Android.bp').read_bytes()
    if hashlib.sha256(blueprint).hexdigest() != BLUEPRINT_SHA:
        raise ValueError('Unreviewed SurfaceFlinger Blueprint')
    bp = blueprint.decode('utf-8')
    anchor = '        "android.hardware.power@1.0",'
    if bp.count(anchor) != 1:
        raise ValueError('Missing or ambiguous Light HAL dependency anchor')
    bp = bp.replace(anchor, '        "android.hardware.light@2.0",\n' + anchor)
    text = data.decode('utf-8')
    edits = [
        ('#include "SurfaceFlinger.h"', '#include "SurfaceFlinger.h"\n#include "KaiDroidBacklight.h"'),
        ('    *outSupport =\n            getHwComposer().hasDisplayCapability(*displayId, hal::DisplayCapability::BRIGHTNESS);',
         '    *outSupport = (displayId == getInternalDisplayIdLocked() &&\n'
         '                   KaiDroidBacklight::get().supported()) ||\n'
         '            getHwComposer().hasDisplayCapability(*displayId, hal::DisplayCapability::BRIGHTNESS);'),
        ('                   return getHwComposer().setDisplayBrightness(*displayId, brightness);',
         '                   if (displayId == getInternalDisplayIdLocked() &&\n'
         '                       KaiDroidBacklight::get().supported()) {\n'
         '                       return promise::yield<status_t>(KaiDroidBacklight::get().brightness(brightness));\n'
         '                   }\n'
         '                   return getHwComposer().setDisplayBrightness(*displayId, brightness);'),
        ('    display->setPowerMode(mode);',
         '    if (display->isPrimary() && KaiDroidBacklight::get().supported()) {\n'
         '        KaiDroidBacklight::get().power(mode == hal::PowerMode::ON || mode == hal::PowerMode::DOZE);\n'
         '    }\n'
         '    display->setPowerMode(mode);'),
        ('    auto presentFenceTime = std::make_shared<FenceTime>(mPreviousPresentFences[0]);',
         '    if (display && display->isPrimary() && KaiDroidBacklight::get().supported() &&\n'
         '        (display->getPowerMode() == hal::PowerMode::ON ||\n'
         '         display->getPowerMode() == hal::PowerMode::DOZE)) {\n'
         '        KaiDroidBacklight::get().frame(mPreviousPresentFences[0]);\n'
         '    }\n'
         '    auto presentFenceTime = std::make_shared<FenceTime>(mPreviousPresentFences[0]);'),
    ]
    for old, new in edits:
        if text.count(old) != 1:
            raise ValueError('Missing or ambiguous patch anchor: ' + old[:70])
        text = text.replace(old, new)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'SurfaceFlinger.cpp').write_text(text, encoding='utf-8', newline='\n')
    (output / 'Android.bp').write_text(bp, encoding='utf-8', newline='\n')
    base = Path(__file__).resolve().parents[1] / 'experiments/display-resume01'
    for name in ('BacklightGate.h', 'KaiDroidBacklight.h'):
        (output / name).write_bytes((base / name).read_bytes())
    report = {'source_sha256': SOURCE_SHA, 'patch_anchors': len(edits),
              'blueprint_source_sha256': BLUEPRINT_SHA,
              'enable_property': 'ro.kaidroid.frame_backlight=true',
              'default_enabled': False, 'compiled': False, 'installed': False,
              'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in output.iterdir() if p.is_file()}}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))

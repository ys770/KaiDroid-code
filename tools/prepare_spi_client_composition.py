"""Prepare hash-pinned, opt-in startup client composition for the N139DL SPI path."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = '53948b7956571a0eb023525e198f303f679b2608ed78de827839934f115ccbff'
ANCHOR = '    ALOGI_IF(mDebugRegion, "showupdates enabled");'
INSERT = '''

    // N139DL SPI validation accepts only the RGB565 GPU client target.
    // Opt in explicitly and require the paired RGB565 RenderSurface path.
    mDebugDisableHWC = base::GetBoolProperty("ro.kaidroid.force_client_composition", false) &&
            base::GetBoolProperty("ro.kaidroid.rgb565_client_target", false);
    ALOGI_IF(mDebugDisableHWC, "KaiDroid SPI startup client composition enabled");'''

def prepare(source, output):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Unexpected SurfaceFlinger source')
    text = data.decode()
    if text.count(ANCHOR) != 1:
        raise ValueError('Ambiguous source anchor')
    candidate = text.replace(ANCHOR, ANCHOR + INSERT).encode()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'SurfaceFlinger.cpp').write_bytes(candidate)
    report = dict(source_sha256=SOURCE_SHA,
                  candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                  enable_properties=['ro.kaidroid.force_client_composition=true',
                                     'ro.kaidroid.rgb565_client_target=true'],
                  default_enabled=False, compiled=False, startup_validated=False,
                  scope='Uses existing global developer client-composition switch, including virtual outputs; HWC still presents client target')
    (output / 'manifest.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    prepare(a.source, a.output)

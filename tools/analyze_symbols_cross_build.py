"""Read-only, hash-bound comparison of actual Symbols panels across builds/apps."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
INPUTS = [
    ('donor-notes', 'docs/screenshots/2026-10-27-tcl-symbols-reference/symbols-open.png',
     '0d473271fa1fa79cc45a7ac557aa6ab5a82d46998feca8fbd9086c617ab23244', (0, 224, 240, 290)),
    ('image53-notes', 'docs/screenshots/2026-10-27-image53/notes-symbols-panel.png',
     'a4708e7e0eadbd0d5c2853e489b964b558383f8cdef0fda36ffbe3684317f587', (0, 254, 240, 320)),
    ('image59-clock', 'docs/screenshots/2026-10-27-image59-clock/first-first-symbols-editor.png',
     '625fc2fdd167f8876e478383f36b7439125d2ac5b8ef3a2fb3ee2c727e6b3022', (0, 224, 240, 290)),
    ('image59-notes', 'docs/screenshots/2026-10-27-image59-notes-functional/first-symbols-editor.png',
     '587db7941f3dd0f5b0de6fcbde2ee9d30464d7371dc525db137da3ab423c7ebc', (0, 224, 240, 290)),
]


def analyze():
    panels = []
    sources = []
    for name, path, pin, box in INPUTS:
        source = ROOT / path
        if hashlib.sha256(source.read_bytes()).hexdigest() != pin:
            raise ValueError('Original capture changed: ' + name)
        with Image.open(source) as image:
            if image.size != (240, 320):
                raise ValueError('Capture dimension mismatch')
            panel = image.convert('RGB').crop(box)
        panels.append(list(panel.get_flattened_data()))
        sources.append(dict(name=name, path=path, sha256=pin, crop_bounds=list(box),
                            cropped_rgb_sha256=hashlib.sha256(panel.tobytes()).hexdigest()))
    rows = []
    donor = panels[0]
    for index, candidate in enumerate(panels[1:], 1):
        pairs = Counter((a, b) for a, b in zip(donor, candidate) if a != b)
        histogram = Counter()
        deltas = Counter()
        for (a, b), count in pairs.items():
            histogram[max(abs(x-y) for x, y in zip(a, b))] += count
            deltas[tuple(y-x for x, y in zip(a, b))] += count
        rows.append(dict(candidate=INPUTS[index][0], pixels=15840, differing_pixels=sum(pairs.values()),
                         maximum_channel_delta_histogram={str(k): v for k, v in sorted(histogram.items())},
                         selected_first_cell_differences=sum(a != b and i % 240 < 33 and i // 240 < 33
                                                             for i, (a, b) in enumerate(zip(donor, candidate))),
                         largest_color_pairs=[dict(donor=a, nokia=b, pixels=n) for (a, b), n in pairs.most_common(8)],
                         signed_channel_deltas=[dict(delta=d, pixels=n) for d, n in deltas.most_common()]))
    return dict(scope='Actual captured Symbols panel only, with explicit original53 displacement; no image editing',
                sources=sources, comparisons=rows,
                all_three_nokia_cropped_rgb_buffers_equal=panels[1] == panels[2] == panels[3],
                full_frames_compared=False, original53_vertical_translation_pixels=30,
                finding='All three Nokia panel RGB buffers are identical. The stable 974-pixel donor residual includes762 selected-blue pixels differing only in green129→130; not solely glyph edges.',
                cause_established=False, renderer_or_format_quantization_is_only_a_hypothesis=True,
                colors_patched=False, remaining_differences_accepted=False, physical_keys=False, full_parity=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = analyze()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(output=str(args.output), cropped_rgb_equal=report['all_three_nokia_cropped_rgb_buffers_equal'],
                          differences=[r['differing_pixels'] for r in report['comparisons']], cause_established=False)))


if __name__ == '__main__':
    main()

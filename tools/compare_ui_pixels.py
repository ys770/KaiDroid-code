"""Exact pixel comparison, without resizing or silently ignoring regions."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from PIL import Image, ImageChops


def compare(reference, candidate, output, regions=None):
    a, b = Image.open(reference).convert('RGB'), Image.open(candidate).convert('RGB')
    if a.size != b.size:
        raise ValueError('Different dimensions; rescaling would hide a mismatch')
    for name, box in (regions or {}).items():
        if (not name or len(box) != 4 or any(type(n) is not int for n in box)
                or not 0 <= box[0] < box[2] <= a.width
                or not 0 <= box[1] < box[3] <= a.height):
            raise ValueError('Invalid region: ' + str(name))
    output.mkdir(parents=True, exist_ok=False)
    diff = ImageChops.difference(a, b)
    pixels = list(diff.get_flattened_data())
    changed = sum(pixel != (0, 0, 0) for pixel in pixels)
    mask = Image.new("L", a.size)
    # Count every changed channel, including a difference of one.
    mask.putdata([255 if pixel != (0, 0, 0) else 0 for pixel in pixels])
    diff.save(output / 'difference.png')
    Image.composite(Image.new('RGB', a.size, 'red'), b, mask).save(output / 'mismatch-map.png')
    report = dict(reference=str(reference.resolve()), candidate=str(candidate.resolve()),
                  reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
                  candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
                  size=list(a.size), changed_pixels=changed, total_pixels=a.width*a.height,
                  exact_pixel_match=changed == 0, ignored_regions=[],
                  note='Includes clock, signal, battery, content and cursor changes. Match starting state before attributing differences to layout. Does not prove input behavior.')
    report['regions'] = {}
    for name, box in (regions or {}).items():
        values = list(diff.crop(box).get_flattened_data())
        histogram = Counter(max(pixel) for pixel in values if max(pixel))
        report['regions'][name] = dict(bounds=list(box), total_pixels=len(values),
            changed_pixels=sum(histogram.values()), max_channel_delta=max(histogram, default=0),
            delta_histogram={str(k): v for k, v in sorted(histogram.items())})
    (output/'comparison.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--regions', type=Path, help='JSON name-to-[left,top,right,bottom] mapping; full-image result still includes every pixel')
    a=p.parse_args()
    print(json.dumps(compare(a.reference, a.candidate, a.output,
                            json.loads(a.regions.read_text()) if a.regions else None)))

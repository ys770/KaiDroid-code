"""Read-only inventory for combining UI JARs and generated ART boot artifacts.

Does not copy a system tree, build an image, change sources or operate a phone.
Uses the encoded installed Wi-Fi JAR, not the pre-hiddenapi module DEX output.
"""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--product', type=Path, required=True)
    a = p.parse_args()
    base = a.baseline.resolve(strict=True)
    product = a.product.resolve(strict=True)
    if 'ro.kaidroid.image=27' not in (base / 'build.prop').read_text().splitlines():
        raise ValueError('Expected preserved image27 baseline')
    paths = set()
    for root in (base, product / 'system'):
        paths.update(str(path.relative_to(root)) for path in (root / 'framework').rglob('*')
                     if path.is_file() and path.suffix in ('.jar', '.art', '.oat', '.vdex'))
        paths.update(str(path.relative_to(root)) for path in (root / 'apex').glob('*/javalib/*.jar')
                     if path.is_file())
    art_source = product / 'apex/com.android.art/javalib/arm'
    if not art_source.is_dir():
        raise ValueError('Missing generated ART boot artifacts')
    paths.update('apex/com.android.art.release/javalib/arm/' + path.name
                 for path in art_source.glob('boot*') if path.is_file())
    rows = []
    for name in sorted(paths):
        old = base / name
        if name.startswith('apex/com.android.art.release/javalib/arm/'):
            new = art_source / Path(name).name
        else:
            new = product / 'system' / name
        before = sha(old) if old.is_file() else None
        after = sha(new) if new.is_file() else None
        rows.append(dict(destination=name, baseline_sha256=before, candidate_sha256=after,
                         source=str(new), candidate_bytes=new.stat().st_size if new.is_file() else None,
                         changed=before != after))
    pins = {
        'framework/framework.jar': '218c2599a1f706969f32f747239bb7073f58925d6938c2b97cc918f3cff310c5',
        'apex/com.android.wifi/javalib/framework-wifi.jar': 'f8b11d15967e37095eb40e72729985db573513e5e138f203331acaaf4ee72351',
    }
    for name, expected in pins.items():
        if sha(product / 'system' / name) != expected:
            raise ValueError('Candidate identity mismatch: ' + name)
    identities = []
    for name in ('apex_manifest.pb', 'apex_pubkey'):
        rel = 'apex/com.android.wifi/' + name
        identities.append(dict(path=rel, baseline_sha256=sha(base / rel),
                               candidate_sha256=sha(product / 'system' / rel)))
    print(json.dumps(dict(scope=__doc__, baseline=str(base), product=str(product), files=rows,
                          wifi_flattened_identity=identities, staged=False, built=False,
                          installed=False, coherence_verified=False), indent=2))


if __name__ == '__main__':
    main()

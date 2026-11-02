"""Stage reviewed native-only change and preserve original source/output."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', required=True, type=Path)
p.add_argument('--candidate', required=True, type=Path)
p.add_argument('--stage', required=True, type=Path)
a = p.parse_args()
source = a.root / 'aosp/frameworks/native/services/surfaceflinger/SurfaceFlinger.cpp'
library = a.root / 'out-eng-02/target/product/n139dl/system/lib/libsurfaceflinger.so'
assert sha(source) == '53948b7956571a0eb023525e198f303f679b2608ed78de827839934f115ccbff'
assert sha(a.candidate) == 'ca49741c30830aacda00d91f24c48e3e410211737a43d1372656436aa8532860'
assert sha(library) == '3f0d105fba18197628bd1183cfc92cb963feddb7c324264a76b9e75131b22639'
a.stage.mkdir(parents=True, exist_ok=False)
shutil.copy2(source, a.stage / 'SurfaceFlinger.original.cpp')
shutil.copy2(library, a.stage / 'libsurfaceflinger.original.so')
shutil.copy2(a.candidate, source)
(a.stage / 'staging.json').write_text(json.dumps(dict(source=str(source),
    candidate_sha256=sha(source), original_library_sha256=sha(library)), indent=2))

"""Prepare an offline Nokia-only FPS diagnostic; never install or change the source tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

SOURCE = 'afcc1de1a68e558b80dcf507d6cd4227fb38df33ce53708297ece8f772287c57'
FILE = 'smali/com/tcl/camera/module/video/AutoVideoModule.smali'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--decoded', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
raw = (a.decoded/FILE).read_bytes()
assert hashlib.sha256(raw).hexdigest() == SOURCE
assert not a.output.exists()
shutil.copytree(a.decoded, a.output, ignore=shutil.ignore_patterns('build', 'dist'))
s = raw.decode().replace('\r\n', '\n')
start = s.index('.method protected applyCommonSettings(')
end = s.index('.end method', start)
m = s[start:end]
anchor = '    const/16 v1, 0xa'
assert m.count(anchor) == 1 and 'CONTROL_AE_TARGET_FPS_RANGE' in m
m = m.replace(anchor, '    const/16 v1, 0x1e')
(a.output/FILE).write_text(s[:start]+m+s[end:], encoding='utf-8', newline='\n')
assert (a.decoded/FILE).read_bytes() == raw
print(json.dumps(dict(source_sha256=SOURCE,
    candidate_sha256=hashlib.sha256((a.output/FILE).read_bytes()).hexdigest(),
    requested_range=[30,30], baseline_range=[10,30],
    diagnostic_only=True, installed=False)))

"""Create a standalone test module with actual provider sources, no registered providers."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','patched','fixtures','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    report=json.loads((a.patched/'report.json').read_text())
    relative=Path('src/com/android/providers/telephony')
    for name,row in report['files'].items():
        assert hashlib.sha256((a.source/relative/name).read_bytes()).hexdigest()==row['before']
        assert hashlib.sha256((a.patched/name).read_bytes()).hexdigest()==row['after']
    a.output.mkdir(parents=True)
    # Reuse telephonyprovider-protos; do not copy its module definitions or
    # regenerate the same classes inside this standalone diagnostic module.
    for name in ('src','res','assets'):
        if (a.source/name).is_dir():
            shutil.copytree(a.source/name,a.output/name,
                            ignore=shutil.ignore_patterns('Android.bp','Android.mk'))
    for name in report['files']:shutil.copyfile(a.patched/name,a.output/relative/name)
    for name in ('Android.bp','AndroidManifest.xml','AttachmentInstrumentation.java'):
        shutil.copyfile(a.fixtures/name,a.output/name)
    manifest=(a.output/'AndroidManifest.xml').read_text()
    assert '<provider' not in manifest and 'org.kaidroid.telephonyprobe' in manifest
    hashes={str(f.relative_to(a.output)):hashlib.sha256(f.read_bytes()).hexdigest()
            for f in a.output.rglob('*') if f.is_file()}
    (a.output/'source-manifest.json').write_text(json.dumps(hashes,indent=2)+'\n')
    print(json.dumps(dict(files=len(hashes),registered_providers=0,built=False,executed=False)))


if __name__=='__main__':main()

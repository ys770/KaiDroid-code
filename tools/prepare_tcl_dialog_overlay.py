"""Freeze dialog-only source changes plus the accepted image46 resolver bindings."""
import argparse
import difflib
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

SOURCE_PINS = {
    'core/java/android/app/TctDialog.java': ('TctDialog.before.java',
        '3a585b86de6980728cf3f68bb25bc0c88a3c54e7edf5b1ba187f71c46d2fc091',
        '1077dd488191aa9907abc45dec344307a487ff3557ed771f28c35dc7600880e6'),
    'core/java/android/widget/TctDialogMessage.java': ('TctDialogMessage.before.java',
        'b11cdb7d1b190bb20c081d740805f94281639790b57c3eda0f79c429bd50e30b',
        '80b4114ff31a2839f65e921257d9d3c2066e177e5bc9d39e0b8e7ac5debf9a3a'),
    'core/java/android/widget/KeypadImeController.java': ('KeypadImeController.before.java',
        '16ae46ac7958dd89759b74a4a0b544555f9b73f54a033f8d76e66cdb053b1948',
        '633dc17c0e4778bdb86e14f9d591ef39a11cc1fcda235816f9c4871e20482acd'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(root, resolver, before, output, version=1):
    if output.exists():
        raise FileExistsError(output)
    retained = json.loads((root/'docs/contracts/tcl-resolver-overlay02.json').read_text())
    if canonical(retained['files']) != '43d44ff4b551ba18344aa511b2a9c228b4e75109e3ed17f1aa68b3270498b98c':
        raise ValueError('Unreviewed retained resolver')
    files = dict(retained['files'])
    sources = {n: resolver/n for n in files}
    source_baseline = {}
    patches = []
    source_pins = dict(SOURCE_PINS)
    if version in (2,3):
        name = 'core/java/android/app/TctDialog.java'
        source_pins[name] = (*source_pins[name][:2],
            '85c9f67f1aeadd3e929d3ae0143ecafeed36698faaf320017620f04243173be0' if version==2 else
            'a2c00d7728281cd5876674573466a3da2e8ebc9ab56a882351b9e752949c86c6')
    elif version != 1:
        raise ValueError('Unreviewed overlay version')
    for name, (old_file, old_hash, new_hash) in source_pins.items():
        source = root/'framework'/name
        old = before/old_file
        if sha(old) != old_hash or sha(source) != new_hash:
            raise ValueError('Unreviewed dialog source: '+name)
        files[name] = new_hash
        sources[name] = source
        source_baseline['aosp/frameworks/base/'+name] = old_hash
        patches.extend(difflib.unified_diff(old.read_text().splitlines(True), source.read_text().splitlines(True),
            fromfile='a/'+name, tofile='b/'+name))
    for name, path in sources.items():
        if sha(path) != files[name]:
            raise ValueError('Retained binding changed: '+name)
    metadata = before/'staging.before.json'
    exports = root/'work/tcl-resolver-title-artifact01/outputs-retry02.json'
    if sha(metadata) != '232add6194c05c30c7c388a352bfd559b97ca784a39e2863afbc270053d98064' or \
            sha(exports) != 'ac53cfb7aa33337346f565b609a915165c14ee41033422a743f610bffde8878f':
        raise ValueError('Changed accepted framework metadata')
    compiled = json.loads(exports.read_text())['files']
    if len(compiled) != 30 or compiled['framework/framework.jar'] != '11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1':
        raise ValueError('Wrong accepted framework closure')
    output.mkdir(parents=True)
    for name, source in sources.items():
        target = output/'overlay'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source,target)
    (output/'dialog.patch').write_text(''.join(patches), newline='\n')
    archive = output/'overlay.tar.gz'
    with archive.open('wb') as stream, gzip.GzipFile(fileobj=stream,mode='wb',mtime=0,filename='') as zipped, \
            tarfile.open(fileobj=zipped,mode='w') as tar:
        for name in sorted(files):
            data=(output/'overlay'/name).read_bytes()
            entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o644
            tar.addfile(entry,io.BytesIO(data))
    report = dict(files=files,canonical_sha256=canonical(files),source_baseline=source_baseline,
        retained_resolver_files=retained['files'],before_closure=compiled,
        art_apex=json.loads(metadata.read_text())['art_apex'],
        accepted_framework_image=46,cache='tcl-resolver-build02/out',
        cache_build_exit='tcl-resolver-build02/build-retry02.exit',
        cache_export='tcl-resolver-build02/outputs-retry02.json',cache_export_sha256=sha(exports),
        cache_staging_sha256=sha(metadata),archive_sha256=sha(archive),
        scope='Three dialog/IME files changed; accepted46 resolver3files retained exactly; no resources/SystemUI/battery/scrollbar changes',
        acceptance='Configure before first show; no dynamic title rerender parity claim',
        remaining=['Rounded corner/glyph pixels differ','Long message scrollbar remains separate',
                   'Checkbox/list/editor donor geometry unmeasured','No platform build or phone acceptance'],
        platform_built=False,installed=False)
    if version in (2,3):
        report['overlay_version'] = version
        report['acceptance'] = 'Three static message cases plus two late setDialogTitle transitions measured against original donor; other dynamic mutations unverified'
    if version == 3:
        report['acceptance'] += '; checkbox Center/left Check and list boundary wrapping/row selection match original3variant observations'
        report['remaining'] = ['Native checkbox artwork still differs','Rounded corner/glyph pixels differ',
            'Editor absolute IME/window/footer integration unverified; relative field layout measured',
            'Long message scrollbar remains separate','No platform build or phone acceptance']
    (output/'contract.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(files=len(files),canonical_sha256=report['canonical_sha256'],archive_sha256=sha(archive))))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('resolver','before','output'):
        p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--version',type=int,choices=(1,2,3),default=1)
    a=p.parse_args()
    prepare(Path(__file__).resolve().parents[1],a.resolver,a.before,a.output,a.version)

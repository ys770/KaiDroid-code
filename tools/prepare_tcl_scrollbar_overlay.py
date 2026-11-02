"""Stage the observed TCL ListView/ScrollView resource differences, without building."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import zipfile
from PIL import Image

DONOR = 'c5065aaf6ec79ce259e9e29fdaae46159f616a2ad9e816e4f93fe66935edd0d4'
STYLES = '7e9be3dec059b888860ff34f6995c1a3957d13bc8ec521c35797a386adb74fbe'
ASSETS = {
    'listview_scrollbar_img': ('7c76bbf8cb4fea32d718ff5ed50bc9a250725489aeb86d13d8a86919c597b941',
                             '193448a679f1cfefed56ead2f3d44a4fef82baa2cceecfc65718081182509a48'),
    'listview_track_img': ('f93b9336f5510fdb236c13174adf49b898a8663dcf3afbd737eb8c65464b7325',
                         '55ff6bfd5c4beb64b8e368a3955a92b40ea8460e2f03af2843cd1e662c8220eb'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(donor, decoded, styles, output):
    if output.exists():
        raise FileExistsError(output)
    if sha(donor) != DONOR or sha(styles) != STYLES:
        raise ValueError('Unreviewed donor/framework source')
    sources = {}
    artwork = {}
    with zipfile.ZipFile(donor) as archive:
        for name, (compiled_sha, source_sha) in ASSETS.items():
            entry = 'res/drawable-mdpi-v4/'+name+'.9.png'
            data = archive.read(entry)
            if hashlib.sha256(data).hexdigest() != compiled_sha:
                raise ValueError('Wrong compiled artwork: '+name)
            matches = list(decoded.glob('res/drawable-mdpi*/'+name+'.9.png'))
            if len(matches) != 1 or sha(matches[0]) != source_sha:
                raise ValueError('Wrong decoded nine-patch: '+name)
            import io
            original = Image.open(io.BytesIO(data)).convert('RGBA')
            source = Image.open(matches[0]).convert('RGBA')
            if source.size != (original.width+2, original.height+2) or \
                    source.crop((1,1,source.width-1,source.height-1)).tobytes() != original.tobytes():
                raise ValueError('Decoded artwork changes core pixels: '+name)
            sources[name] = matches[0]
            artwork[name] = dict(compiled_entry=entry, compiled_sha256=compiled_sha,
                                 source_sha256=source_sha, core_pixels_identical=True,
                                 compiled_size=list(original.size), source_size=list(source.size))
    before = styles.read_text()
    after = before
    addition = '''
        <item name="scrollbarThumbVertical">@drawable/zz_kaidroid_tcl_listview_scrollbar_img</item>
        <item name="scrollbarTrackVertical">@drawable/zz_kaidroid_tcl_listview_track_img</item>
        <item name="fadeScrollbars">false</item>'''
    for anchor in ('<style name="Widget.ListView" parent="Widget.AbsListView">',
                   '<style name="Widget.ScrollView">'):
        if after.count(anchor) != 1:
            raise ValueError('Unexpected native style anchor')
        start = after.index(anchor)
        end = after.index('</style>', start)
        if any(n in after[start:end] for n in ('scrollbarThumbVertical', 'scrollbarTrackVertical', 'fadeScrollbars')):
            raise ValueError('Scrollbars already customized; re-review source')
        after = after[:start]+after[start:].replace(anchor, anchor+addition, 1)
    output.mkdir(parents=True)
    overlay = output/'overlay'
    target = overlay/'values/styles.xml'
    target.parent.mkdir(parents=True)
    target.write_text(after, newline='\n')
    for name, source in sources.items():
        target = overlay/'drawable-mdpi'/('zz_kaidroid_tcl_'+name+'.9.png')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (output/'styles.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile='a/frameworks/base/core/res/res/values/styles.xml', tofile='b/frameworks/base/core/res/res/values/styles.xml')), newline='\n')
    report = dict(donor_sha256=DONOR, base_styles_sha256=STYLES, artwork=artwork,
                  overlay={p.relative_to(overlay).as_posix():sha(p) for p in sorted(overlay.rglob('*')) if p.is_file()},
                  changed_styles=['Widget.ListView','Widget.ScrollView'],
                  changed_attributes=['scrollbarThumbVertical','scrollbarTrackVertical','fadeScrollbars'],
                  naming='zz_ prefix intended to append private drawable entries; actual old-ID stability must be verified after build',
                  required_gates=['Every old framework resource name retains its old numeric ID',
                                  'Only these two default style bags and the two new drawable definitions differ',
                                  'Existing styles/parents/explicit app overrides preserved',
                                  'Real Clock Repeat scroll thumb/track bounds, pixels and no-fade behavior compared'],
                  resource_apk_built=False, installed=False,
                  scope='Offline original-artwork/style source overlay; no pixel/runtime or complete framework parity claim')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(files=len(report['overlay']), built=False, installed=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('donor','decoded','styles','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    prepare(a.donor, a.decoded, a.styles, a.output)

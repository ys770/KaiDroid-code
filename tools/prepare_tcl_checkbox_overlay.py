"""Stage original checkbox artwork separately from the active dialog03 build."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile
from PIL import Image, ImageChops

DONOR='c5065aaf6ec79ce259e9e29fdaae46159f616a2ad9e816e4f93fe66935edd0d4'
SELECTOR='23e75024cb042ad32900a3ca5302dfb31b6ce1d3ff43cfb3f24e10001e94a50c'
ART={
    'checkbox_checked_nofocus':'15b42ae64fa156216cfbf4204ed4f68ce026bffa3899a7d7a8f2b3458e621a10',
    'checkbox_checked_focused':'094cebebbc76bd37af12b125efc3b6c3628fb35391d836900c9a8413ba37f375',
    'checkbox_unchecked_focus':'be1620cd900f7483adb9604296e540fc24fea80c22bc53543bafdbf1587c273a',
    'checkbox_unchecked_nofocus':'c71d2de7b33d84643e86e32933768a2c818ec8f4911afdb38e7a123a63a50fdc',
}
REFERENCES={
    'checkbox-initial':('f706dafb7d21de96b910328ef85a6d605620583b73246fc09a12c32661abf711','checkbox_checked_nofocus',(255,255,255,255)),
    'checkbox-focused':('754d47c5c3bb46670b7a109839a8d2f3b5cdec6819d2a08aa79e9424eca9a56f','checkbox_checked_focused',(0,140,170,255)),
    'checkbox-left':('4299ac2dbcd010ea97b96f506df42313eea814fc9bf241e602c76b82d6366f92','checkbox_unchecked_focus',(0,140,170,255)),
}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(donor,decoded,references,output):
    if output.exists():raise FileExistsError(output)
    selector=decoded/'res/drawable/ic_checkbox.xml'
    if sha(donor)!=DONOR or sha(selector)!=SELECTOR:
        raise ValueError('Unreviewed donor/selector')
    payload={};artwork={}
    with zipfile.ZipFile(donor) as archive:
        for name,digest in ART.items():
            data=archive.read('res/drawable-mdpi-v4/'+name+'.png')
            if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Artwork changed: '+name)
            source=decoded/'res/drawable-mdpi'/(name+'.png')
            if source.read_bytes()!=data:raise ValueError('Decoded artwork not byte-exact')
            image=Image.open(io.BytesIO(data)).convert('RGBA')
            if image.size!=(18,18):raise ValueError('Artwork geometry changed')
            payload['drawable-mdpi/zz_kaidroid_tcl_'+name+'.png']=data
            artwork[name]=image
    text=selector.read_text(encoding='utf-8')
    for name in ART:
        if text.count('@drawable/'+name+'"')!=1:raise ValueError('Unexpected selector mapping')
        text=text.replace('@drawable/'+name+'"','@drawable/zz_kaidroid_tcl_'+name+'"')
    payload['drawable/zz_kaidroid_tcl_dialog_checkbox.xml']=text.encode('utf-8')
    matches={}
    for name,(digest,art,background) in REFERENCES.items():
        source=references/(name+'.png')
        if sha(source)!=digest:raise ValueError('Wrong original reference: '+name)
        frame=Image.open(source).convert('RGB').crop((10,258,28,276))
        expected=Image.new('RGBA',(18,18),background)
        expected.alpha_composite(artwork[art])
        pixels=list(ImageChops.difference(frame,expected.convert('RGB')).get_flattened_data())
        if any(any(p) for p in pixels):raise ValueError('Original artwork does not match live icon rectangle')
        matches[name]=dict(reference_sha256=digest,artwork=art,bounds=[10,258,28,276],
            pixels=324,changed_pixels=0,max_channel_delta=0)
    output.mkdir(parents=True)
    for name,data in payload.items():
        target=output/'overlay'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(payload.items())}
    archive=output/'overlay.tar.gz'
    with archive.open('wb') as stream,gzip.GzipFile(fileobj=stream,mode='wb',mtime=0,filename='') as zipped,tarfile.open(fileobj=zipped,mode='w') as tar:
        for name,data in sorted(payload.items()):
            entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o644;tar.addfile(entry,io.BytesIO(data))
    report=dict(files=files,canonical_sha256=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        archive_sha256=sha(archive),donor_sha256=DONOR,original_selector_sha256=SELECTOR,
        original_artwork=ART,compiled_and_decoded_artwork_bytes_identical=True,geometry=[18,18],
        original_icon_rectangle_matches=matches,unchecked_unfocused_live_reference=False,
        source_binding='Not included: future dialog must load the new selector without tinting original pixels; no active03 files changed',
        required_platform_gates=['Every existing resource ID/name/visibility/qualified value unchanged',
            'Only5new appended drawable entries and their payloads; old files unchanged',
            'Compiled selector4state predicates/reference IDs exact; compiledRGBA exact',
            'Actual native checkbox4state/keys/geometry/pixel comparison'],
        platform_built=False,installed=False,scope='Original artwork source candidate and3observed icon compositions only; no complete dialog/pixel/UX parity')
    (output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(files=len(files),canonical_sha256=report['canonical_sha256'],archive_sha256=sha(archive))))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('donor','decoded','references','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();prepare(a.donor,a.decoded,a.references,a.output)

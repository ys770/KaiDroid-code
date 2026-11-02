"""Build a native SDK scrollbar resource control. Never installs or changes devices."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from PIL import Image

REFERENCE = '801015e666d99e7269f44487a4079220387066983a4445f3996a39f02dd3b658'
SOURCES = {
    'zz_kaidroid_tcl_listview_scrollbar_img.9.png': '193448a679f1cfefed56ead2f3d44a4fef82baa2cceecfc65718081182509a48',
    'zz_kaidroid_tcl_listview_track_img.9.png': '55ff6bfd5c4beb64b8e368a3955a92b40ea8460e2f03af2843cd1e662c8220eb',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','jdk','overlay','reference','output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise FileExistsError(a.output)
    if sha(a.reference) != REFERENCE:
        raise ValueError('Wrong physical donor reference')
    styles = ET.parse(a.overlay/'values/styles.xml').getroot()
    expected = {'scrollbarThumbVertical':'@drawable/zz_kaidroid_tcl_listview_scrollbar_img',
                'scrollbarTrackVertical':'@drawable/zz_kaidroid_tcl_listview_track_img', 'fadeScrollbars':'false'}
    for name in ('Widget.ListView','Widget.ScrollView'):
        matches = [s for s in styles.findall('style') if s.get('name') == name]
        if len(matches) != 1 or {i.get('name'):i.text for i in matches[0].findall('item') if i.get('name') in expected} != expected:
            raise ValueError('Candidate style properties differ')
    for name, digest in SOURCES.items():
        if sha(a.overlay/'drawable-mdpi'/name) != digest:
            raise ValueError('Wrong compiled-source artwork')
    root = Path(__file__).resolve().parents[1]
    source = root/'tests/scrollbarprobe'
    out = a.output.resolve();out.mkdir(parents=True)
    for name in ('classes','dex','res/drawable-mdpi','res/values','generated','assets'):
        (out/name).mkdir(parents=True)
    for name in SOURCES:
        shutil.copyfile(a.overlay/'drawable-mdpi'/name, out/'res/drawable-mdpi'/name)
    Image.open(a.reference).crop((236,66,240,286)).save(out/'assets/clock-repeat-reference-strip.png')
    resources = ET.Element('resources')
    base = ET.SubElement(resources,'style',name='ProbeBase',parent='@android:style/Theme.Material.NoActionBar')
    ET.SubElement(base,'item',name='android:windowActionModeOverlay').text='true'
    theme = ET.SubElement(resources,'style',name='ProbeCandidate',parent='ProbeBase')
    for name, parent, attr in [('TclList','Widget.Material.ListView','listViewStyle'),('TclScroll','Widget.Material.ScrollView','scrollViewStyle')]:
        style = ET.SubElement(resources,'style',name=name,parent='@android:style/'+parent)
        for key, value in expected.items():
            ET.SubElement(style,'item',name='android:'+key).text=value
        ET.SubElement(theme,'item',name='android:'+attr).text='@style/'+name
    ET.ElementTree(resources).write(out/'res/values/styles.xml',encoding='utf-8',xml_declaration=True)
    jdk = a.jdk.resolve();bt = a.sdk.resolve()/'build-tools/35.0.0';android = a.sdk.resolve()/'platforms/android-30/android.jar'
    suffix = '.exe' if os.name == 'nt' else ''
    env = os.environ.copy();env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
    def run(args):
        args = list(map(str,args));r = subprocess.run(args,capture_output=True,env=env,timeout=120)
        with (out/'build.log').open('ab') as f:
            f.write((json.dumps(args)+'\n').encode()+r.stdout+r.stderr)
        r.check_returncode()
    apk = out/'unsigned.apk'
    run([bt/('aapt'+suffix),'package','-f','-m','-M',source/'AndroidManifest.xml','-S',out/'res','-A',out/'assets','-I',android,'-J',out/'generated','-F',apk])
    run([jdk/('bin/javac'+suffix),'--release','8','-classpath',android,'-d',out/'classes',*source.rglob('*.java'),*sorted((out/'generated').rglob('*.java'))])
    run([jdk/('bin/java'+suffix),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',out/'dex',*sorted((out/'classes').rglob('*.class'))])
    with zipfile.ZipFile(apk,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(out/'dex/classes.dex','classes.dex')
    aligned = out/'aligned.apk';run([bt/('zipalign'+suffix),'-f','4',apk,aligned])
    key = out/'diagnostic-only.p12'
    run([jdk/('bin/keytool'+suffix),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Local Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
    signed = out/'scrollbar-probe.apk';signer = [jdk/('bin/java'+suffix),'-jar',bt/'lib/apksigner.jar']
    run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--out',signed,aligned]);run([*signer,'verify','--verbose','--print-certs',signed])
    report = dict(apk_sha256=sha(signed),reference_full_sha256=REFERENCE,reference_crop=[236,66,240,286],
                  reference_crop_sha256=sha(out/'assets/clock-repeat-reference-strip.png'),source_assets=SOURCES,
                  fixture_sources={str(f.relative_to(root)):sha(f) for f in sorted(source.rglob('*')) if f.is_file()},
                  scope='Controlled native SDK ListView/ScrollView with candidate style properties; not compiled framework or actual Clock rendering',installed=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__ == '__main__':main()

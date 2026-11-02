"""Freeze current-source scrollbar resource inputs and build-scope proposal offline."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from prepare_tcl_scrollbar_overlay import DONOR, STYLES

OVERLAY={
 'values/styles.xml':'bc5d94a3f61009f9419e6577bc95b0e2838a866c62d1bda15d233ed31ccaf9a3',
 'drawable-mdpi/zz_kaidroid_tcl_listview_scrollbar_img.9.png':'193448a679f1cfefed56ead2f3d44a4fef82baa2cceecfc65718081182509a48',
 'drawable-mdpi/zz_kaidroid_tcl_listview_track_img.9.png':'55ff6bfd5c4beb64b8e368a3955a92b40ea8460e2f03af2843cd1e662c8220eb',
}
BASE='42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
CONTRACT='ce85d9e71c211386baee0f65e2c93083852acedba937f4ba2c1b406ac866d2c3'
SDK_PROOF='303b36d1654fdc91d64fbc9b2d72f87f4508a7219d49ca28c600e003aa2e6169'
GATE='1a4931286e8c643e1d49064308dc398357232ece1d5de45a1138fc011cc56e56'


def sha(data):return hashlib.sha256(data).hexdigest()


def canonical(data):return sha(json.dumps(json.loads(data),sort_keys=True,separators=(',',':')).encode())


def packet_files(root,overlay,source):
 report=json.loads((overlay/'report.json').read_text())
 if report.get('donor_sha256')!=DONOR or report.get('base_styles_sha256')!=STYLES or report.get('overlay')!=OVERLAY:
  raise ValueError('Scrollbar source/artwork scope changed')
 original=(source/'styles.xml').read_bytes();receipt=json.loads((source/'source.json').read_text())
 if sha(original)!=STYLES or receipt.get('sha256')!=STYLES or receipt.get('host_modified') is not False:
  raise ValueError('Current read-only host styles acquisition differs')
 files={'baseline/styles.xml':original,'proofs/current-source.json':(source/'source.json').read_bytes(),
        'proofs/source-overlay.json':(overlay/'report.json').read_bytes(),
        'proofs/sdk-native-control.json':(root/'docs/evidence/tcl-scrollbar-native-control01.json').read_bytes(),
        'contract.json':(root/'docs/contracts/tcl-scrollbar-overlay01.json').read_bytes(),
        'tools/verify_tcl_scrollbar_resources.py':(root/'tools/verify_tcl_scrollbar_resources.py').read_bytes().replace(b'\r\n',b'\n')}
 if canonical(files['contract.json'])!=CONTRACT or canonical(files['proofs/sdk-native-control.json'])!=SDK_PROOF or sha(files['tools/verify_tcl_scrollbar_resources.py'])!=GATE:
  raise ValueError('Reviewed resource scope gate/contract/SDK evidence changed')
 for name,pin in OVERLAY.items():
  data=(overlay/'overlay'/name).read_bytes()
  if sha(data)!=pin:raise ValueError('Overlay file changed: '+name)
  files['overlay/'+name]=data
 plan=dict(scope='Resource-only build proposal; no staging, compiler launch, package signing or phone action',
  stage='tcl-scrollbar-build01',backing='/mnt/ext1/kaidroid-tcl-scrollbar-build01',
  baseline_framework_res_sha256=BASE,retained_framework_jar_sha256=FRAMEWORK,
  source_styles_sha256=STYLES,donor_framework_res_sha256=DONOR,
  intended_target='/build/out-eng-02/target/product/n139dl/system/framework/framework-res.apk',
  export_files=['framework/framework-res.apk'],source_delta={'modified':['values/styles.xml'],
   'added':sorted(n for n in OVERLAY if n!='values/styles.xml'),'removed':[]},
  allowed_style_bags=['Widget.ListView','Widget.ScrollView'],
  allowed_style_attributes=['scrollbarThumbVertical','scrollbarTrackVertical','fadeScrollbars'],
  required_preparation=[
   'Verify actual live processes and reserve hardware-owned shared build slot',
   'Use exclusive UID/GID1000 external stage with root/external20GiB floors',
   'Inventory and copy complete current core/res/res into owned tree; preserve all original paths/bytes/modes',
   'Apply only these three pinned overlay inputs to owned copy; compare full source tree',
   'Mount whole owned resource directory read-only over core/res/res; do not create individual new paths in shared source',
   'Use read-only accepted cache lower with private writable OverlayFS upper; preserve complete lower inventory',
   'Regenerate frontend and review actual single-APK Ninja plan with all three resource inputs',
   'Use bounded compiler/watchdog lifecycle; inspect same live job after observation timeout',
   'Export only signed framework-res APK and verify complete cache preservation',
   'Run archived exact resource gate against original42adf baseline and donor; verify signer separately',
   'Prepare later image only over fully verified current installed baseline; retain all Java/preopt/hardware/app/data work'],
  compiled_gate=dict(all_old_ids_and_qualified_values_unchanged=True,only_six_default_style_items_added=True,
   exactly_two_appended_private_drawables=True,old_archive_payloads_unchanged=True,
   exact_donor_rgba_and_ninepatch_metadata=True,manifest_unchanged=True),
  known_residual='SDK ListView and ScrollView each differ from donor at6/880 strip pixels, max channel delta1; unresolved',
  shared_source_modified=False,host_job_started=False,resource_apk_built=False,installed=False,full_parity=False)
 files['build-proposal.json']=(json.dumps(plan,indent=2)+'\n').encode()
 return files


def main():
 root=Path(__file__).resolve().parents[1]
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--overlay',type=Path,default=root/'work/tcl-scrollbar-overlay02')
 p.add_argument('--source',type=Path,default=root/'work/tcl-scrollbar-current-source01')
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 files=packet_files(root,a.overlay,a.source)
 files['packet.json']=(json.dumps(dict(files={n:sha(b) for n,b in sorted(files.items())},
  scope='Frozen offline resource build inputs/proposal, not a launched build'),indent=2)+'\n').encode()
 a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 archive=Path(str(a.output)+'.tar.gz')
 with archive.open('xb') as raw:
  with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as compressed:
   with tarfile.open(fileobj=compressed,mode='w') as tar:
    for name,data in sorted(files.items()):
     item=tarfile.TarInfo(name);item.mode=0o644;item.size=len(data);tar.addfile(item,io.BytesIO(data))
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers()
  if len(members)!=len(files) or {m.name for m in members}!=files.keys():raise ValueError('Archive coverage differs')
  for item in members:
   if not item.isfile() or item.mode!=0o644 or tar.extractfile(item).read()!=files[item.name]:raise ValueError('Archive payload differs')
 print(json.dumps(dict(packet=str(a.output),packet_sha256=sha(files['packet.json']),archive_sha256=sha(archive.read_bytes()),
  files=len(files),archive_bytes_and_modes_verified=True,host_job_started=False)))


if __name__=='__main__':main()

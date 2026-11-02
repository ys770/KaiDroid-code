"""Freeze the resource wrapper's scoped envsetup/lunch nounset correction offline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

ARCHIVE = '06d9a22648c07a452b4a3e268495d500bc7052e169b5f1dae95b1523e3450f73'
SOURCE = '332124036f40dd0aaec3959923c52c1f3d68629c707a360aaf44201aeecad2b0'
OLD = 'source build/envsetup.sh\nlunch kaidroid_n139dl-eng\n'
NEW = '''# AOSP envsetup/lunch intentionally inspect unset optional shell variables.
set +u
if source build/envsetup.sh; then
  :
else
  kaidroid_setup_status=$?
  set -euo pipefail
  exit "$kaidroid_setup_status"
fi
if lunch kaidroid_n139dl-eng; then
  :
else
  kaidroid_lunch_status=$?
  set -euo pipefail
  exit "$kaidroid_lunch_status"
fi
set -euo pipefail
'''


def sha(value):
    return hashlib.sha256(value).hexdigest()


def corrected(source, stage='tcl-scrollbar-build02'):
    if sha(source) != SOURCE or stage != 'tcl-scrollbar-build02':
        raise ValueError('Exact original wrapper and reserved retry02 namespace required')
    text = source.decode()
    if text.count(OLD) != 1 or text.count('stage=/build/tcl-scrollbar-build01\n') != 1:
        raise ValueError('Original setup/namespace boundary differs')
    result = text.replace(OLD,NEW).replace('stage=/build/tcl-scrollbar-build01\n','stage=/build/'+stage+'\n')
    if result.replace(NEW,OLD).replace('stage=/build/'+stage+'\n','stage=/build/tcl-scrollbar-build01\n') != text:
        raise ValueError('Wrapper changed outside reviewed setup/namespace blocks')
    return result.encode()


def prepare(archive, output):
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    raw = archive.read_bytes()
    if sha(raw) != ARCHIVE:
        raise ValueError('Original frozen archive differs')
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as source:
        before = source.extractfile('tools/build_tcl_scrollbar.sh').read()
    after = corrected(before)
    output.mkdir(parents=True)
    (output/'build.sh').write_bytes(after)
    result = dict(original_archive_sha256=ARCHIVE, original_build_sha256=SOURCE,
                  corrected_build_sha256=sha(after),retry_namespace='tcl-scrollbar-build02',
                  changed_blocks=['stage variable namespace','nounset only across source/lunch with explicit failure propagation'],
                  remaining_source_graph_plan_build_export_bytes_unchanged=True,
                  strict_errexit_nounset_pipefail_restored=True,host_operations=False,
                  original_failed_stage_modified=False,compiler_launched=False,full_parity=False)
    with (output/'result.json').open('x',encoding='utf-8') as stream:
        json.dump(result,stream,indent=2);stream.write('\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(prepare(args.archive,args.output)))


if __name__=='__main__':
    main()

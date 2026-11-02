"""Complete native12 raw-word/CSV audit without repeating retained disassembly."""
import argparse
import json
from pathlib import Path
from audit_tcl_app_widgets import BASE, compare_flags, compare_metadata
from audit_tcl_ime_picker_metadata import metadata
from audit_tcl_ime_footer_native11 import archive_payloads
from audit_resolver_title_dex import sha
from read_dex_hiddenapi import inventory
from prepare_tcl_app_widgets_flags_inherited import CSV, validate

CANDIDATE='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','baseline-flags','candidate-flags','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if sha(a.baseline)!=BASE or sha(a.candidate)!=CANDIDATE or sha(a.candidate_flags)!=CSV:
        raise ValueError('Wrong exact native11/native12/CSV inputs')
    delta=validate(a.baseline_flags.read_bytes(),a.candidate_flags.read_bytes())
    before,_=inventory(a.baseline)
    after,_=inventory(a.candidate)
    raw=compare_flags(before,after,True)
    declared=compare_metadata(metadata(a.baseline),metadata(a.candidate),'Landroid/widget/')
    archives=archive_payloads(a.baseline,a.candidate)
    result=dict(baseline_sha256=BASE,candidate_sha256=CANDIDATE,candidate_csv_sha256=CSV,
                csv=delta,raw_flags=raw,metadata=declared,archives=archives,
                complete_flag_and_metadata_checks_passed=True,
                method_disassembly_repeated=False,independent_body_review_recorded=False,
                full_acceptance=False,installed=False,full_parity=False)
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'result.json').write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps(result))


if __name__=='__main__':main()

"""Notes eligibility explicitly binds original failed Clock plus continuation."""
import argparse,json,uuid
from pathlib import Path
import trial_tcl_ime_handover_image59 as t
from finish_tcl_clock_image59 import load_first,paired_clock,FIRST

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',required=True);p.add_argument('--boot',required=True,type=lambda s:str(uuid.UUID(s)))
 p.add_argument('--failed-clock-result',type=Path,required=True);p.add_argument('--donor-cancel-xml',type=Path,required=True)
 p.add_argument('--clock-continuation',type=Path,required=True);p.add_argument('--continuation-sha256',required=True)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 first,donor=load_first(a.failed_clock_result,a.donor_cancel_xml,a.boot)
 t.require(t.sha(a.clock_continuation)==a.continuation_sha256,'Frozen successful continuation required')
 continued=json.loads(a.clock_continuation.read_text());paired_clock(first,continued,a.boot,FIRST,donor)
 a.phase='notes';a.fresh_clock_first=False;a.clock_result=a.clock_continuation
 trial=t.Trial(a)
 trial.report['clock_eligibility']=dict(original_trial_passed=False,original_failed_clock_sha256=FIRST,
  successful_continuation_sha256=a.continuation_sha256,first_symbols_from_original_trial=True,no_fresh_clock_retry=True)
 report=trial.execute()
 t.require(t.sha(a.failed_clock_result)==FIRST and t.sha(a.clock_continuation)==a.continuation_sha256,'Source receipts changed')
 print(json.dumps(report))
 if not report['passed']:raise RuntimeError('Notes acceptance failed; preserve result/state')

if __name__=='__main__':main()

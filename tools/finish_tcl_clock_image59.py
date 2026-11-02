"""Reviewed continuation of one preserved Clock59 trial; never relaunch/Symbols."""
import argparse,copy,json,uuid
from pathlib import Path
import trial_tcl_ime_handover_image59 as t

FIRST='e60dd51b8cc9ab0b2944e2e399fc2ea0709fdea591e1b333684bd0fd97018d6d'
BASE_RUNNER='b5c791affe30616acbdf5170a75cd6ccc866cc67d5ddb7c61613429364f3c7fa'
DONOR='19709cc681708e4e0f6b34559c71375ea6e15db7cbef0a267f89af8f59ed38d7'
FAILURE="ValueError('Symbols cancellation changed editor content/focus/bounds/mode')"

def donor_signature(xml):
 nodes=t.xml_nodes(xml)
 fields=[n for n in nodes if n.get('resource-id')=='android:id/title_edit_text_content' and n.get('class')=='android.widget.EditText']
 left=[n for n in nodes if n.get('resource-id')=='android:id/menu_lsk']
 t.require(len(fields)==len(left)==1,'Exact donor field/native LSK missing')
 value=dict(text=fields[0].get('text',''),bounds=t.bounds(fields[0]['bounds']),focused=fields[0].get('focused')=='true',mode=left[0].get('text'))
 t.require(value==dict(text='Alarm',bounds=[10,252,230,280],focused=True,mode='abc'),'Pinned donor post-Back signature differs')
 return value

def first_evidence(first,boot,donor):
 t.require(first.get('phase')=='clock' and first.get('image')==59 and first.get('boot')==boot and first.get('framework_sha256')==t.FRAMEWORK,'Wrong original Clock binding')
 t.require(first.get('passed') is False and first.get('failure')==FAILURE and first.get('command_state_ambiguous') is False and first.get('cleanup',{}).get('status')=='deferred_mode_restoration_unproven','Only the exact preserved geometry-assumption failure is eligible')
 t.require(first.get('fresh_clock_first_attested') is True and first.get('symbols_requests')==1 and first.get('text_entered') is False and first.get('save_invoked') is False,'Original first-use provenance/one request missing')
 t.require(all(first.get(k,{}).get('visible_reference_panel') is True for k in ('first_symbols_panel','settled_symbols_panel')),'Actual first and settled panel evidence required')
 t.require(first.get('editor_after_symbols')==donor and first.get('editor_before')==dict(text='Alarm',bounds=[10,262,230,290],focused=True,mode='abc'),'Post-Back donor signature does not resolve original failure')
 t.require(first.get('before_home',[None,None])[1]==t.HOME and first.get('original_mode')=='abc','Original Home/mode missing')
 return first['captures']['symbols-cancelled']['owner']

def paired_clock(first,continued,boot,first_sha,donor):
 first_evidence(first,boot,donor)
 t.require(first_sha==FIRST and continued.get('continued_from_failed_clock_sha256')==FIRST and continued.get('first_symbols_evidence_source_sha256')==FIRST and continued.get('original_clock_trial_passed') is False,'Explicit original failed receipt lineage missing')
 t.require(continued.get('new_symbols_requests')==0 and continued.get('donor_postback_signature_match') is True and continued.get('donor_cancel_hierarchy_sha256')==DONOR and continued.get('original_trial_unmodified') is True,'Continuation may not repeat Symbols, hide donor mismatch or rewrite the original')
 t.require(continued.get('first_symbols_panel')==first['first_symbols_panel'] and continued.get('settled_symbols_panel')==first['settled_symbols_panel'] and continued.get('before_home')==first['before_home'],'Original Symbols/Home evidence changed')
 return t.clock_prior(continued,boot)

def load_first(path,donor_path,boot):
 t.require(t.sha(Path(t.__file__))==BASE_RUNNER,'Frozen base runner changed')
 t.require(t.sha(path)==FIRST and t.sha(donor_path)==DONOR,'Exact original failure/donor receipt required')
 first=json.loads(path.read_text());donor=donor_signature(donor_path.read_text());first_evidence(first,boot,donor)
 return first,donor

def finish(args):
 first,donor=load_first(args.failed_clock_result,args.donor_cancel_xml,args.boot)
 trial=t.Trial(args);report=trial.report
 report.update(scope='Bounded continuation: original first Symbols evidence plus new numeric/return/restoration; original terminal1 unchanged',
  continued_from_failed_clock_sha256=FIRST,original_clock_trial_passed=False,first_symbols_evidence_source_sha256=FIRST,
  new_symbols_requests=0,symbols_requests=1,fresh_clock_first_attested=True,before_home=first['before_home'],
  first_symbols_panel=copy.deepcopy(first['first_symbols_panel']),settled_symbols_panel=copy.deepcopy(first['settled_symbols_panel']),
  donor_cancel_hierarchy_sha256=DONOR,donor_postback_signature_match=False,before_state=copy.deepcopy(first['before_state']),original_mode='abc')
 trial.before=first['before_state'];trial.original_mode='abc'
 try:
  trial.identity()
  hashes=trial.shell('core-hashes','sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
  t.require([s.split()[0] for s in hashes.splitlines()]==[t.FRAMEWORK,t.SYSTEMUI],'Core hashes changed')
  owner=first_evidence(first,args.boot,donor);t.require(trial.focus()==owner,'Original Alarm window changed; no input')
  t.require(trial.snapshot('continued-editor')=='editor' and t.editor_signature(trial.current[2],'clock')==donor,'Current unchanged editor does not match actual donor post-Back')
  reference=Path(t.__file__).resolve().parents[1]/t.PROFILES['clock']['reference']
  t.require(t.sha(reference)==t.PROFILES['clock']['reference_sha256'],'Donor Symbols reference changed')
  t.require(not t.panel(args.output/'continued-editor.png',reference)['visible_reference_panel'],'Symbols panel still visible; no mode input')
  report['donor_postback_signature_match']=True
  observed=trial.state('continued-before');report['continued_before_state']=observed
  t.require(observed==trial.before,'Original settings/appfiles changed before continuation')
  trial.owned=True;trial.mode_dirty=True
  trial.choose('numeric',4);t.require(t.mode(trial.current[2])=='123','Numeric callback absent')
  report['numeric_callback_observed']=True;report['numeric_editor']=t.editor_signature(trial.current[2],'clock')
  trial.choose('restore',1);current=t.editor_signature(trial.current[2],'clock')
  t.require(current['text']=='Alarm' and current['focused'] is True and current['mode']=='abc','Original text/focus/mode not restored')
  report['restored_editor']=current
  report['numeric_restore_geometry_independently_unverified']=True
  trial.mode_dirty=False;report['mode_roundtrip_verified']=True;report['symbols_cancelled_without_text']=True;report['workflow_passed']=True
 except Exception as error:report['failure']=repr(error)
 finally:
  try:
   report['cleanup']=trial.cleanup()
   if report.get('exact_home_window_restored'):
    after=trial.state('after');report['after_state']=after;report['all_settings_and_appfiles_restored']=after==trial.before
    t.require(after==trial.before,'Settings/appfiles changed; preservation unproven')
    t.require(t.sha(args.failed_clock_result)==FIRST,'Original failure receipt changed')
    report['passed']=bool(report.get('workflow_passed') and not report.get('failure'))
   if not trial.ambiguous:trial.shell('complete-clock-log',t.log_since(first['log_start_device_time']))
  except Exception as error:report['cleanup_failure']=repr(error);report['passed']=False
  report['original_trial_unmodified']=t.sha(args.failed_clock_result)==FIRST
  report['command_state_ambiguous']=trial.ambiguous;trial.save()
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',required=True);p.add_argument('--boot',required=True,type=lambda s:str(uuid.UUID(s)))
 p.add_argument('--failed-clock-result',type=Path,required=True);p.add_argument('--donor-cancel-xml',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();a.phase='clock';a.fresh_clock_first=False
 report=finish(a);print(json.dumps(report))
 if not report['passed']:raise RuntimeError('Continuation failed; preserve state and both receipts')

if __name__=='__main__':main()

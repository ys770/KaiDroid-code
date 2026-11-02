"""Offline controls: do not collapse selection/death state or harness cleanup into LMK."""
import sys
sys.dont_write_bytecode=True
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('contact_candidate',Path(__file__).with_name('contact-pressure-candidate-analysis01.py'))
analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)


def line(epoch,tag,message):return f'         {epoch}  1164  1231 I {tag}: {message}\n'


class CandidateControls(unittest.TestCase):
    def test_epoch_bound_excludes_old_warning(self):
        raw=line('1793121284.999','ActivityTaskManager','startActivity called from finishing ActivityRecord')
        raw+=line('1793121285.000','ActivityManager','normal')
        result=analysis.extract(raw.encode(),'1793121285')
        self.assertEqual(result['fresh_lines'],1)
        self.assertEqual(result['negative_screen_matches']['finishing_activity_start'],[])

    def test_LMK_selection_and_later_AMS_top_state_stay_separate(self):
        raw=line('1793121302.027','ActivityManager','Start proc 3877:com.android.permissioncontroller/u0a94 for pre-top-activity {component}')
        raw+=line('1793121302.184','lowmemorykiller',"Kill 'com.android.permissioncontroller' (3877), uid 10094, oom_adj 905 to free 14800kB")
        raw+=line('1793121302.210','ActivityManager','Process com.android.permissioncontroller (pid 3877) has died: fg  TOP ')
        kill=analysis.extract(raw.encode(),'1793121285')['kills'][0]
        self.assertEqual(kill['LMK_reported_adj'],905)
        self.assertEqual(kill['AMS_death']['reported_importance'],'fg  TOP')
        self.assertEqual((kill['start_to_kill_ms'],kill['kill_to_AMS_death_ms']),(157,26))

    def test_harness_stop_is_not_counted_as_LMK(self):
        raw=line('1793121382.904','ActivityManager','Force stopping com.android.contacts appid=10073 user=0: from pid 1197')
        raw+=line('1793121382.909','ActivityManager','Killing 3824:com.android.contacts/u0a73 (adj 0): stop com.android.contacts due to from pid 1197')
        result=analysis.extract(raw.encode(),'1793121285')
        self.assertEqual(result['kills'],[]);self.assertEqual(len(result['manual_AMS_kills']),1)

    def test_settings_duplicate_is_not_permission_duplicate(self):
        raw=line('1793121376.531','ActivityTaskManager','Duplicate finish request for r=ActivityRecord{b819fbd u0 com.android.contacts/.preference.ContactsPreferenceActivity t540 f}}')
        result=analysis.extract(raw.encode(),'1793121285')
        self.assertEqual(len(result['duplicate_finish_events']),1)
        self.assertNotIn('GrantPermissionsActivity',result['duplicate_finish_events'][0]['message'])


if __name__=='__main__':unittest.main()

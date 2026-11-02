"""Offline extraction controls. No reproduction or device action."""
import sys
sys.dont_write_bytecode=True
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('contact_pressure_analysis',Path(__file__).with_name('contact-pressure-analysis01.py'))
analysis=importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def line(time,tag,message,pid=1164):
    return f'10-27 {time} {pid:5} {pid:5} I {tag}: {message}\n'


class ExtractionControls(unittest.TestCase):
    def test_cold_start_kill_and_replacement_are_distinct_from_ui_crash(self):
        text=line('12:37:34.133','am_proc_start','[0,748,10094,com.android.permissioncontroller,pre-top-activity,{component}]')
        text+=line('12:37:34.381','lowmemorykiller',"Kill 'com.android.permissioncontroller' (748), uid 10094, oom_adj 905 to free 12364kB",340)
        text+=line('12:37:34.400','am_proc_died','[0,748,com.android.permissioncontroller,905,19]')
        text+=line('12:37:34.616','am_proc_start','[0,844,10094,com.android.permissioncontroller,top-activity,{component}]')
        result=analysis.extract(text.encode())
        kill=result['kills'][0]
        self.assertEqual((kill['start_to_kill_ms'],kill['kill_to_next_start_ms']),(248,235))
        self.assertEqual(kill['death']['state'],19)
        self.assertEqual(result['negative_screen_matches']['ANR'],[])

    def test_opaque_killinfo_does_not_create_a_second_kill(self):
        text=line('12:37:15.644','killinfo','[328,10045,905,800,19904,-1,6368]')
        text+=line('12:37:15.644','some_other_tag',"Kill 'android.process.acore' (328), uid 10045, oom_adj 905 to free 19904kB")
        self.assertEqual(analysis.extract(text.encode())['kills'],[])

    def test_pss_units_and_state_are_read_from_the_right_fields(self):
        text=line('12:38:09.061','am_pss','[448,10045,android.process.acore,7805952,147456,6802432,8527872,0,3,4]')
        row=analysis.extract(text.encode())['later_acore_pss_samples'][0]
        self.assertEqual((row['pss_bytes'],row['swap_pss_bytes'],row['rss_bytes'],row['process_state']),(7805952,6802432,8527872,3))

    def test_pressure_snapshot_is_parsed_instead_of_assumed(self):
        text=line('12:37:16.060','ActivityManager','  ZRAM: 65,588K RAM, 262,140K swap total, 27,972K swap free')
        text+=line('12:37:16.060','ActivityManager','    724K buffers, 97,176K cached, 64,960K mapped, 8,244K free')
        text+=line('12:37:16.060','ActivityManager','  Free RAM: 58,872K')
        row=analysis.extract(text.encode())['pressure_snapshot']
        self.assertEqual((row['meminfo_free_kib'],row['reported_free_ram_kib'],row['swap_used_kib']),(8244,58872,234168))
        self.assertFalse(row['exact_LMK_trigger_proven'])


if __name__=='__main__':unittest.main()

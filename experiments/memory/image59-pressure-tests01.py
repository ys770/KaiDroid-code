"""Offline controls for lifetime, identity, gaps and replayed-log accounting."""
import sys
sys.dont_write_bytecode=True
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
import unittest
spec=importlib.util.spec_from_file_location('image59pressure',Path(__file__).with_name('image59-pressure-analysis01.py'))
analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)


def record(uptime,count,start=100,read_bytes=100):
    fields=['0']*25;fields[0]='S'
    for index,value in ((7,count*10),(9,count),(11,count),(12,count),(19,start)):fields[index]=str(value)
    return dict(returncode=0,elapsed=uptime,output=['59','boot','1',str(uptime)+' 1'],
        pressure=['MemFree: 8000 kB','MemAvailable: 100000 kB','SwapTotal: 262140 kB','SwapFree: 100000 kB']+[key+' '+str(count) for key in analysis.COUNTERS],
        process_io=['PROCESS system_server 1155','1155 (worker (x)) '+' '.join(fields),'read_bytes: '+str(read_bytes),'write_bytes: 0','VmRSS: 100 kB','VmSwap: 10 kB'])


class PressureControls(unittest.TestCase):
    def test_process_restart_cannot_be_joined_by_pid(self):
        result=analysis.metrics([record(10,10),record(20,20,start=200,read_bytes=1)],'59','boot')
        self.assertEqual(len(result['processes']),2)
        self.assertTrue(all(p['observed_delta']['read_bytes']==0 for p in result['processes']))

    def test_bad_shell_sample_is_not_used_as_a_counter_endpoint(self):
        bad=record(20,1000);bad['returncode']=1
        result=analysis.metrics([record(10,10),bad,record(30,30,read_bytes=300)],'59','boot')
        self.assertEqual(result['pressure_delta']['pswpin'],20)
        self.assertEqual(result['unavailable_sample_indices'],[1])
        self.assertTrue(result['pressure_intervals'][0]['spans_unavailable_sample'])

    def test_boot_change_and_cumulative_reset_are_rejected(self):
        wrong=record(20,20);wrong['output'][1]='otherboot'
        for second in (wrong,record(20,5)):
            with self.assertRaises(ValueError):analysis.metrics([record(10,10),second],'59','boot')

    def test_replayed_log_lines_do_not_double_count_LMK(self):
        raw=b"10-27 13:59:00.000 339 339 I lowmemorykiller: Kill 'sample' (1), uid 1000, oom_adj 905 to free 100kB\n"
        parts=[SimpleNamespace(name='logcat.txt',read_bytes=lambda:raw),SimpleNamespace(name='logcat-002.txt',read_bytes=lambda:raw)]
        result=analysis.logs(parts)
        self.assertEqual((result['LMK_count'],result['duplicate_full_lines']),(1,1))

    def test_missing_terminal_receipt_cannot_become_final_analysis(self):
        output=Mock();output.exists.return_value=False
        with patch.object(Path,'read_text',side_effect=FileNotFoundError('no terminal receipt')):
            with self.assertRaises(FileNotFoundError):analysis.analyze(output)
        output.open.assert_not_called()


if __name__=='__main__':unittest.main()

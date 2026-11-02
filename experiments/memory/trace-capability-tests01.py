"""Mocked inspection only. Never calls ADB or a remote shell."""
import sys
sys.dont_write_bytecode=True
import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock,patch
import unittest
spec=importlib.util.spec_from_file_location('tracecap',Path(__file__).with_name('trace-capability-inspect01.py'))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
BOOT='00000000-0000-0000-0000-000000000002'


def frame(key,value='',status='read',rc=0):
    return f'TC_BEGIN {key}\nTC_STATUS {status}\n{value}\nTC_RC {rc}\nTC_END {key}\n'.encode()


def absent():
    return frame('mounts')+frame('root0.visibility','absent_or_not_visible')+frame('root1.visibility','absent_or_not_visible')


def visible(event=True,format_readable=True,active=False,instance_active=False,more=False):
    raw=frame('mounts','1 2 0:1 / /sys/kernel/tracing rw - tracefs tracefs rw')+frame('root0.visibility','visible')
    for name in tool.STATE_FILES:
        value='1' if active and name=='tracing_on' else '0' if name in ('tracing_on','events/enable') else 'nop' if name=='current_tracer' else '256' if 'size' in name else '[boot]'
        raw+=frame('root0.state.'+name.replace('/','_'),value)
    raw+=frame('root0.available_events',tool.EVENTS[0] if event else '')
    for i in range(len(tool.EVENTS)):raw+=frame('root0.event'+str(i)+'.enable','0')
    raw+=frame('root0.oom_format','name: oom_score_adj_update\nID: 5\nformat:\n field:pid_t pid;' if format_readable else '',status='read' if format_readable else 'not_readable')
    if instance_active:
        for name,value in (('name','existing-observer'),('tracing_on','1'),('current_tracer','nop'),('events_enable','X')):
            raw+=frame('root0.instance0.'+name,value)
    raw+=frame('root0.instances_state',f'inspected={1 if instance_active else 0} additional={1 if more else 0}')
    raw+=frame('root1.visibility','absent_or_not_visible')
    return raw


def response(value,code=0):return SimpleNamespace(returncode=code,stdout=value,stderr=b'')


class TraceCapabilityControls(unittest.TestCase):
    def run_probe(self,raw,after=BOOT):
        runner=Mock(side_effect=[response((tool.SERIAL+'\n').encode()),response(('59\n'+BOOT+'\n0\n').encode()),response(raw),response(('59\n'+after+'\n0\n').encode())])
        return tool.inspect('never-executed-adb',BOOT,runner),runner

    def test_absent_facilities_are_not_tracing_readiness(self):
        report,runner=self.run_probe(absent())
        self.assertTrue(report['inspection_valid']);self.assertFalse(report['trace_root_observed'])
        self.assertFalse(report['capability_summary']['actual_tracing_readiness_proven'])
        self.assertEqual(report['capability_summary']['roots'][0]['oom_availability'],'unknown_not_readable_or_visible')
        self.assertEqual(runner.call_count,4)

    def test_available_event_requires_a_readable_format(self):
        for readable in (True,False):
            report,_=self.run_probe(visible(format_readable=readable))
            summary=report['capability_summary']['roots'][0]
            self.assertTrue(summary['oom_event_listed'])
            self.assertEqual(summary['oom_availability'],'available_metadata_observed' if readable else 'unknown_format_unreadable_or_incomplete')
            self.assertFalse(report['capability_summary']['actual_tracing_readiness_proven'])

    def test_absent_event_is_explicit_only_when_event_list_was_read(self):
        report,_=self.run_probe(visible(event=False,format_readable=False))
        self.assertEqual(report['capability_summary']['roots'][0]['oom_availability'],'absent_from_readable_event_list')

    def test_existing_active_root_and_instance_are_reported_as_conflicts(self):
        report,_=self.run_probe(visible(active=True,instance_active=True))
        summary=report['capability_summary']['conflict_summary']
        self.assertEqual(summary['status'],'active_tracing_observed_conflict')
        self.assertEqual(summary['active_locations'],['root0','root0.instance0'])

    def test_additional_uninspected_instances_keep_conflicts_unknown(self):
        report,_=self.run_probe(visible(more=True))
        summary=report['capability_summary']['conflict_summary']
        self.assertEqual(summary['status'],'unknown');self.assertIn('root0.additional_instances',summary['unknown_locations'])

    def test_identity_mismatch_stops_before_capability_queries(self):
        runner=Mock(side_effect=[response((tool.SERIAL+'\n').encode()),response(('58\n'+BOOT+'\n0\n').encode())])
        report=tool.inspect('never-executed-adb',BOOT,runner)
        self.assertFalse(report['inspection_valid']);self.assertEqual(runner.call_count,2);self.assertNotIn('reads',report)

    def test_post_boot_change_discards_unverified_capability_results(self):
        report,_=self.run_probe(visible(),after='00000000-0000-0000-0000-000000000013')
        self.assertFalse(report['identity_verified']);self.assertFalse(report['inspection_valid']);self.assertNotIn('reads',report)

    def test_unframed_duplicate_or_missing_visible_metadata_is_rejected(self):
        for raw in (b'extra\n'+absent(),absent()+frame('root0.visibility','visible'),frame('mounts')+frame('root0.visibility','visible')+frame('root1.visibility','absent_or_not_visible')):
            with self.assertRaises(ValueError):tool.parse_frames(raw)

    def test_generated_commands_have_fixed_identity_and_no_mutation_or_buffer_read(self):
        body=tool.script(BOOT)
        for forbidden in ('trace_pipe','/snapshot','/trace\n','/trace"','setprop','chmod','chown','mount ','umount','perfetto','atrace','sendevent','am start','pm grant','tee ','rm ','echo ','>'):
            self.assertNotIn(forbidden,body)
        self.assertIn("= '59'",body);self.assertIn(BOOT,body)
        self.assertIn('/proc/self/mountinfo',body)
        report,runner=self.run_probe(absent())
        for call in runner.call_args_list:
            argv=call.args[0]
            self.assertEqual(argv[1:3],['-s',tool.SERIAL]);self.assertEqual(call.kwargs['timeout'],10)
        with self.assertRaises(ValueError):tool.script("x'; touch /tmp/anything; '")

    def test_truncated_format_is_not_reported_readable(self):
        rows=tool.parse_frames(visible());rows['root0.oom_format']['potentially_truncated']=True
        summary=tool.summarize_metadata(rows)
        self.assertEqual(summary['roots'][0]['oom_availability'],'unknown_format_unreadable_or_incomplete')

    def test_pretty_printed_report_budget_cannot_become_an_availability_claim(self):
        with patch.object(tool,'MAX_REPORT',4000):
            report,_=self.run_probe(visible())
        self.assertFalse(report['inspection_valid']);self.assertNotIn('reads',report)
        self.assertEqual(report['status'],'report_bound_exceeded')


if __name__=='__main__':unittest.main()

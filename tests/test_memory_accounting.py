"""Accounting guard tests: shared mappings, PID races and incomplete captures."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('audit',Path(__file__).parents[1]/'tools/summarize_memory_audit.py')
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AccountingTest(unittest.TestCase):
    def fixture(self, root, changed=False, missing=False):
        system=('MEMINFO\nMemTotal: 1000 kB\nMemFree: 100 kB\nSwapTotal: 500 kB\nSwapFree: 200 kB\n'
                'VMSTAT\npgfault 1\npgmajfault 0\nZRAM\n204800 51200 65536\n')
        for name in ('system-before','system-after'):
            (root/(name+'.txt')).write_text(system)
        blocks=[]
        for pid in (10,20):
            fields=['S']+['0']*18+['123']
            first=f'{pid} (test worker) '+ ' '.join(fields)
            if changed and pid==20: fields[-1]='124'
            last=f'{pid} (test worker) '+ ' '.join(fields)
            maps='' if missing and pid==20 else 'Rss: 100 kB\nPss: 50 kB\nPrivate_Clean: 10 kB\nPrivate_Dirty: 20 kB\nSwapPss: 70 kB\n'
            blocks.append(f'PROCESS {pid}\n{first}\nworker\nVmSize: 1000 kB\nThreads: 1\nMAPTOTALS\n{maps}STAT_AFTER\n{last}\nEND_PROCESS\n')
        (root/'processes.txt').write_text(''.join(blocks)+'END_CENSUS\n')

    def test_shared_pages_and_compressed_swap_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            result=audit.summarize(root)
            self.assertEqual(result['census_totals_KiB']['Pss'],100)
            self.assertEqual(result['census_totals_KiB']['Rss'],200)
            self.assertEqual(result['snapshots'][0]['zram_physical_KiB'],64)
            self.assertEqual(result['snapshots'][0]['occupied_visible_KiB'],900)

    def test_pid_reuse_and_missing_maps_not_counted(self):
        for changed,missing in ((True,False),(False,True)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); self.fixture(root,changed,missing)
                result=audit.summarize(root)
                self.assertEqual(result['userspace_processes'],1)
                self.assertEqual(len(result['omitted']),1)

    def test_truncated_census_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            path=root/'processes.txt'; path.write_text(path.read_text().replace('END_CENSUS',''))
            with self.assertRaises(ValueError): audit.summarize(root)


if __name__=='__main__':
    unittest.main()

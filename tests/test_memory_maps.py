import importlib.util
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('maps',Path(__file__).parents[1]/'tools/summarize_memory_maps.py')
maps=importlib.util.module_from_spec(spec)
spec.loader.exec_module(maps)


class MemoryMapsTest(unittest.TestCase):
    def test_anonymous_image_and_memfd_jit_labels(self):
        self.assertEqual(maps.category('[anon:dalvik-/system/framework/boot-framework.art]'),'art_image')
        self.assertEqual(maps.category('/memfd:jit-cache (deleted)'),'art_jit')
        self.assertEqual(maps.category('[anon:dalvik-main space (region space)]'),'managed_heap')

    def test_exclusive_groups_preserve_totals(self):
        text=('1000-2000 rw-p 00000000 00:00 0 [anon:libc_malloc]\n'
              'Rss: 100 kB\nPss: 50 kB\nSwapPss: 10 kB\n'
              '2000-3000 rw-p 00000000 00:00 0 [anon:dalvik-/system/boot.art]\n'
              'Rss: 200 kB\nPss: 60 kB\nSwapPss: 20 kB\n')
        result=maps.summarize(text)
        self.assertEqual(result['total_KiB']['Pss'],110)
        self.assertEqual(sum(x['Pss'] for x in result['groups_KiB'].values()),110)
        self.assertEqual(result['total_KiB']['SwapPss'],30)

    def test_real_file_names_are_not_thread_stacks(self):
        for name in ['/system/priv-app/InProcessNetworkStack/InProcessNetworkStack.apk',
                     '/system/priv-app/InProcessNetworkStack/InProcessNetworkStack.apk (deleted)']:
            self.assertEqual(maps.category(name),'apk_jar')
        for name in ['/system/lib/libunwindstack.so','/system/lib/libutilscallstack.so',
                     '/system/lib/libunwindstack.so (deleted)','/system/lib/libjemalloc.so']:
            self.assertEqual(maps.category(name),'native_library')

    def test_stack_labels_and_dalvik_auxiliary_names_stay_separate(self):
        for name in ['[stack]','[stack:123]','[anon:stack_and_tls:123]',
                     '[anon:thread signal stack]']:
            self.assertEqual(maps.category(name),'stack_labelled')
        self.assertEqual(maps.category('[anon:dalvik-thread local mark stack]'),'art_metadata_other')
        self.assertEqual(maps.category('/data/local/tmp/stack-inspection-output'),'other_file')

    def test_incomplete_tail_rejected(self):
        with self.assertRaises(ValueError):
            maps.summarize('1000-2000 rw-p 00000000 00:00 0\nRss: 1 kB\n')


if __name__=='__main__':
    unittest.main()

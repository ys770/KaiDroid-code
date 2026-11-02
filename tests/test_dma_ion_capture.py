import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from summarize_dma_ion_capture import dma_buffers,ion_heaps

DMA='''Dma-buf Objects:
size flags mode count exp_name
00004096 00000002 00000007 00000010 ion
 Attached Devices:
 kgsl-3d0
 kgsl-3d0
Total 2 devices attached

00004096 00000002 00000007 00000002 ion
 Attached Devices:
Total 0 devices attached
Total 2 objects, 8192 bytes
'''


class AllocationControls(unittest.TestCase):
    def test_equal_sizes_are_distinct_rows_and_attachment_duplicates_not_allocations(self):
        rows=dma_buffers(DMA)
        self.assertEqual(len(rows),2)
        self.assertEqual(sum(r['size_bytes'] for r in rows),8192)
        self.assertEqual(rows[0]['reported_file_refs'],10)
        self.assertEqual(rows[0]['attached_devices'],['kgsl-3d0','kgsl-3d0'])

    def test_wrong_total_rejected(self):
        with self.assertRaises(ValueError):dma_buffers(DMA.replace('8192 bytes','4096 bytes'))

    def test_missing_or_wrong_attachment_footer_rejected(self):
        for text in [DMA.replace('Total 2 devices attached\n',''),DMA.replace('Total 2 devices attached','Total 1 devices attached')]:
            with self.assertRaises(ValueError):dma_buffers(text)

    def test_physical_aliases_count_once_client_handles_remain_overlapping(self):
        ion='''client pid size
kernel 1 4096
process 22 4096
orphaned allocations (info is from last known client):
 total orphaned 0
 total 4096
Memory Map
kernel 0x0x1000 0x0x1fff 4096 (0x1000)
22 0x0x1000 0x0x1fff 4096 (0x1000)
'''
        heap=ion_heaps(ion)[0]
        self.assertEqual(heap['sum_client_handle_bytes_not_unique'],8192)
        self.assertEqual(heap['printed_physical_range_union_bytes'],4096)
        self.assertEqual(heap['printed_physical_range_rows'],2)

    def test_truncated_heap_and_invalid_inclusive_extent_rejected(self):
        with self.assertRaises(ValueError):ion_heaps('client pid size\n total 0\n')
        text='client pid size\n total orphaned 0\n total 4096\nMemory Map\nx 0x1000 0x1fff 4095 (0xfff)\n'
        with self.assertRaises(ValueError):ion_heaps(text)


if __name__=='__main__':unittest.main()

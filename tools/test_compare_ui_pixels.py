import tempfile
import unittest
from pathlib import Path
from PIL import Image
from compare_ui_pixels import compare

class PixelTests(unittest.TestCase):
    def test_exact_and_single_channel_difference(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            image=Image.new('RGB',(2,2),'black');image.save(p/'a.png');image.save(p/'b.png')
            self.assertTrue(compare(p/'a.png',p/'b.png',p/'same')['exact_pixel_match'])
            image.putpixel((0,0),(0,0,1));image.save(p/'b.png')
            result=compare(p/'a.png',p/'b.png',p/'different')
            self.assertEqual(result['changed_pixels'],1)
            self.assertEqual(Image.open(p/'different/mismatch-map.png').getpixel((0,0)),(255,0,0))
            regions=compare(p/'a.png',p/'b.png',p/'regions',{'top':[0,0,2,1], 'bottom':[0,1,2,2]})
            self.assertFalse(regions['exact_pixel_match'])
            self.assertEqual(regions['regions']['top']['delta_histogram'],{'1':1})
            self.assertEqual(regions['regions']['bottom']['max_channel_delta'],0)
            with self.assertRaises(ValueError):
                compare(p/'a.png',p/'b.png',p/'invalid',{'outside':[0,0,3,2]})
            self.assertFalse((p/'invalid').exists())
    def test_dimensions_are_not_rescaled(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            Image.new('RGB',(2,2)).save(p/'a.png');Image.new('RGB',(3,2)).save(p/'b.png')
            with self.assertRaises(ValueError):compare(p/'a.png',p/'b.png',p/'out')
            self.assertFalse((p/'out').exists())

if __name__=='__main__':unittest.main()

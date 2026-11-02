import unittest
from trial_clock_parallel38 import packages,uid,require_fresh,PACKAGE,ORIGINAL

class ClockTrialGuards(unittest.TestCase):
    def test_inventory_exact_identity(self):
        self.assertEqual(packages('package:'+ORIGINAL),{ORIGINAL})
        with self.assertRaises(ValueError):packages('Error: unavailable')
    def test_fresh_rejects_existing_and_provider_alias(self):
        require_fresh({ORIGINAL},'unrelated provider')
        for inventory,providers in [({ORIGINAL,PACKAGE},''),({ORIGINAL},'['+PACKAGE+']'),(set(),'')]:
            with self.assertRaises(ValueError):require_fresh(inventory,providers)
    def test_uid_exact_unambiguous(self):
        self.assertEqual(uid('  userId=1000\n'),1000)
        for value in ['','userId=1000\nuserId=10055','userId=1000garbage']:
            with self.assertRaises(ValueError):uid(value)

if __name__=='__main__':unittest.main()

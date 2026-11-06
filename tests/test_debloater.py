import unittest
from src.domain.debloater import Debloater

class TestDebloater(unittest.TestCase):
    def test_debloater_preserves_whitelist(self):
        debloater = Debloater(
            blacklist=['com.ts.car.updater', 'com.roco.canbus'],
            whitelist=['com.roco.canbus']
        )
        result = debloater.filter_packages(['com.ts.car.updater', 'com.roco.canbus'])
        self.assertIn('com.ts.car.updater', result)
        self.assertNotIn('com.roco.canbus', result)

if __name__ == '__main__':
    unittest.main()

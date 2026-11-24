import unittest
from security.simulations import port_scan, repeated_logins, save_results
from tempfile import TemporaryDirectory
from pathlib import Path

class SimulationTests(unittest.TestCase):
    def test_scan_high(self):
        e = port_scan()[0]
        self.assertEqual(e['severity'], 'HIGH')
        self.assertFalse(e['engine_backed'])

    def test_login_high(self):
        self.assertEqual(repeated_logins()[0]['severity'], 'HIGH')
        self.assertEqual(repeated_logins(failures=20)[0]['severity'], 'CRITICAL')

    def test_bad_port(self):
        with self.assertRaises(ValueError):
            port_scan(ports=[65536])

    def test_reports(self):
        with TemporaryDirectory() as d:
            save_results(port_scan() + repeated_logins(), d)
            self.assertTrue((Path(d) / 'security_alerts.jsonl').is_file())
            self.assertIn('PASS', (Path(d) / 'security_test_results.csv').read_text())

if __name__ == '__main__':
    unittest.main()

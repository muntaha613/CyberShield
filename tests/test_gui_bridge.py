import unittest
from security.gui_bridge import run_scenario, event_for_table


class BridgeTests(unittest.TestCase):
    def test_port_scan(self):
        alert = run_scenario('port_scan')[0]
        self.assertEqual(alert['severity'], 'HIGH')
        self.assertFalse(alert['engine_backed'])
        self.assertEqual(event_for_table(alert)['scenario'], 'PORT_SCAN')

    def test_login_critical(self):
        alert = run_scenario('repeated_login', failures=20)[0]
        self.assertEqual(alert['severity'], 'CRITICAL')

    def test_invalid_name(self):
        with self.assertRaises(ValueError):
            run_scenario('unknown')

    def test_missing_engine(self):
        with self.assertRaises(ValueError):
            run_scenario('high_traffic')

"""Policy persistence tests; independent of PySide6 availability."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'gui'))
from rule_store import read_rules, write_rules, normalize_rule


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'config' / 'firewall_rules.json'

    def test_no_policy_is_empty(self):
        self.assertEqual(read_rules(self.path), [])

    def test_roundtrip_and_order(self):
        data = [
            {'ip':'*', 'port':22, 'protocol':'TCP', 'action':'DENY', 'enabled':True},
            {'ip':'192.168.1.10','port':0,'protocol':'ANY','action':'ALLOW','enabled':False},
        ]
        write_rules(self.path, data)
        self.assertEqual(read_rules(self.path),data)
        self.assertEqual(json.loads(self.path.read_text())['version'],1)

    def test_normalize_engine_rule_ignores_ephemeral_id(self):
        rule = {'id':8,'ip':'*','port':22,'protocol':'tcp','action':'deny','enabled':True}
        expected = {'ip':'*','port':22,'protocol':'TCP','action':'DENY','enabled':True}
        self.assertEqual(normalize_rule(rule),expected)

    def test_invalid_rule_not_written(self):
        with self.assertRaises(ValueError):
            write_rules(self.path,[{'ip':'*', 'port':70000, 'action':'DENY', 'protocol':'TCP'}])
        self.assertFalse(self.path.exists())

    def test_corrupt_policy_detected(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text('{bad')
        with self.assertRaises(json.JSONDecodeError):
            read_rules(self.path)

    def test_replace_is_atomic_and_no_temp_left(self):
        item = {'ip':'*','port':80,'protocol':'TCP','action':'DENY','enabled':True}
        write_rules(self.path, [item])
        item['enabled'] = False
        write_rules(self.path, [item])
        self.assertEqual(read_rules(self.path)[0]['enabled'],False)
        self.assertFalse(self.path.with_name(self.path.name+'.tmp').exists())

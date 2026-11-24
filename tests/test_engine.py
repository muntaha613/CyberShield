"""Black-box smoke test for preserved C++17 protocol."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EngineSmokeTest(unittest.TestCase):
    def test_generate_rule_and_stats(self):
        subprocess.run(['make'], cwd=ROOT, check=True, capture_output=True)
        # Generate 1000 packets; every packet must be denied by wildcard rule.
        commands = 'ADD * 0 ANY DENY\nGENERATE 1000\nSTATS\nRULES\nQUIT\n'
        output = subprocess.run([str(ROOT/'engine'/'cybershield')], input=commands,
                                text=True, capture_output=True, timeout=15, check=True)
        events = [json.loads(line) for line in output.stdout.splitlines()]
        packets = [e for e in events if e.get('type') == 'packet']
        self.assertEqual(len(packets), 1000)
        self.assertTrue(all(p['decision'] == 'DENY' and p['rule'] == 1 for p in packets))
        self.assertTrue(any(e.get('type') == 'rules' and len(e['items']) == 1 for e in events))
        self.assertTrue(any(e.get('type') == 'ready' for e in events))


if __name__ == '__main__':
    unittest.main()

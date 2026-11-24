"""Regression for semaphore ordering: queued packets are not counted as processed before a token is available."""
import json
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'engine' / 'cybershield'


class SemaphoreOrderRegression(unittest.TestCase):
    def test_waiting_for_token_does_not_increment_processed(self):
        proc = subprocess.Popen([str(EXE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            proc.stdin.write('RATE 1\nGENERATE 12\n')
            proc.stdin.flush()
            time.sleep(0.14)  # RATE 1 needs ~1 second to make its first token
            proc.stdin.write('STATS\n')
            proc.stdin.flush()
            # The command loop answers STATS independently of blocked workers.
            messages = []
            while True:
                line = proc.stdout.readline()
                self.assertTrue(line, 'engine exited before producing its STATS event')
                item = json.loads(line)
                messages.append(item)
                if item.get('type') == 'stats':
                    stats = item
                    break
            self.assertEqual(stats['rate_limit'], 1)
            self.assertEqual(stats['processed'], 0,
                'The engine must not count packets before a semaphore token is acquired')
            self.assertGreaterEqual(stats['rate_waiting'], 1)
            proc.stdin.write('QUIT\n')
            proc.stdin.flush()
            remainder, errors = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0, errors)
            packets = [x for x in messages if x.get('type') == 'packet']
            packets.extend(json.loads(x) for x in remainder.splitlines() if x.strip())
            packets = [x for x in packets if x.get('type') == 'packet']
            self.assertEqual(len(packets), 12, 'QUIT must drain the packet queue without loss')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()

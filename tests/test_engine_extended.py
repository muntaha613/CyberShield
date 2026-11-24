"""Multithreading / OS-feature tests for the C++ engine (Abeeha).

Run:  python3 -m unittest discover -s tests -v
Each test feeds commands to the engine over stdin and parses the JSON lines it prints.
"""
import json
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = str(ROOT / 'engine' / 'cybershield')


def run_engine(commands, timeout=60):
    """Run the engine with a command script; return (events, elapsed_seconds)."""
    t0 = time.time()
    out = subprocess.run([ENGINE], input=commands, text=True, capture_output=True, timeout=timeout, check=True)
    return [json.loads(l) for l in out.stdout.splitlines()], time.time() - t0


def of_type(events, typ):
    return [e for e in events if e.get('type') == typ]


class EngineBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['make'], cwd=ROOT, check=True, capture_output=True)


class TestLoad(EngineBuild):
    """Test case: multithreading under 100 / 1,000 / 10,000 simulated packets."""

    def check_load(self, n):
        ev, secs = run_engine(f'GENERATE {n}\nSTATS\nQUIT\n')
        pk = of_type(ev, 'packet')
        self.assertEqual(len(pk), n, 'every generated packet must be processed exactly once')
        ids = [p['id'] for p in pk]
        self.assertEqual(len(set(ids)), n, 'no packet processed twice (no race / duplicate)')
        self.assertEqual(sorted(ids), list(range(1, n + 1)), 'no packet lost')
        print(f'\n  {n:>6} packets processed in {secs:.2f}s')

    def test_100_packets(self): self.check_load(100)
    def test_1000_packets(self): self.check_load(1000)
    def test_10000_packets(self): self.check_load(10000)   # larger than the 3000-slot queue: needs back-pressure


class TestStats(EngineBuild):
    def test_stats_fields_and_consistency(self):
        ev, _ = run_engine('GENERATE 500\nSTATS\nWORKERS\nQUIT\n')
        st = of_type(ev, 'stats')[0]
        for key in ('generated', 'processed', 'allowed', 'denied', 'queued', 'workers',      # V2 fields
                    'busy', 'capacity', 'utilization', 'peak_queue', 'mode', 'target_workers'):  # new fields
            self.assertIn(key, st)
        self.assertEqual(st['capacity'], 3000)
        self.assertEqual(st['workers'], 4)
        self.assertEqual(st['mode'], 'FIXED')
        self.assertLessEqual(st['processed'], st['generated'])
        self.assertEqual(st['processed'], st['allowed'] + st['denied'])
        self.assertTrue(0 <= st['utilization'] <= 100)

    def test_per_worker_stats_sum_to_total(self):
        # Use a long-lived session so WORKERS can be asked after processing finishes.
        p = subprocess.Popen([ENGINE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        p.stdin.write('GENERATE 3000\n'); p.stdin.flush()
        lines = []
        deadline = time.time() + 20
        while time.time() < deadline:
            l = p.stdout.readline()
            if not l: break
            lines.append(json.loads(l))
            if len([e for e in lines if e['type'] == 'packet']) == 3000: break
        time.sleep(0.2)
        p.stdin.write('WORKERS\nQUIT\n'); p.stdin.flush()
        rest = [json.loads(l) for l in p.stdout.read().splitlines()]
        p.wait(timeout=10)
        w = of_type(rest, 'workers')[0]
        self.assertEqual(sum(i['processed'] for i in w['items']), 3000)
        self.assertEqual(w['alive'], 4)
        self.assertEqual(len(w['items']), 4)


class TestRules(EngineBuild):
    def test_first_match_wins_and_default_allow(self):
        cmds = 'ADD * 22 TCP DENY\nADD * 0 ANY ALLOW\nGENERATE 2000\nQUIT\n'
        ev, _ = run_engine(cmds)
        for p in of_type(ev, 'packet'):
            if p['port'] == 22 and p['protocol'] == 'TCP':
                self.assertEqual((p['decision'], p['rule']), ('DENY', 1))
            else:
                self.assertEqual((p['decision'], p['rule']), ('ALLOW', 2))

    def test_default_allow_without_rules(self):
        ev, _ = run_engine('GENERATE 300\nQUIT\n')
        self.assertTrue(all(p['decision'] == 'ALLOW' and p['rule'] == 0 for p in of_type(ev, 'packet')))

    def test_toggle_and_delete(self):
        ev, _ = run_engine('ADD * 0 ANY DENY\nTOGGLE 1\nGENERATE 200\nDELETE 1\nRULES\nQUIT\n')
        self.assertTrue(all(p['decision'] == 'ALLOW' for p in of_type(ev, 'packet')))
        self.assertEqual(of_type(ev, 'rules')[-1]['items'], [])

    def test_invalid_commands(self):
        ev, _ = run_engine('ADD * 99999 TCP DENY\nFOO\nMODE X\nSETWORKERS 99\nQUIT\n')
        self.assertEqual(len(of_type(ev, 'error')), 4)


class TestPool(EngineBuild):
    def test_set_workers_and_mode(self):
        ev, _ = run_engine('SETWORKERS 6\nWORKERS\nSETWORKERS 2\nWORKERS\nMODE FIXED\nWORKERS\nQUIT\n')
        w = of_type(ev, 'workers')
        self.assertEqual([x['alive'] for x in w], [6, 2, 4])

    def test_adaptive_scales_up_under_load_and_still_correct(self):
        ev, _ = run_engine('MODE ADAPTIVE\nSETWORKERS 2\nMODE ADAPTIVE\nDELAY 300\nGENERATE 6000\nQUIT\n', timeout=120)
        self.assertEqual(len(of_type(ev, 'packet')), 6000)
        self.assertTrue(any(e['direction'] == 'up' for e in of_type(ev, 'scale')), 'adaptive pool should grow under load')

    def test_benchmark_fixed_vs_adaptive(self):
        ev, _ = run_engine('BENCH 4000 300\nSTATS\nQUIT\n', timeout=120)
        b = of_type(ev, 'benchmark')[0]
        fixed, adaptive = b['results']
        self.assertEqual((fixed['mode'], adaptive['mode']), ('FIXED', 'ADAPTIVE'))
        self.assertEqual(fixed['peak_workers'], 4)
        self.assertGreater(adaptive['peak_workers'], 4)
        self.assertLess(adaptive['seconds'], fixed['seconds'])       # more workers => faster under heavy per-packet cost
        self.assertEqual(of_type(ev, 'stats')[0]['processed'], 0)    # benchmark does not pollute dashboard counters
        print(f"\n  BENCH {b['count']} pkts @ {b['delay_us']}us: FIXED {fixed['seconds']:.2f}s ({fixed['throughput']} pps) "
              f"vs ADAPTIVE {adaptive['seconds']:.2f}s ({adaptive['throughput']} pps, peak {adaptive['peak_workers']} workers)")


class TestRateControl(EngineBuild):
    """Semaphore-based rate control: workers need a token from a semaphore refilled at RATE packets/s."""

    def test_rate_limit_slows_processing_and_loses_nothing(self):
        proc = subprocess.Popen([ENGINE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        proc.stdin.write('RATE 500\nGENERATE 250\n'); proc.stdin.flush()
        t0, n = time.time(), 0
        while n < 250:
            line = proc.stdout.readline()
            self.assertTrue(line, 'engine ended early')
            if json.loads(line)['type'] == 'packet': n += 1
        secs = time.time() - t0
        proc.stdin.write('STATS\nRATE 0\nQUIT\n'); proc.stdin.flush()
        rest = [json.loads(l) for l in proc.stdout.read().splitlines()]
        proc.wait(timeout=10)
        st = of_type(rest, 'stats')[0]
        self.assertEqual(st['rate_limit'], 500)
        self.assertEqual(st['processed'], 250)
        self.assertGreater(secs, 0.35, 'rate limit of 500 pps should make 250 packets take about 0.5 s')
        self.assertLess(secs, 2.0)
        print(f'\n  RATE 500: 250 packets in {secs:.2f}s (~{250 / secs:.0f} pps)')

    def test_rate_off_is_fast_and_invalid_rate_errors(self):
        ev, secs = run_engine('RATE 100\nRATE 0\nGENERATE 2000\nRATE -5\nRATE abc\nQUIT\n')
        self.assertEqual(len(of_type(ev, 'packet')), 2000)
        self.assertEqual(len(of_type(ev, 'error')), 2)
        self.assertLess(secs, 3)

    def test_quit_with_tiny_rate_does_not_hang(self):
        ev, secs = run_engine('RATE 1\nGENERATE 300\nQUIT\n', timeout=15)
        self.assertEqual(len(of_type(ev, 'packet')), 300)   # shutdown drains at full speed
        self.assertLess(secs, 5)


class TestPriority(EngineBuild):
    """Priority packets overtake the normal backlog but cannot starve it (aging after 8 in a row)."""

    def test_priority_packets_jump_the_queue(self):
        proc = subprocess.Popen([ENGINE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        proc.stdin.write('SETWORKERS 1\nDELAY 500\nGENERATE 2000\n'); proc.stdin.flush()
        while json.loads(proc.stdout.readline())['type'] != 'packet':   # wait until the backlog is being worked
            pass
        proc.stdin.write('PRIORITY 20\nSTATS\nQUIT\n'); proc.stdin.flush()
        ev = [json.loads(l) for l in proc.stdout.read().splitlines()]
        proc.wait(timeout=30)
        pk = of_type(ev, 'packet')
        hi = [i for i, p in enumerate(pk) if p['priority'] == 'HIGH']
        self.assertEqual(len(hi), 20)
        self.assertLessEqual(hi[-1], 20 + 20 // 8 + 3, 'priority packets should finish near the front of the backlog')
        ids = [p['id'] for p in pk]
        self.assertEqual(sorted(ids), list(range(2, 2021)), 'no packet lost or duplicated (packet 1 was read while waiting)')
        st = of_type(ev, 'stats')[0]
        self.assertGreater(st['priority_queued'] + st['priority_processed'], 0)

    def test_normal_traffic_not_starved(self):
        # Aging: while priority packets are waiting, a normal packet is served after every 8 priority packets.
        proc = subprocess.Popen([ENGINE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        proc.stdin.write('SETWORKERS 1\nDELAY 500\nGENERATE 500\n'); proc.stdin.flush()
        while json.loads(proc.stdout.readline())['type'] != 'packet':
            pass
        proc.stdin.write('PRIORITY 80\nQUIT\n'); proc.stdin.flush()
        pk = of_type([json.loads(l) for l in proc.stdout.read().splitlines()], 'packet')
        proc.wait(timeout=30)
        hi = [i for i, p in enumerate(pk) if p['priority'] == 'HIGH']
        run = best = 0
        for i in range(hi[0], hi[-1] + 1):
            run = run + 1 if pk[i]['priority'] == 'HIGH' else 0
            best = max(best, run)
        self.assertLessEqual(best, 8, 'never more than 8 priority packets in a row while normal traffic waits')

    def test_priority_fields_and_validation(self):
        ev, _ = run_engine('PRIORITY 5\nPRIORITY 9999\nSTATS\nQUIT\n')
        st = of_type(ev, 'stats')[0]
        for key in ('priority_queued', 'priority_processed', 'avg_wait_us_normal', 'avg_wait_us_priority', 'rate_limit', 'rate_waiting'):
            self.assertIn(key, st)
        self.assertTrue(all(p['priority'] in ('HIGH', 'NORMAL') for p in of_type(ev, 'packet')))
        self.assertEqual(st['processed'], st['allowed'] + st['denied'])


class TestShutdown(EngineBuild):
    def test_clean_exit_and_repeat_runs(self):
        for _ in range(15):   # repeated runs help expose deadlocks / lost wake-ups
            ev, _ = run_engine('GENERATE 500\nMODE ADAPTIVE\nSETWORKERS 3\nQUIT\n', timeout=15)
            self.assertEqual(len(of_type(ev, 'packet')), 500)


if __name__ == '__main__':
    unittest.main()

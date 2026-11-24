"""UI text and unbiased map-sampling regression tests; no PySide6 required."""
import unittest
from datetime import datetime, timezone, timedelta
from gui.display_logic import (format_local_time, format_local_hms,
    format_scenario_time, sample_packet_route, queue_readout,
    processing_readout)

class TestDisplayLogic(unittest.TestCase):
    def test_12_hour_clock(self):
        dt = datetime(2026, 11, 24, 15, 17, 13)
        self.assertEqual(format_local_time(dt), '2026-11-24  03:17:13 PM')
        self.assertEqual(format_local_hms(dt), '03:17:13 PM')

    def test_scenario_utc_to_pakistan_time(self):
        pkt = timezone(timedelta(hours=5))
        self.assertEqual(format_scenario_time('2026-11-24T10:02:14+00:00', pkt),
                         '03:02:14 PM')
        self.assertEqual(format_scenario_time('not-a-date'), 'not-a-date')

    def test_decision_sampling_no_red_bias(self):
        import random
        rng = random.Random(20261124)
        # Correlated/periodic packet colors must not correlate with sampling.
        flags = [(index % 12 == 0) for index in range(1, 12001)]
        picked = [blocked for blocked in flags if sample_packet_route(rng.random())]
        self.assertGreater(len(picked), 350)
        self.assertAlmostEqual(sum(picked) / len(picked), sum(flags) / len(flags), delta=.04)
        self.assertFalse(sample_packet_route(.5, interval=24))
        self.assertTrue(sample_packet_route(.01, interval=24))

    def test_queue_format_consistent_across_reports(self):
        stats = {'type': 'stats', 'queued': 125, 'capacity': 3000, 'peak_queue': 3000}
        workers = {'type': 'workers', 'queued': 125, 'capacity': 3000, 'peak_queue': 3000}
        self.assertEqual(queue_readout(stats), queue_readout(workers))
        self.assertIn('peak observed by engine 3,000', queue_readout(stats))

    def test_processing_status_never_fakes_progress(self):
        self.assertIn('READY', processing_readout(0, 0))
        self.assertIn('PROCESSING', processing_readout(1000, 450))
        self.assertIn('COMPLETE', processing_readout(1000, 1000))

class TestRateInputGuard(unittest.TestCase):
    def test_user_entry_survives_periodic_stats(self):
        from gui.display_logic import RateInputGuard
        g = RateInputGuard()
        g.edited()
        self.assertFalse(g.reported(0))
        g.submit(200)
        self.assertFalse(g.reported(0))
        self.assertEqual(g.pending, 200)
        self.assertTrue(g.reported(200))
        self.assertIsNone(g.pending)
        self.assertTrue(g.reported(200))

    def test_failed_send_can_cancel(self):
        from gui.display_logic import RateInputGuard
        g = RateInputGuard()
        g.submit(500)
        g.cancel()
        self.assertIsNone(g.pending)

if __name__ == "__main__":
    unittest.main()

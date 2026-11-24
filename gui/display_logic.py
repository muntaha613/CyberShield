"""Pure display logic for the CyberShield simulator.

No Qt imports: this can be tested without a desktop session.  Every number is
based on engine JSON or recorded events; display code never invents statistics.
"""
from datetime import datetime


def format_local_time(when=None):
    """Return a 12-hour, local date/time with an unambiguous AM/PM suffix."""
    when = datetime.now().astimezone() if when is None else when
    return when.strftime('%Y-%m-%d  %I:%M:%S %p')


def format_local_hms(when=None):
    when = datetime.now().astimezone() if when is None else when
    return when.strftime('%I:%M:%S %p')


def format_scenario_time(utc_timestamp, target_tz=None):
    """Convert an ISO-8601 UTC scenario timestamp to the local display zone."""
    try:
        parsed = datetime.fromisoformat(str(utc_timestamp).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return str(utc_timestamp)  # do not silently assume an unknown zone
        if target_tz is None:
            local = parsed.astimezone()
        else:
            local = parsed.astimezone(target_tz)
        return local.strftime('%I:%M:%S %p')
    except (TypeError, ValueError, OverflowError):
        return str(utc_timestamp)


def sample_packet_route(random_fraction, interval=24):
    """Bernoulli sample independent of decision, packet ID and packet order.

    Pass a draw from a dedicated pseudorandom stream. A 1/24 sampling rate
    lets packet-color proportions track the underlying decisions over time.
    """
    return interval > 0 and 0 <= float(random_fraction) < 1.0 / interval


def queue_readout(data):
    """Identical queue text regardless of STATS or WORKERS response type."""
    queued = max(0, int(data.get('queued', 0)))
    capacity = max(1, int(data.get('capacity', 3000)))
    peak = max(queued, int(data.get('peak_queue', 0)))
    return (f'{queued:,} / {capacity:,} packets queued  •  '
            f'peak observed by engine {peak:,}  •  '
            f'{100 * min(queued, capacity) / capacity:.1f}% of normal-queue capacity')


def processing_readout(generated, processed):
    generated, processed = max(0, int(generated)), max(0, int(processed))
    if not generated:
        return 'READY  •  Waiting for simulated packets'
    if processed < generated:
        return f'PROCESSING  •  {processed:,} / {generated:,} packets completed'
    return (f'COMPLETE  •  {processed:,} packets processed. '
            'Recent map animations may still be fading.')

class RateInputGuard:
    """Keep unsubmitted/pending user changes out of periodic STATS refreshes.

    An observed server value, rather than button clicks, confirms changes.
    """
    def __init__(self):
        self.dirty = False
        self.pending = None

    def edited(self):
        self.dirty = True

    def submit(self, value):
        self.pending = int(value)
        self.dirty = False

    def reported(self, engine_value):
        value = int(engine_value)
        if self.pending is not None:
            if value != self.pending:
                return False
            self.pending = None
            return True
        return not self.dirty

    def cancel(self):
        self.pending = None

"""GUI-safe interface to CyberShield's standalone security simulations.

No PySide6 dependency. The high-traffic run starts a separate engine process and
can block; call it from a QThread/worker instead of the GUI main thread.
"""
from pathlib import Path
from .simulations import port_scan, repeated_logins, engine_traffic

SCENARIOS = ('port_scan', 'repeated_login', 'high_traffic')


def run_scenario(name, *, engine_path=None, packet_count=1000,
                 ports=None, failures=12):
    """Return security alert dictionaries; never submit real network traffic.

    name: port_scan | repeated_login | high_traffic
    high_traffic requires a compiled engine path and runs a SEPARATE engine.
    """
    if name == 'port_scan':
        return port_scan(ports=ports)
    if name == 'repeated_login':
        return repeated_logins(failures=failures)
    if name == 'high_traffic':
        if engine_path is None:
            raise ValueError('engine_path is required for high_traffic')
        return engine_traffic(Path(engine_path).resolve(), count=packet_count)
    raise ValueError(f'Unknown scenario: {name}; choose from {SCENARIOS}')


def event_for_table(event):
    """Convert a structured alert into display-ready table fields."""
    return {
        'time': event['timestamp'],
        'scenario': event['scenario'],
        'severity': event['severity'],
        'details': event['description'],
        'source': event['source_ip'],
        'target': event['target_ip'],
        'simulation': event['simulation'],
        'engine_backed': event['engine_backed'],
    }

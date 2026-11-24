"""Synthetic event scenarios and a real C++ engine high-traffic harness.

No network packets are transmitted. Scan/login events are modeled only;
they are NOT inserted into the C++ firewall engine.
"""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')


def alert(scenario, severity, source_ip, target_ip, description, evidence, engine_backed=False):
    if severity not in SEVERITIES:
        raise ValueError('Invalid severity')
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'type': 'security_alert', 'scenario': scenario,
        'severity': severity, 'source_ip': source_ip, 'target_ip': target_ip,
        'description': description, 'evidence': evidence,
        'engine_backed': engine_backed, 'simulation': True,
    }


def port_scan(source_ip='192.168.1.50', target_ip='192.168.1.100', ports=None):
    """Model a sweep of destination ports; never touches the network."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080]
    ports = list(ports)
    if any(not isinstance(p, int) or p < 1 or p > 65535 for p in ports):
        raise ValueError('Ports must be integers between 1 and 65535')
    unique_count = len(set(ports))
    severity = 'HIGH' if unique_count >= 10 else 'MEDIUM' if unique_count >= 5 else 'LOW'
    return [alert('PORT_SCAN', severity, source_ip, target_ip,
                  'Synthetic multi-port connection attempts',
                  {'attempts': len(ports), 'unique_destination_ports': unique_count,
                   'ports': ports, 'thresholds': {'medium': 5, 'high': 10}})]


def repeated_logins(source_ip='192.168.1.60', target_ip='192.168.1.100', failures=12):
    """Model failed authentication events; no login requests are sent."""
    if failures < 0:
        raise ValueError('failures must be nonnegative')
    severity = 'CRITICAL' if failures >= 20 else 'HIGH' if failures >= 10 else 'MEDIUM' if failures >= 5 else 'LOW'
    return [alert('REPEATED_LOGIN', severity, source_ip, target_ip,
                  'Synthetic repeated failed authentication attempts',
                  {'failed_attempts': failures, 'service': 'SSH (simulated)',
                   'thresholds': {'medium': 5, 'high': 10, 'critical': 20}})]


def engine_traffic(engine_path, count=1000, timeout=60):
    """Run a separate real engine process with its existing GENERATE protocol.

    The production GUI's running engine is NOT modified. Worker packet lines
    are consumed from stdout; final STATS are taken after QUIT drains queue.
    """
    if not 1 <= count <= 20000:
        raise ValueError('count must be 1..20000 for one engine command')
    path = Path(engine_path)
    if not path.is_file():
        raise FileNotFoundError(f'Engine not found: {path}. Run make in the CyberShield project folder first.')
    started = time.monotonic()
    proc = subprocess.run([str(path)], input=f'GENERATE {count}\nQUIT\n',
                          capture_output=True, text=True, timeout=timeout, check=True)
    seconds = max(time.monotonic() - started, 1e-6)
    events = [json.loads(line) for line in proc.stdout.splitlines()]
    packets = [e for e in events if e.get('type') == 'packet']
    accepted = next((e for e in events if e.get('type') == 'ack'), None)
    if not accepted:
        raise RuntimeError('No engine acknowledgement')
    allowed = sum(e['decision'] == 'ALLOW' for e in packets)
    blocked = sum(e['decision'] == 'DENY' for e in packets)
    if allowed + blocked != len(packets):
        raise RuntimeError('Unexpected packet decision from engine')
    return [alert('HIGH_TRAFFIC', 'HIGH' if len(packets) >= 1000 else 'MEDIUM',
                  'synthetic generator', 'C++ packet queue',
                  'Actual isolated engine process completed simulated packet workload',
                  {'requested': count, 'processed': len(packets), 'allowed': allowed,
                   'blocked': blocked, 'elapsed_seconds': round(seconds, 4),
                   'observed_packets_per_second': round(len(packets) / seconds, 2),
                   'engine_ack': accepted['message'],
                   'note': 'Elapsed time includes process startup, JSON output and shutdown; not pure engine throughput.'},
                  engine_backed=True)]


def save_results(events, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with (out / 'security_alerts.jsonl').open('w', encoding='utf-8') as f:
        for event in events:
            f.write(json.dumps(event, sort_keys=True) + '\n')
    with (out / 'security_test_results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'expected_condition', 'actual_observation', 'result', 'engine_backed'])
        for e in events:
            ev = e['evidence']
            if e['scenario'] == 'PORT_SCAN':
                expected = 'At least 10 unique ports => HIGH'
                actual = f"{ev['unique_destination_ports']} unique ports => {e['severity']}"
                passed = (ev['unique_destination_ports'] >= 10 and e['severity'] == 'HIGH')
            elif e['scenario'] == 'REPEATED_LOGIN':
                expected = 'At least 10 failures => HIGH or CRITICAL'
                actual = f"{ev['failed_attempts']} failures => {e['severity']}"
                passed = ev['failed_attempts'] >= 10 and e['severity'] in ('HIGH', 'CRITICAL')
            else:
                expected = 'Processed packets equal accepted/generated packets'
                actual = f"Processed {ev['processed']}, requested {ev['requested']}"
                passed = ev['processed'] == ev['requested']
            writer.writerow([e['scenario'], expected, actual, 'PASS' if passed else 'FAIL', e['engine_backed']])
    return out


def main():
    parser = argparse.ArgumentParser(description='CyberShield security simulation (no real attacks)')
    parser.add_argument('--scenario', choices=['scan', 'login', 'traffic', 'all'], default='all')
    parser.add_argument('--engine', type=Path, help='Path to compiled engine/cybershield, required for traffic/all')
    parser.add_argument('--count', type=int, default=1000, help='Traffic packet count: 1..20000')
    parser.add_argument('--out', default='security_results')
    args = parser.parse_args()
    events = []
    if args.scenario in ('scan', 'all'):
        events += port_scan()
    if args.scenario in ('login', 'all'):
        events += repeated_logins()
    if args.scenario in ('traffic', 'all'):
        if args.engine is None:
            parser.error('--engine is required for traffic or all')
        events += engine_traffic(args.engine, args.count)
    saved = save_results(events, args.out)
    for e in events:
        print(f"{e['scenario']}: {e['severity']} | engine-backed={e['engine_backed']} | {e['evidence']}")
    print(f'Reports saved to: {saved.resolve()}')


if __name__ == '__main__':
    main()

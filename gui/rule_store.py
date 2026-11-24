"""Durable, ordered firewall policy storage for the CyberShield simulator.

The C++ engine owns active rules during a session. This GUI-side store writes
user-selected policy to disk and replays it when a fresh engine starts.
"""
import json
import os
from pathlib import Path

POLICY_VERSION = 1


def normalize_rule(item):
    if not isinstance(item, dict):
        raise ValueError('Rule must be an object')
    ip = str(item.get('ip', '')).strip()
    port = int(item.get('port', 0))
    protocol = str(item.get('protocol', 'ANY')).upper()
    action = str(item.get('action', 'DENY')).upper()
    enabled = item.get('enabled', True)
    if not ip or any(c.isspace() for c in ip) or '\n' in ip:
        raise ValueError('Invalid source IP')
    if not 0 <= port <= 65535:
        raise ValueError('Invalid port')
    if protocol not in ('ANY', 'TCP', 'UDP'):
        raise ValueError('Invalid protocol')
    if action not in ('ALLOW', 'DENY'):
        raise ValueError('Invalid action')
    if not isinstance(enabled, bool):
        raise ValueError('Enabled must be a boolean')
    return {'ip': ip, 'port': port, 'protocol': protocol,
            'action': action, 'enabled': enabled}


def read_rules(path):
    path = Path(path)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('version') != POLICY_VERSION:
        raise ValueError('Unrecognized policy format')
    rows = data.get('rules')
    if not isinstance(rows, list):
        raise ValueError('Rules must be a list')
    return [normalize_rule(r) for r in rows]


def write_rules(path, rows):
    path = Path(path)
    policies = [normalize_rule(row) for row in rows]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    try:
        with tmp.open('w', encoding='utf-8') as dest:
            json.dump({'version': POLICY_VERSION, 'rules': policies}, dest, indent=2)
            dest.write('\n')
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return policies

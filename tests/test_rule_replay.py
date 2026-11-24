"""A saved GUI rule policy must be restorable using the untouched C++ commands."""
import json
import subprocess
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'gui'))
from rule_store import normalize_rule


class RuleReplayTests(unittest.TestCase):
    def test_restore_order_and_disabled_state_in_engine(self):
        rules = [
            {'ip':'*','port':22,'protocol':'TCP','action':'DENY','enabled':True},
            {'ip':'*','port':0,'protocol':'ANY','action':'ALLOW','enabled':False},
            {'ip':'192.168.1.99','port':8080,'protocol':'UDP','action':'DENY','enabled':True},
        ]
        commands=[]
        for index, rule in enumerate(rules,1):
            commands.append('ADD {ip} {port} {protocol} {action}'.format(**rule))
            if not rule['enabled']:
                commands.append(f'TOGGLE {index}')
        commands+=['RULES','QUIT']
        result=subprocess.run([str(ROOT/'engine'/'cybershield')],
                              input='\n'.join(commands)+'\n',text=True,capture_output=True,check=True,timeout=10)
        last=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        final=[e for e in last if e.get('type')=='rules'][-1]
        self.assertEqual([normalize_rule(r) for r in final['items']],rules)

"""Exercise the real GUI handler functions without a Qt display or PySide6 wheel.

The test extracts only the target App methods from source; its mocks represent
spin boxes, labels, progress bars and chart helpers (not engine logic).
"""
import ast
import types
import unittest
from pathlib import Path
from gui.display_logic import RateInputGuard, queue_readout

SRC = Path(__file__).resolve().parents[1] / 'gui' / 'app.py'
code = ast.parse(SRC.read_text(encoding='utf-8'))
app_class = next(node for node in code.body if isinstance(node, ast.ClassDef) and node.name == 'App')
methods = ('rate_input_edited', 'apply_rate_limit', 'update_queue_readout')
functions = [node for node in app_class.body
             if isinstance(node, ast.FunctionDef) and node.name in methods]
assert len(functions) == len(methods)
ns = {'queue_readout': queue_readout}
exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])), str(SRC), 'exec'), ns)

class FakeSpin:
    def __init__(self, value): self._value = value; self.interpreted = False
    def interpretText(self): self.interpreted = True
    def value(self): return self._value

class FakeLabel:
    def __init__(self): self.text = ''
    def setText(self, v): self.text = str(v)

class FakeBar:
    def __init__(self): self.range = None; self.value = None
    def setRange(self, *v): self.range = v
    def setValue(self, v): self.value = v

class FakeHistory:
    def __init__(self): self.values = []
    def push(self, value): self.values.append(value)

class TestGUIInteraction(unittest.TestCase):
    def fake_app(self):
        ob = types.SimpleNamespace()
        ob._rate_guard = RateInputGuard()
        ob._syncing_rate_value = False
        ob.rate_limit_spin = FakeSpin(200)
        ob.worker_rate_status = FakeLabel()
        ob.sent = []
        def send(command): ob.sent.append(command); return True
        ob.send = send
        ob.rate_input_edited = types.MethodType(ns['rate_input_edited'], ob)
        ob.apply_rate_limit = types.MethodType(ns['apply_rate_limit'], ob)
        ob.update_queue_readout = types.MethodType(ns['update_queue_readout'], ob)
        ob.queue_bar, ob.queue_title, ob.queue_label = FakeBar(), FakeLabel(), FakeLabel()
        ob.queue_history = FakeHistory()
        return ob

    def test_apply_captures_rate_before_stale_stats(self):
        gui = self.fake_app()
        gui.rate_input_edited(200)
        self.assertFalse(gui._rate_guard.reported(0))
        gui.apply_rate_limit()
        self.assertTrue(gui.rate_limit_spin.interpreted)
        self.assertEqual(gui.sent, ['RATE 200'])
        self.assertEqual(gui._rate_guard.pending, 200)
        self.assertFalse(gui._rate_guard.reported(0))
        self.assertTrue(gui._rate_guard.reported(200))

    def test_queue_readout_identical_from_both_report_types(self):
        gui = self.fake_app()
        stats = {'type': 'stats', 'queued': 250, 'peak_queue': 3000, 'capacity': 3000}
        workers = {**stats, 'type': 'workers'}
        gui.update_queue_readout(stats, True)
        first = gui.queue_label.text
        gui.update_queue_readout(workers, False)
        self.assertEqual(gui.queue_label.text, first)
        self.assertEqual(gui.queue_bar.value, 250)
        self.assertEqual(gui.queue_history.values, [250])

if __name__ == '__main__': unittest.main()

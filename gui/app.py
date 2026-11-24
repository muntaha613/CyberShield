"""CyberShield: PySide6 SOC interface for the concurrent C++17 firewall simulator."""
import csv
import json
import math
import random
import sys
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QProcess, QTimer, QPointF, QRectF, Signal, QThread
from PySide6.QtGui import QColor, QPainter, QPen, QBrush, QPainterPath, QFont, QLinearGradient, QPolygonF
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QStackedWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLineEdit, QSpinBox, QComboBox, QFileDialog,
    QMessageBox, QProgressBar, QScrollArea, QSizePolicy, QGraphicsDropShadowEffect,
)

ROOT = Path(__file__).resolve().parents[1]
# FATIMA_SCENARIO_GUI_V1 — local security module lives at project root.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from security.gui_bridge import run_scenario, event_for_table
from rule_store import read_rules, write_rules, normalize_rule
from display_logic import (
    format_local_time, format_local_hms, format_scenario_time,
    sample_packet_route, queue_readout, processing_readout, RateInputGuard,
)
CYAN = '#FFC24A'             # primary allowed-traffic gold
GOLD = '#FFCE71'
RED = '#FF5360'              # denied packets retain a distinct red
GREEN = '#5FE8AF'            # verified online status
MUTED = '#AAA6A0'
BG = '#0E0D0E'
PANEL = '#1A191A'

STYLE = r''' 
QWidget { background:#0E0D0E; color:#F4F0EA; font-family:'DejaVu Sans'; font-size:12px; }
QFrame#sidebar { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #181614,stop:1 #100F0F); border-right:1px solid #694B26; }
QFrame#panel { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #24201C,stop:1 #181717); border:1px solid #75542C; border-radius:13px; }
QFrame#metric { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #352A1F,stop:0.55 #27211B,stop:1 #191818); border:1px solid #A17A3F; border-radius:11px; }
QLabel { background:transparent; }
QLabel#brand { color:#FFE2AC; font-size:20px; font-weight:900; }
QLabel#hero { color:#FFF6EA; font-size:21px; font-weight:900; }
QLabel#section { color:#FFF4DF; font-size:14px; font-weight:800; }
QLabel#muted { color:#AAA7A4; }
QLabel#micro { color:#E6B965; font-size:10px; font-weight:700; }
QLabel#value { color:#FFF0C9; font-size:27px; font-weight:900; }
QLabel#statuschip { color:#65F2B9; border:1px solid #8F6E32; border-radius:12px; padding:7px 12px; background:#1D1B19; font-size:10px; font-weight:800; }
QLabel#brandmark { color:#FFC458; font-size:28px; font-weight:900; }
QPushButton { background:#24211E; border:1px solid #75542C; border-radius:8px; padding:8px 12px; color:#F8E1B5; font-weight:600; }
QPushButton:hover { background:#383029; border-color:#E6AB43; }
QPushButton:pressed { background:#6B4D27; }
QPushButton:disabled { color:#91887B; border-color:#443A2D; }
QPushButton#nav { background:transparent; border:0; border-left:3px solid transparent; border-radius:5px; text-align:left; padding:12px 13px; color:#DDD6CB; font-weight:600; }
QPushButton#nav:hover { background:#29231D; color:#FFE9BF; }
QPushButton#nav:checked { background:#3C2E1D; color:#FFDA87; border-left:3px solid #FFB93C; }
QPushButton#primary { color:#1A130C; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #FFE39B,stop:0.6 #FFC14F,stop:1 #F2A52A); border:1px solid #FFDE87; font-weight:900; padding:10px 15px; }
QPushButton#primary:hover { background:#FFD879; border-color:#FFE4A0; }
QPushButton#danger { color:#FF9098; border-color:#82434B; }
QLineEdit,QSpinBox,QComboBox { background:#181717; border:1px solid #826236; border-radius:7px; padding:8px; color:#FFE7BA; selection-background-color:#8D6126; }
QLineEdit:focus,QSpinBox:focus,QComboBox:focus { border-color:#FFC858; }
QTableWidget { background:#131313; alternate-background-color:#211E1A; border:1px solid #56442E; border-radius:6px; gridline-color:#383129; selection-background-color:#65451D; }
QHeaderView::section { background:#29221A; color:#FFD67D; border:0; border-bottom:1px solid #72502C; padding:7px; font-weight:800; }
QTableWidget::item { padding:4px; }
QScrollBar:vertical { background:#151312; width:10px; }
QScrollBar::handle:vertical { background:#78603C; border-radius:5px; }
QScrollBar:horizontal { background:#151312; height:10px; }
QScrollBar::handle:horizontal { background:#78603C; border-radius:5px; }
QProgressBar { background:#181818; border:1px solid #6F5430; border-radius:5px; text-align:center; height:17px; }
QProgressBar::chunk { background:#FFC553; border-radius:4px; }
QScrollArea { border:0; background:transparent; }
'''



def label(text, kind=None):
    w = QLabel(str(text))
    if kind:
        w.setObjectName(kind)
    return w


def panel(title=None):
    f = QFrame()
    f.setObjectName('panel')
    l = QVBoxLayout(f)
    l.setContentsMargins(16, 14, 16, 14)
    l.setSpacing(10)
    if title:
        title_bar = QHBoxLayout()
        title_bar.setSpacing(9)
        title_accent = QFrame()
        title_accent.setFixedSize(4, 18)
        title_accent.setStyleSheet('background:#FFBD44;border:0;border-radius:2px;')
        title_bar.addWidget(title_accent)
        title_bar.addWidget(label(title, 'section'), 1)
        l.addLayout(title_bar)
    return f, l


def table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.verticalHeader().hide()
    t.verticalHeader().setDefaultSectionSize(30)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    t.horizontalHeader().setStretchLastSection(True)
    t.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    t.setTextElideMode(Qt.TextElideMode.ElideRight)
    return t


def row_insert(t, values, max_rows=500):
    t.insertRow(0)
    for i, v in enumerate(values):
        item = QTableWidgetItem(str(v))
        item.setToolTip(str(v))
        if str(v) == 'DENY' or str(v) == 'ERROR':
            item.setForeground(QColor(RED))
        elif str(v) == 'ALLOW':
            item.setForeground(QColor(GREEN))
        t.setItem(0, i, item)
    if t.rowCount() > max_rows:
        t.removeRow(t.rowCount()-1)


class Sparkline(QWidget):
    def __init__(self, color=CYAN, parent=None):
        super().__init__(parent)
        self.color = QColor(color)
        self.points = deque([0]*45, maxlen=45)
        self.setMinimumHeight(105)

    def push(self, value):
        self.points.append(max(0, float(value)))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(QPen(QColor('#54422B'), 1))
        for j in range(1, 5):
            y = j*h/5
            p.drawLine(0, int(y), w, int(y))
        vals = list(self.points)
        high = max(max(vals, default=1), 1)
        coords = [QPointF(i*w/max(1, len(vals)-1), h-8-(v/high)*(h-20)) for i, v in enumerate(vals)]
        if len(coords) < 2:
            return
        path = QPainterPath(coords[0])
        for point in coords[1:]:
            path.lineTo(point)
        fill = QPainterPath(path)
        fill.lineTo(coords[-1].x(), h)
        fill.lineTo(0, h)
        fill.closeSubpath()
        grad = QLinearGradient(0, 0, 0, h)
        c = QColor(self.color)
        c.setAlpha(105)
        grad.setColorAt(0, c)
        c.setAlpha(4)
        grad.setColorAt(1, c)
        p.fillPath(fill, grad)
        p.setPen(QPen(self.color, 2))
        p.drawPath(path)


# Stylized, schematic landmass outlines; deliberately not a precise geopolitical map.
CONTINENTS = [
    [(-168,69),(-146,72),(-128,61),(-122,51),(-128,44),(-117,31),(-110,28),(-103,20),(-97,16),(-88,20),(-83,27),(-81,33),(-72,45),(-60,50),(-55,59),(-81,63),(-100,72),(-125,73)],
    [(-81,12),(-71,10),(-61,4),(-51,-2),(-47,-14),(-54,-25),(-63,-39),(-70,-55),(-77,-41),(-79,-21),(-73,-5)],
    [(-53,59),(-42,62),(-38,75),(-48,83),(-59,81),(-61,70)],
    [(-11,36),(-10,47),(-2,51),(12,54),(27,60),(34,70),(50,71),(62,60),(90,56),(110,59),(131,52),(149,61),(169,59),(179,48),(154,36),(139,35),(121,23),(110,9),(103,1),(92,7),(77,9),(66,24),(50,30),(42,38),(30,36),(25,43),(15,45),(6,43),(-3,36)],
    [(-18,34),(-1,37),(17,31),(33,22),(43,12),(49,-10),(34,-20),(28,-34),(19,-35),(11,-25),(5,-7),(-5,4),(-15,15)],
    [(112,-12),(125,-13),(139,-16),(153,-27),(149,-39),(133,-43),(116,-34)],
    [(44,-12),(51,-15),(49,-25),(44,-26)],
    [(95,21),(108,20),(120,13),(124,3),(114,-7),(104,-4),(100,8)],
    [(129,32),(138,36),(143,43),(146,37),(139,32)],
]
NODES = [(-74,40),(-118,34),(-46,-23),(-0.1,51),(12,48),(31,30),(37,56),(55,25),(78,22),(103,1),(116,39),(139,35),(151,-33),(18,-34),(-99,19)]


class NetworkMap(QWidget):
    """Schematic animation of sampled C++ firewall events, not IP geolocation.

    Routes are visual replays with a short fade, not live network captures.
    Equal-probability sampling avoids overstating the number of DENY packets.
    """
    routeStarted = Signal(object)
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(250)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.events = deque(maxlen=16)
        self.pending = deque(maxlen=20)
        self.rng = random.Random(42)
        self.next_spawn = 0.0
        self.coastlines = []
        geography = ROOT / 'gui' / 'world_polygons.json'
        if geography.exists():
            try:
                self.coastlines = json.loads(geography.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate)
        self.timer.start(45)

    def add_packet(self, blocked, packet=None):
        # Identical treatment for ALLOW and DENY. Sampling is decided by
        # the GUI packet handler, *independent* of the firewall decision.
        # Retain the actual packet metadata with the synthetic visualization.
        self.pending.append((bool(blocked), dict(packet or {})))

    def project(self, lon, lat):
        """Keep the map's aspect ratio stable when CyberShield is maximized."""
        w = max(1, self.width())
        h = max(1, self.height())
        draw_width = min(max(1, w - 32), max(1, h - 48) * 2.35)
        draw_height = draw_width / 2.35
        offset_x = (w - draw_width) / 2.0
        offset_y = (h - draw_height) / 2.0 - 5.0
        return QPointF(offset_x + (lon + 180) / 360 * draw_width,
                       offset_y + (82 - lat) / 140 * draw_height)


    def animate(self):
        now = time.monotonic()
        if self.pending and now >= self.next_spawn:
            blocked, packet = self.pending.popleft()
            a, b = self.rng.sample(range(len(NODES)), 2)
            self.events.append((a, b, now, blocked))
            self.routeStarted.emit(packet)
            self.next_spawn = now + 0.18
        while self.events and now - self.events[0][2] > 5.5:
            self.events.popleft()
        self.update()

    def paintEvent(self, event):
        """Paint synthetic route animations without obscuring map geography."""
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        background = QLinearGradient(0, 0, w, h)
        background.setColorAt(0, QColor('#171513'))
        background.setColorAt(1, QColor('#0F0D0C'))
        p.fillRect(self.rect(), background)
        p.setPen(QPen(QColor(146, 103, 43, 60), 0.7))
        for x in range(0, w, 44):
            p.drawLine(x, 0, x, h)
        for y in range(0, h, 44):
            p.drawLine(0, y, w, y)

        polygons = self.coastlines if self.coastlines else CONTINENTS
        for polygon in polygons:
            if len(polygon) < 3:
                continue
            shape = QPainterPath(self.project(*polygon[0]))
            for coordinate in polygon[1:]:
                shape.lineTo(self.project(*coordinate))
            shape.closeSubpath()
            p.fillPath(shape, QColor('#252422'))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor('#81715C'), 0.95))
            p.drawPath(shape)

        for lon, lat in NODES:
            point = self.project(lon, lat)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(255, 195, 77, 67))
            p.drawEllipse(point, 5.0, 5.0)
            p.setBrush(QColor('#FFD47D'))
            p.drawEllipse(point, 2.0, 2.0)

        now = time.monotonic()
        for source, target, started, is_denied in self.events:
            elapsed = now - started
            if elapsed >= 5.5:
                continue
            # Animate the new packet first; then retain a softly fading *historical*
            # trail for a few seconds. No routes appear without actual packet events.
            strength = 1.0 if elapsed < 1.5 else (0.6 if elapsed < 3.7
                         else max(0.0, 0.6 * (5.5 - elapsed) / 1.8))
            source_point = self.project(*NODES[source])
            target_point = self.project(*NODES[target])
            control = QPointF(
                (source_point.x() + target_point.x()) / 2,
                min(source_point.y(), target_point.y())
                - min(50, max(12, abs(source_point.x() - target_point.x()) * 0.14)),
            )
            route = QPainterPath(source_point)
            route.quadTo(control, target_point)
            base = QColor(RED if is_denied else CYAN)

            # A translucent outer stroke gives the curved line a glow.
            # NoBrush is essential: otherwise paths can become filled wedges.
            p.setBrush(Qt.BrushStyle.NoBrush)
            halo = QColor(base)
            halo.setAlpha(int((95 if is_denied else 112) * strength))
            p.setPen(QPen(halo, 4.5, Qt.PenStyle.SolidLine,
                          Qt.PenCapStyle.RoundCap))
            p.drawPath(route)
            core = QColor(base)
            core.setAlpha(int(255 * strength))
            p.setPen(QPen(core, 1.7 if is_denied else 2.2, Qt.PenStyle.SolidLine,
                          Qt.PenCapStyle.RoundCap))
            p.drawPath(route)

            moving_point = route.pointAtPercent(min(elapsed / 1.45, 1.0))
            p.setPen(Qt.PenStyle.NoPen)
            glow = QColor(base)
            glow.setAlpha(int(130 * strength))
            p.setBrush(glow)
            p.drawEllipse(moving_point, 6.3, 6.3)
            p.setBrush(core)
            p.drawEllipse(moving_point, 3.0, 3.0)

        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QColor('#CBAF82'))
        p.setFont(QFont('DejaVu Sans', 9))
        p.drawText(14, h - 11, 'SAMPLED ENGINE DECISIONS   •   NOT LIVE GEOLOCATION')



class Gauge(QWidget):
    """Engine-derived SOC dial. The label tells viewers what is measured."""
    def __init__(self, color=CYAN, title='', center='—'):
        super().__init__()
        self.color=QColor(color); self.title=title
        self.center=center; self.percent=0
        self.setMinimumHeight(116)

    def set_value(self, percent, center=None, color=None):
        self.percent = max(0., min(100., float(percent)))
        if center is not None: self.center=str(center)
        if color is not None: self.color=QColor(color)
        self.update()

    def paintEvent(self, event):
        p=QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w,h=self.width(),self.height()
        size=min(w-38,h-18,130)
        side=max(48,size)
        rect=QRectF((w-side)/2,(h-side)/2+5,side,side)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor('#50483D'),9,Qt.PenStyle.SolidLine,Qt.PenCapStyle.RoundCap))
        p.drawArc(rect,210*16,-240*16)
        p.setPen(QPen(self.color,9,Qt.PenStyle.SolidLine,Qt.PenCapStyle.RoundCap))
        p.drawArc(rect,210*16,int(-240*16*self.percent/100))
        p.setPen(QColor('#FFF7E6'))
        font=QFont('DejaVu Sans',16)
        font.setBold(True)
        p.setFont(font)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.center)


class TrafficChart(QWidget):
    """Recent observed ALLOW and DENY packet rates, sampled from C++ stats."""
    def __init__(self):
        super().__init__()
        self.accepted = deque([0.] * 38, maxlen=38)
        self.denied = deque([0.] * 38, maxlen=38)
        self._accepted_samples = deque(maxlen=3)
        self._denied_samples = deque(maxlen=3)
        self.setMinimumHeight(165)

    def push(self, allowed_per_second, denied_per_second):
        self._accepted_samples.append(max(0., float(allowed_per_second)))
        self._denied_samples.append(max(0., float(denied_per_second)))
        self.accepted.append(sum(self._accepted_samples) / len(self._accepted_samples))
        self.denied.append(sum(self._denied_samples) / len(self._denied_samples))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        left, right, top, bottom = 43, max(60, w - 11), 13, max(40, h - 25)
        high = max(1., *self.accepted, *self.denied)
        p.setFont(QFont('DejaVu Sans', 8))
        for i in range(5):
            frac = i / 4
            y = top + (bottom - top) * frac
            p.setPen(QPen(QColor('#50412E'), 1))
            p.drawLine(left, int(y), right, int(y))
            p.setPen(QColor('#BCA985'))
            p.drawText(1, int(y + 4), f'{high * (1 - frac):.1f}' if high < 5 else f'{high * (1 - frac):.0f}')
        for j, t in ((0, '-24s'), (0.5, '-12s'), (1, 'now')):
            x = left + (right - left) * j
            p.setPen(QColor('#BCA985'))
            p.drawText(int(x - 12), h - 5, t)
        for values, stroke in ((self.accepted, CYAN), (self.denied, RED)):
            vals = list(values)
            if len(vals) < 2:
                continue
            pts = [QPointF(left + i * (right - left) / (len(vals)-1),
                           bottom - v / high * (bottom - top)) for i, v in enumerate(vals)]
            path = QPainterPath(pts[0])
            for pt in pts[1:]:
                path.lineTo(pt)
            fill = QPainterPath(path)
            fill.lineTo(pts[-1].x(), bottom)
            fill.lineTo(left, bottom)
            fill.closeSubpath()
            gradient = QLinearGradient(0, top, 0, bottom)
            tint = QColor(stroke)
            tint.setAlpha(94)
            gradient.setColorAt(0, tint)
            tint.setAlpha(2)
            gradient.setColorAt(1, tint)
            p.fillPath(fill, gradient)
            halo = QColor(stroke)
            halo.setAlpha(70)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(halo, 5))
            p.drawPath(path)
            p.setPen(QPen(QColor(stroke), 2.0))
            p.drawPath(path)



class Metric(QFrame):
    def __init__(self, title, accent=CYAN):
        super().__init__()
        self.setObjectName('metric')
        l = QVBoxLayout(self)
        l.setContentsMargins(15, 13, 15, 13)
        l.setSpacing(5)
        icon_titles = {'GENERATED':'⬡', 'PROCESSED':'▤', 'ALLOWED':'✓',
                       'BLOCKED':'⊘', 'IN QUEUE':'◷', 'WORKERS':'⚙'}
        top = QHBoxLayout()
        symbol = label(icon_titles.get(title.upper(), '◈'))
        symbol.setStyleSheet(f'color:{accent};font-size:18px;font-weight:900;')
        top.addWidget(symbol)
        t = label(title.upper(), 'micro')
        top.addWidget(t)
        top.addStretch()
        l.addLayout(top)
        self.number = label('0', 'value')
        self.number.setStyleSheet(f'color:{accent};font-size:27px;font-weight:800;')
        l.addWidget(self.number)
        self.sub = label('C++ engine', 'muted')
        l.addWidget(self.sub)

    def set(self, n):
        self.number.setText(f'{n:,}')


class ScenarioWorker(QThread):
    """Run the isolated simulation engine away from Qt's event loop."""
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, name, count=1000, failures=12, parent=None):
        super().__init__(parent)
        self.name = name
        self.count = count
        self.failures = failures

    def run(self):
        try:
            events = run_scenario(
                self.name, engine_path=ROOT / 'engine' / 'cybershield',
                packet_count=self.count, failures=self.failures
            )
            self.completed.emit(events)
        except Exception as exc:
            self.failed.emit(str(exc))


class ShieldMark(QWidget):
    """Gold shield crest rendered natively by Qt; stays sharp at all DPIs."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(36, 41)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center_x = self.width() / 2
        path = QPainterPath(QPointF(center_x, 3))
        path.lineTo(QPointF(31, 9))
        path.lineTo(QPointF(29, 22))
        path.quadTo(QPointF(27, 30), QPointF(center_x, 38))
        path.quadTo(QPointF(9, 30), QPointF(7, 22))
        path.lineTo(QPointF(5, 9))
        path.closeSubpath()
        color = QLinearGradient(0, 0, 34, 38)
        color.setColorAt(0, QColor('#FFE1A2'))
        color.setColorAt(1, QColor('#A76515'))
        painter.fillPath(path, QBrush(QColor('#302312')))
        painter.setPen(QPen(QBrush(color), 2.9))
        painter.drawPath(path)
        painter.setPen(QPen(QColor('#FFCE74'), 2.0))
        painter.drawLine(QPointF(center_x, 12), QPointF(center_x, 29))
        painter.drawLine(QPointF(12, 17), QPointF(center_x, 23))
        painter.drawLine(QPointF(24, 17), QPointF(center_x, 23))


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('CyberShield  |  SOC Command Center  |  Simulation')
        self.resize(1380, 910)
        self.setMinimumSize(1040, 640)
        self.setStyleSheet(STYLE)
        self.buffer = ''
        self.metrics = {}
        self.rules = []
        self.rule_policy_path = ROOT / 'config' / 'firewall_rules.json'
        try:
            self.saved_rules = read_rules(self.rule_policy_path)
            self.rule_load_error = None
        except (OSError, ValueError, TypeError) as exc:
            self.saved_rules = []
            self.rule_load_error = str(exc)
        self.restoring_rules = False
        self.rules_restored = False
        self.recent_packets = []  # retain full session for CSV export
        self.last_processed = 0
        self.last_blocked = 0
        self.last_allowed = 0
        self.event_counter = 0
        self._map_sample_rng = random.Random(20261124)
        self.logs_history = []  # retain all session events for CSV export
        self.scenario_worker = None
        self.scenario_history = []
        self._rate_guard = RateInputGuard()
        self._syncing_rate_value = False
        self._benchmark_packets_reported = 0
        self.proc = QProcess(self)
        self.proc.setProgram(str(ROOT/'engine'/'cybershield'))
        self.proc.setWorkingDirectory(str(ROOT))
        self.proc.readyReadStandardOutput.connect(self.read_engine)
        self.proc.readyReadStandardError.connect(self.read_error)
        self.proc.errorOccurred.connect(self.engine_error)
        self.proc.finished.connect(self.engine_finished)
        self.build_ui()
        self.proc.start()
        self.poll = QTimer(self)
        self.poll.timeout.connect(lambda: self.send('STATS'))
        self.poll.start(650)
        self.worker_poll = QTimer(self)
        self.worker_poll.timeout.connect(
            lambda: self.send('WORKERS') if self.stack.currentIndex() == 4 else None
        )
        self.worker_poll.start(1100)
        self.clock = QTimer(self)
        self.clock.timeout.connect(self.update_clock)
        self.clock.start(1000)
        self.update_clock()

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        main = QHBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName('sidebar')
        sidebar.setFixedWidth(256)
        s = QVBoxLayout(sidebar)
        s.setContentsMargins(12, 20, 12, 17)
        s.setSpacing(5)
        brandbar = QHBoxLayout()
        brandbar.setSpacing(8)
        crest = ShieldMark()
        brandbar.addWidget(crest)
        self.brand_label = label('CYBERSHIELD', 'brand')
        self.brand_label.setMinimumWidth(170)
        brandbar.addWidget(self.brand_label, 1)
        s.addLayout(brandbar)
        tagline = label('SECURITY  /  OS SIMULATOR', 'micro')
        tagline.setStyleSheet('color:#D4B787;font-size:10px;')
        s.addWidget(tagline)
        s.addSpacing(28)
        self.stack = QStackedWidget()
        self.nav = []
        names = ['Command Center', 'Packet Inspector', 'Firewall Rules', 'Attack Simulator', 'Worker Monitor', 'Activity Logs']
        icons = ['◉', '⌕', '⬡', '⚡', '▥', '≡']
        for i, (name, icon) in enumerate(zip(names, icons)):
            b = QPushButton(f'{icon}   {name}')
            b.setObjectName('nav')
            b.setCheckable(True)
            b.clicked.connect(lambda checked=False, idx=i: self.navigate(idx))
            s.addWidget(b)
            self.nav.append(b)
        s.addStretch()
        s.addWidget(label('SIMULATION MODE', 'micro'))
        disclaimer = label('Synthetic packets only.\nNo real network filtering.', 'muted')
        disclaimer.setWordWrap(True)
        s.addWidget(disclaimer)
        s.addSpacing(12)
        s.addWidget(label('ENGINE  •  C++17 / MULTITHREADED', 'micro'))
        main.addWidget(sidebar)
        content = QWidget()
        c = QVBoxLayout(content)
        c.setContentsMargins(18, 13, 18, 13)
        c.setSpacing(12)
        header = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(2)
        left.addWidget(label('SECURITY OPERATIONS COMMAND CENTER', 'hero'))
        left.addWidget(label('C++17 CONCURRENT FIREWALL  /  SIMULATION MONITOR', 'micro'))
        header.addLayout(left)
        header.addStretch()
        self.status = label('● CONNECTING ENGINE', 'statuschip')
        header.addWidget(self.status)
        header.addSpacing(18)
        self.time_label = label('', 'micro')
        header.addWidget(self.time_label)
        c.addLayout(header)
        self.pages = [self.overview(), self.inspector(), self.rules_page(), self.simulator(), self.workers_page(), self.logs_page()]
        for page in self.pages:
            self.stack.addWidget(page)
        c.addWidget(self.stack, 1)
        main.addWidget(content, 1)
        self.navigate(0)

    def page(self, title, description):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(13)
        h = QHBoxLayout()
        info = QVBoxLayout()
        info.addWidget(label(title, 'section'))
        info.addWidget(label(description, 'muted'))
        h.addLayout(info)
        h.addStretch()
        l.addLayout(h)
        return w, l, h

    def overview(self):
        # CYBERSHIELD_GUI_ONLY_FINAL_2026 — SOC visuals and packet-count controls only.
        w, l, h = self.page(
            'REAL-TIME FIREWALL MONITOR',
            'SYNTHETIC TRAFFIC  •  ENGINE-VERIFIED STATISTICS  •  NO LIVE INTERCEPTION',
        )
        controls = QHBoxLayout()
        controls.setSpacing(9)
        controls.addWidget(label('PACKETS', 'micro'))
        self.dashboard_count = QSpinBox()
        self.dashboard_count.setRange(1, 20000)
        self.dashboard_count.setValue(100)
        self.dashboard_count.setSingleStep(100)
        self.dashboard_count.setMinimumWidth(90)
        self.dashboard_count.setToolTip('Select 1 to 20,000 synthetic packets')
        controls.addWidget(self.dashboard_count)
        for title, count in [('100', 100), ('500', 500), ('1,000', 1000), ('5,000', 5000)]:
            preset = QPushButton(title)
            preset.setToolTip(f'Select {count:,} packets')
            preset.clicked.connect(
                lambda checked=False, n=count: self.dashboard_count.setValue(n)
            )
            controls.addWidget(preset)
        run = QPushButton('▶  RUN PACKETS')
        run.setObjectName('primary')
        run.setToolTip('Send GENERATE to the existing C++ firewall engine')
        run.clicked.connect(self.run_dashboard_batch)
        controls.addWidget(run)
        controls.addStretch()
        l.addLayout(controls)
        self.dashboard_feedback = label(
            'Select a packet count and run a synthetic C++ engine workload.', 'muted'
        )
        l.addWidget(self.dashboard_feedback)
        self.dashboard_progress = label('READY  •  Waiting for simulated packets', 'micro')
        self.dashboard_progress.setWordWrap(True)
        l.addWidget(self.dashboard_progress)

        metrics = QGridLayout()
        metrics.setSpacing(8)
        self.cards = {}
        for i, (key, title, accent) in enumerate([
            ('generated', 'Generated', CYAN),
            ('processed', 'Processed', GOLD),
            ('allowed', 'Allowed', GREEN),
            ('denied', 'Blocked', RED),
            ('queued', 'In Queue', CYAN),
            ('workers', 'Workers', GOLD),
        ]):
            card = Metric(title, accent)
            card.setMinimumWidth(95)
            metrics.addWidget(card, 0, i)
            self.cards[key] = card
        self.dashboard_metric_layout = metrics
        self.dashboard_metric_cards = list(self.cards.values())
        self.dashboard_metric_columns = 6
        l.addLayout(metrics)

        upper = QHBoxLayout()
        upper.setSpacing(12)
        map_panel, map_layout = panel('GLOBAL PACKET ACTIVITY  /  SYNTHETIC ROUTES')
        legend = QHBoxLayout()
        allowed_legend = label('●  ALLOW', 'micro')
        allowed_legend.setStyleSheet('color:#FFD26C;font-size:11px;font-weight:800')
        denied_legend = label('●  DENY', 'micro')
        denied_legend.setStyleSheet('color:#FF5969;font-size:11px;font-weight:800')
        legend.addWidget(allowed_legend)
        legend.addWidget(denied_legend)
        self.map_sampling_note = label('Uniform packet-event sample', 'muted')
        legend.addWidget(self.map_sampling_note)
        legend.addStretch()
        map_layout.addLayout(legend)
        self.map = NetworkMap()
        self.map.routeStarted.connect(self.display_map_event)
        self.map.setMinimumHeight(250)
        self.map.setMaximumHeight(420)
        map_layout.addWidget(self.map, 1)
        self.latest_packet_label = label(
            'Awaiting packet decisions from the C++ engine…', 'micro'
        )
        self.latest_packet_label.setWordWrap(True)
        map_layout.addWidget(self.latest_packet_label)
        map_panel.setMaximumHeight(490)
        upper.addWidget(map_panel, 7)

        gauges = QVBoxLayout()
        gauges.setSpacing(12)
        processing_panel, processing_layout = panel('PACKET PROCESSING')
        self.health_gauge = Gauge(GREEN, 'PROCESSING', '—')
        self.health_gauge.setMaximumHeight(170)
        processing_layout.addWidget(self.health_gauge, 1)
        self.health_detail = label('Processed / Generated packets', 'micro')
        self.health_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        processing_layout.addWidget(self.health_detail)
        gauges.addWidget(processing_panel, 1)

        denied_panel, denied_layout = panel('BLOCKED TRAFFIC LEVEL')
        self.threat_gauge = Gauge(CYAN, 'DENY RATE', '—')
        self.threat_gauge.setMaximumHeight(170)
        denied_layout.addWidget(self.threat_gauge, 1)
        self.threat_detail = label('Denied / Processed packets', 'micro')
        self.threat_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        denied_layout.addWidget(self.threat_detail)
        gauges.addWidget(denied_panel, 1)
        upper.addLayout(gauges, 3)
        l.addLayout(upper)

        bottom = QHBoxLayout()
        bottom.setSpacing(12)
        events_panel, events_layout = panel('LIVE SECURITY EVENT STREAM')
        self.alerts = table(['Time', 'Event', 'Details'])
        self.alerts.setColumnWidth(0, 84)
        self.alerts.setColumnWidth(1, 105)
        self.alerts.horizontalHeader().setStretchLastSection(True)
        self.alerts.setMinimumHeight(155)
        self.alerts.setMaximumHeight(245)
        events_layout.addWidget(self.alerts, 1)
        bottom.addWidget(events_panel, 5)

        chart_panel, chart_layout = panel('LIVE TRAFFIC DATA')
        self.traffic_chart = TrafficChart()
        self.traffic_chart.setMaximumHeight(225)
        chart_layout.addWidget(self.traffic_chart, 1)
        rates = QHBoxLayout()
        self.rate = label('●  0 allowed/s', 'micro')
        self.rate.setStyleSheet('color:#FFD26C;font-size:10px')
        self.blockrate = label('●  0 denied/s', 'micro')
        self.blockrate.setStyleSheet('color:#FF5969;font-size:10px')
        rates.addWidget(self.rate)
        rates.addWidget(self.blockrate)
        chart_layout.addLayout(rates)
        self.traffic_totals = label('Session totals — ALLOW 0  •  DENY 0', 'micro')
        chart_layout.addWidget(self.traffic_totals)
        note = label('Gold/red lines show the recent rate; totals stay visible after the traffic ends.', 'muted')
        chart_layout.addWidget(note)
        bottom.addWidget(chart_panel, 5)
        l.addLayout(bottom)
        l.addStretch(1)

        scroll = QScrollArea()
        # Center the content instead of stretching it across a large screen.
        w.setMaximumWidth(1480)
        w.setMinimumHeight(715)
        scroll.setWidgetResizable(True)
        scroll.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(w)
        return scroll



    def display_map_event(self, packet):
        """Label the route when it appears, not when the C++ batch finishes."""
        if packet:
            self.latest_packet_label.setText(
                f"REPLAYED ENGINE SAMPLE  •  PACKET #{packet.get('id')}  •  "
                f"{packet.get('ip')}  •  "
                f"{packet.get('protocol')}:{packet.get('port')}  •  "
                f"{packet.get('decision')}  •  schematic path"
            )

    def run_dashboard_batch(self):
        """Send a user-selected packet count via the existing engine protocol."""
        amount = self.dashboard_count.value()
        if self.proc.state() != QProcess.ProcessState.Running:
            self.dashboard_feedback.setText('Engine offline — no packets requested.')
            return
        self.generate(amount)
        self.dashboard_feedback.setText(
            f'Requested {amount:,} synthetic packets; engine counters will update.'
        )

    def resizeEvent(self, event):
        """Reflow KPI tiles on narrower Kali windows; leave other pages intact."""
        super().resizeEvent(event)
        if not hasattr(self, 'dashboard_metric_layout'):
            return
        available = self.stack.width() if hasattr(self, 'stack') else self.width()
        columns = 6 if available >= 975 else 3 if available >= 550 else 2
        if columns == self.dashboard_metric_columns:
            return
        layout = self.dashboard_metric_layout
        for tile in self.dashboard_metric_cards:
            layout.removeWidget(tile)
        for index, tile in enumerate(self.dashboard_metric_cards):
            layout.addWidget(tile, index // columns, index % columns)
        self.dashboard_metric_columns = columns

    def inspector(self):
        w, l, h = self.page('PACKET INSPECTOR', 'Inspect simulated packets and the exact C++ rule decision')
        self.packet_filter = QComboBox()
        self.packet_filter.addItems(['ALL', 'ALLOW', 'DENY'])
        self.packet_filter.currentTextChanged.connect(self.filter_packets)
        h.addWidget(self.packet_filter)
        export = QPushButton('EXPORT CSV')
        export.clicked.connect(self.export_packets)
        h.addWidget(export)
        p, pl = panel('PACKET RECORDS  /  CURRENT SESSION')
        self.packet_table = table(['ID', 'Source IP', 'Port', 'Protocol', 'Decision', 'Matched Rule', 'Priority'])
        self.packet_table.setColumnWidth(0,70)
        self.packet_table.setColumnWidth(1,165)
        self.packet_table.setColumnWidth(2,75)
        self.packet_table.setColumnWidth(3,105)
        self.packet_table.setColumnWidth(4,105)
        self.packet_table.setColumnWidth(5,135)
        self.packet_table.setColumnWidth(6,105)
        # Avoid the old 600px-wide Priority column when the VM is maximized.
        self.packet_table.horizontalHeader().setStretchLastSection(False)
        self.packet_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        pl.addWidget(self.packet_table)
        l.addWidget(p, 1)
        return w

    def rules_page(self):
        w, l, h = self.page('FIREWALL RULE MANAGER', 'First enabled matching rule wins; unmatched packets are allowed')
        p, pl = panel('CREATE RULE')
        controls = QHBoxLayout()
        self.ip = QLineEdit('*')
        self.ip.setPlaceholderText('Source IP or *')
        controls.addWidget(self.ip, 2)
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText('Any port')
        controls.addWidget(self.port, 1)
        self.protocol = QComboBox()
        self.protocol.addItems(['ANY', 'TCP', 'UDP'])
        controls.addWidget(self.protocol, 1)
        self.action = QComboBox()
        self.action.addItems(['DENY', 'ALLOW'])
        controls.addWidget(self.action, 1)
        add = QPushButton('+ ADD RULE')
        self.add_rule_button = add
        add.setObjectName('primary')
        add.clicked.connect(self.add_rule)
        controls.addWidget(add)
        pl.addLayout(controls)
        l.addWidget(p)
        p, pl = panel('ACTIVE RULE SET')
        self.rules_table = table(['Rule ID', 'Source IP', 'Port', 'Protocol', 'Action', 'Enabled'])
        self.rules_table.setColumnWidth(0, 90)
        self.rules_table.setColumnWidth(1, 180)
        self.rules_table.setColumnWidth(2, 110)
        self.rules_table.setColumnWidth(3, 120)
        self.rules_table.setColumnWidth(4, 125)
        self.rules_table.setColumnWidth(5, 115)
        pl.addWidget(self.rules_table)
        actions = QHBoxLayout()
        for title, fn, obj in [('TOGGLE SELECTED', self.toggle_rule, ''), ('DELETE SELECTED', self.delete_rule, 'danger'), ('REFRESH', lambda: self.send('RULES'), '')]:
            b = QPushButton(title)
            if obj:
                b.setObjectName(obj)
            b.clicked.connect(fn)
            actions.addWidget(b)
        actions.addStretch()
        pl.addLayout(actions)
        l.addWidget(p, 1)
        return w

    def simulator(self):
        w, l, h = self.page('ATTACK SIMULATION LAB', 'Safe, synthetic traffic experiments — no live traffic interception')
        p, pl = panel('TRAFFIC GENERATOR')
        pl.addWidget(label('PACKETS TO GENERATE', 'micro'))
        self.amount = QSpinBox()
        self.amount.setRange(1, 20000)
        self.amount.setValue(500)
        pl.addWidget(self.amount)
        presets = QHBoxLayout()
        for title, count in [('QUICK TEST  /  100', 100), ('STANDARD  /  1,000', 1000), ('STRESS  /  5,000', 5000)]:
            b = QPushButton(title)
            b.clicked.connect(lambda checked=False, n=count: self.amount.setValue(n))
            presets.addWidget(b)
        pl.addLayout(presets)
        start = QPushButton('▶  GENERATE & PROCESS TRAFFIC')
        start.setObjectName('primary')
        start.clicked.connect(lambda: self.generate(self.amount.value()))
        pl.addWidget(start)
        self.sim_feedback = label('Ready to send a GENERATE command to the C++ engine.', 'muted')
        pl.addWidget(self.sim_feedback)
        l.addWidget(p)
        p2, p2l = panel('SCENARIO GUIDE')
        guide = label('PORT 22 TEST: In Firewall Rules, add Source IP = *, Port = 22, Protocol = TCP, Action = DENY. Then generate traffic and inspect the blocked results.\n\nThe concurrent C++17 engine generates synthetic packets across ports 22, 53, 80, 443 and 8080. Packet-count presets do not select an attack pattern. The Security Scenario Lab below provides modeled port-scan and repeated-login alerts and an isolated C++ high-traffic run. No real scans, login attempts, SYN floods, or network interception occur.', 'muted')
        guide.setWordWrap(True)
        p2l.addWidget(guide)
        l.addWidget(p2)
        # Security scenario controls are deliberately separate from live engine counters.
        p3, p3l = panel('SECURITY SCENARIO LAB  /  SYNTHETIC ALERTS')
        p3l.addWidget(label('Port scan and failed-login scenarios are modeled alerts. High traffic uses a separate C++ engine process.', 'muted'))
        controls = QHBoxLayout()
        self.login_failures = QSpinBox()
        self.login_failures.setRange(0, 1000)
        self.login_failures.setValue(12)
        self.login_failures.setPrefix('Failed logins: ')
        controls.addWidget(self.login_failures)
        self.scenario_count = QSpinBox()
        self.scenario_count.setRange(1, 20000)
        self.scenario_count.setValue(1000)
        self.scenario_count.setPrefix('Traffic packets: ')
        controls.addWidget(self.scenario_count)
        p3l.addLayout(controls)
        actions = QHBoxLayout()
        self.scenario_buttons = []
        for name, title in [('port_scan', 'RUN PORT SCAN'), ('repeated_login', 'RUN FAILED LOGINS'), ('high_traffic', 'RUN HIGH TRAFFIC')]:
            b = QPushButton(title)
            b.clicked.connect(lambda checked=False, kind=name: self.start_security_scenario(kind))
            actions.addWidget(b)
            self.scenario_buttons.append(b)
        p3l.addLayout(actions)
        self.scenario_feedback = label('Ready. All three scenarios use local, synthetic data.', 'muted')
        p3l.addWidget(self.scenario_feedback)
        self.scenario_alert_table = table(['Local Time', 'Scenario', 'Severity', 'Source', 'Details', 'Engine-backed'])
        self.scenario_alert_table.setMinimumHeight(200)
        # Fit the common Kali VM width; wrap details and keep full evidence below.
        for col, width in enumerate((122, 142, 95, 142, 278, 138)):
            self.scenario_alert_table.setColumnWidth(col, width)
        self.scenario_alert_table.setWordWrap(True)
        self.scenario_alert_table.horizontalHeader().setStretchLastSection(False)
        self.scenario_alert_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scenario_alert_table.itemSelectionChanged.connect(self.show_scenario_details)
        p3l.addWidget(self.scenario_alert_table)
        self.scenario_details_label = label('Select an alert to read its complete details and evidence.', 'muted')
        self.scenario_details_label.setWordWrap(True)
        p3l.addWidget(self.scenario_details_label)
        l.addWidget(p3)
        l.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(w)
        return scroll

    def workers_page(self):
        """Live C++ thread statistics, semaphore controls and priority/benchmark views."""
        w, l, h = self.page('CONCURRENT WORKER MONITOR',
                            'Live C++ engine synchronization, worker pools and queue scheduling')

        mode_box, mode_layout = panel('THREAD POOL CONTROLS')
        row = QHBoxLayout()
        row.addWidget(label('POOL MODE', 'micro'))
        self.worker_mode_combo = QComboBox()
        self.worker_mode_combo.addItems(['FIXED', 'ADAPTIVE'])
        row.addWidget(self.worker_mode_combo)
        apply_mode = QPushButton('APPLY MODE')
        apply_mode.clicked.connect(lambda: self.send('MODE ' + self.worker_mode_combo.currentText()))
        row.addWidget(apply_mode)
        row.addStretch(1)
        mode_layout.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(label('FIXED WORKER COUNT', 'micro'))
        self.worker_target_spin = QSpinBox()
        self.worker_target_spin.setRange(1, 8)
        self.worker_target_spin.setValue(4)
        row.addWidget(self.worker_target_spin)
        set_threads = QPushButton('SET WORKERS')
        set_threads.setToolTip('This command switches to fixed mode')
        set_threads.clicked.connect(lambda: self.send('SETWORKERS ' + str(self.worker_target_spin.value())))
        row.addWidget(set_threads)
        row.addStretch(1)
        mode_layout.addLayout(row)
        self.worker_mode_status = label('Waiting for C++ WORKERS report…', 'muted')
        self.worker_mode_status.setWordWrap(True)
        mode_layout.addWidget(self.worker_mode_status)
        l.addWidget(mode_box)

        state_box, state = panel('ENGINE LOAD  /  BOUNDED SHARED QUEUE')
        self.worker_label = label('Waiting for engine…', 'value')
        state.addWidget(self.worker_label)
        self.worker_busy_label = label('Waiting for thread activity', 'muted')
        state.addWidget(self.worker_busy_label)
        self.queue_title = label('QUEUE UTILIZATION', 'micro')
        state.addWidget(self.queue_title)
        self.queue_bar = QProgressBar()
        self.queue_bar.setRange(0, 3000)
        state.addWidget(self.queue_bar)
        self.queue_label = label('0 / 3,000 packets queued  •  peak 0', 'muted')
        self.queue_label.setWordWrap(True)
        state.addWidget(self.queue_label)
        state.addWidget(label('RECENT SHARED QUEUE DEPTH  /  observed C++ samples', 'micro'))
        self.queue_history = Sparkline(CYAN)
        self.queue_history.setMinimumHeight(72)
        self.queue_history.setMaximumHeight(80)
        state.addWidget(self.queue_history)
        l.addWidget(state_box)

        threads_box, threads = panel('INDIVIDUAL WORKERS  /  ALL WORKLOADS (INCLUDING BENCHMARKS)')
        self.worker_tiles = []
        tiles = QGridLayout()
        tiles.setSpacing(8)
        for idx in range(8):
            tile = Metric(f'Worker {idx + 1}', CYAN)
            tile.number.setText('—')
            tile.number.setStyleSheet(f'color:{MUTED};font-size:22px;font-weight:800;')
            tile.sub.setText('Awaiting WORKERS event')
            tile.sub.setWordWrap(True)
            tiles.addWidget(tile, idx // 4, idx % 4)
            self.worker_tiles.append(tile)
        threads.addLayout(tiles)
        fairness_note = label(
            'Worker counters are historical per-thread totals, including benchmark work. '
            'INACTIVE means that thread is no longer running, NOT that it never processed packets. '
            'Benchmark packets are excluded from the main Command Center totals.', 'muted')
        fairness_note.setWordWrap(True)
        threads.addWidget(fairness_note)
        l.addWidget(threads_box)

        limiter_box, limiter_layout = panel('SEMAPHORE RATE CONTROL  /  C++ ENGINE')
        row = QHBoxLayout()
        row.addWidget(label('RATE  /  PACKETS PER SECOND', 'micro'))
        self.rate_limit_spin = QSpinBox()
        self.rate_limit_spin.setRange(0, 100000)
        self.rate_limit_spin.setValue(0)
        self.rate_limit_spin.setSpecialValueText('Unlimited (0)')
        self.rate_limit_spin.setKeyboardTracking(True)
        self.rate_limit_spin.valueChanged.connect(self.rate_input_edited)
        row.addWidget(self.rate_limit_spin)
        set_rate = QPushButton('APPLY RATE LIMIT')
        set_rate.clicked.connect(self.apply_rate_limit)
        row.addWidget(set_rate)
        row.addStretch(1)
        limiter_layout.addLayout(row)
        self.worker_rate_status = label('Rate limit: unknown until first STATS response', 'muted')
        self.worker_rate_status.setWordWrap(True)
        limiter_layout.addWidget(self.worker_rate_status)
        l.addWidget(limiter_box)

        priority_box, priority_layout = panel('PRIORITY PACKETS  /  AGING-BASED SCHEDULING')
        row = QHBoxLayout()
        row.addWidget(label('HIGH-PRIORITY PACKETS', 'micro'))
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(1, 500)
        self.priority_spin.setValue(20)
        row.addWidget(self.priority_spin)
        send_priority = QPushButton('QUEUE PRIORITY PACKETS')
        send_priority.clicked.connect(lambda: self.send('PRIORITY ' + str(self.priority_spin.value())))
        row.addWidget(send_priority)
        row.addStretch(1)
        priority_layout.addLayout(row)
        priority_help = label(
            'QUEUE PRIORITY PACKETS directly generates and processes high-priority simulated packets; '
            'you do not need to press RUN PACKETS afterward.', 'muted')
        priority_help.setWordWrap(True)
        priority_layout.addWidget(priority_help)
        self.priority_status = label('No high-priority packets reported yet', 'muted')
        self.priority_status.setWordWrap(True)
        priority_layout.addWidget(self.priority_status)
        l.addWidget(priority_box)

        benchmark_box, benchmark_layout = panel('PERFORMANCE COMPARISON  /  FIXED vs ADAPTIVE')
        row = QHBoxLayout()
        row.addWidget(label('PACKETS', 'micro'))
        self.bench_amount = QSpinBox()
        self.bench_amount.setRange(100, 10000)
        self.bench_amount.setValue(4000)
        row.addWidget(self.bench_amount)
        row.addWidget(label('DELAY (µs)', 'micro'))
        self.bench_delay = QSpinBox()
        self.bench_delay.setRange(0, 10000)
        self.bench_delay.setValue(300)
        row.addWidget(self.bench_delay)
        row.addStretch(1)
        benchmark_layout.addLayout(row)
        start_benchmark = QPushButton('▶  RUN FIXED / ADAPTIVE COMPARISON')
        start_benchmark.clicked.connect(self.run_worker_benchmark)
        benchmark_layout.addWidget(start_benchmark)
        self.benchmark_status = label('BENCH runs FIXED and ADAPTIVE workloads separately. It does not increase the ordinary firewall counters.', 'muted')
        self.benchmark_status.setWordWrap(True)
        benchmark_layout.addWidget(self.benchmark_status)
        self.benchmark_count_note = label(
            'Benchmark workload processed: 0 packets (two separate test passes)', 'muted'
        )
        self.benchmark_count_note.setWordWrap(True)
        benchmark_layout.addWidget(self.benchmark_count_note)
        l.addWidget(benchmark_box)
        l.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(w)
        return scroll

    def run_worker_benchmark(self):
        """Request the existing engine benchmark without polluting ordinary counters."""
        count = self.bench_amount.value()
        delay = self.bench_delay.value()
        if self.send(f'BENCH {count} {delay}'):
            self.benchmark_status.setText(
                f'Benchmark requested: {count:,} packets at {delay} microseconds. '
                'The C++ engine will send the comparison when complete.'
            )

    def rate_input_edited(self, _value):
        """A poll must never erase a rate the user is editing or applying."""
        if not self._syncing_rate_value:
            self._rate_guard.edited()

    def apply_rate_limit(self):
        """Commit the spin-box text before sending RATE to the engine."""
        self.rate_limit_spin.interpretText()
        requested = self.rate_limit_spin.value()
        self._rate_guard.submit(requested)
        if self.send(f'RATE {requested}'):
            self.worker_rate_status.setText(
                f'Requested {requested:,} packets/sec  •  awaiting engine confirmation'
            )
        else:
            self._rate_guard.cancel()
            self.worker_rate_status.setText('Could not apply rate: C++ engine is offline')

    def update_queue_readout(self, data, record_sample=False):
        """One queue format for both STATS and WORKERS; record real samples."""
        capacity = max(1, int(data.get('capacity', 3000)))
        queued = max(0, int(data.get('queued', 0)))
        self.queue_bar.setRange(0, capacity)
        self.queue_bar.setValue(min(capacity, queued))
        self.queue_title.setText(f'SHARED QUEUE DEPTH  /  NORMAL CAPACITY {capacity:,}')
        self.queue_label.setText(queue_readout(data))
        if record_sample:
            self.queue_history.push(queued)

    def show_scenario_details(self):
        """Show untruncated security evidence for the selected alert."""
        row = self.scenario_alert_table.currentRow()
        if row < 0:
            self.scenario_details_label.setText('Select an alert to see full details.')
            return
        item = self.scenario_alert_table.item(row, 0)
        if item is None:
            return
        try:
            alert = json.loads(item.data(Qt.ItemDataRole.UserRole))
        except (TypeError, ValueError):
            return
        evidence = json.dumps(alert.get('evidence', {}), ensure_ascii=False)
        self.scenario_details_label.setText(
            f"{alert.get('scenario', 'SCENARIO')}  •  "
            f"{format_scenario_time(alert.get('timestamp', ''))} local  •  "
            f"{alert.get('description', '')}\n"
            f"Evidence (synthetic): {evidence}"
        )

    def render_worker_report(self, data):
        """Only display the actual data contained in a C++ WORKERS reply."""
        alive = int(data.get('alive', 0))
        busy = int(data.get('busy', 0))
        target = int(data.get('target', alive))
        mode = str(data.get('mode', 'UNKNOWN'))
        capacity = max(1, int(data.get('capacity', 3000)))
        queued = max(0, int(data.get('queued', 0)))
        peak = int(data.get('peak_workers', alive))
        self.worker_label.setText(f'{alive} active C++ workers')
        self.worker_busy_label.setText(f'{busy} busy  •  target {target}  •  peak {peak}')
        self.worker_mode_status.setText(f'{mode} MODE  •  {alive} alive / {target} target')
        if mode in ('FIXED', 'ADAPTIVE') and not self.worker_mode_combo.hasFocus():
            self.worker_mode_combo.setCurrentText(mode)
        if not self.worker_target_spin.hasFocus() and mode == 'FIXED':
            self.worker_target_spin.setValue(target)
        self.update_queue_readout(data, record_sample=False)
        by_id = {int(item.get('id', -1)): item for item in data.get('items', [])}
        for index, tile in enumerate(self.worker_tiles):
            item = by_id.get(index)
            active = bool(item and item.get('alive'))
            if item is None:
                tile.number.setText('—')
                tile.sub.setText('INACTIVE')
            else:
                tile.number.setText(f'{int(item.get("processed", 0)):,}')
                state = 'BUSY' if active and item.get('busy') else 'IDLE' if active else 'INACTIVE'
                tile.sub.setText(state + '  •  historical total (incl. BENCH)')
            tile.number.setStyleSheet(f'color:{GREEN if active else MUTED};font-size:22px;font-weight:800;')

    def render_benchmark(self, data):
        """Show actual measured throughput from the C++ benchmark response."""
        results = {str(item.get('mode')): item for item in data.get('results', [])}
        fixed, adaptive = results.get('FIXED'), results.get('ADAPTIVE')
        if not fixed or not adaptive:
            self.benchmark_status.setText('The engine response is incomplete. Check Activity Logs.')
            return
        factor = (float(fixed.get('seconds', 0)) /
                  max(.000001, float(adaptive.get('seconds', 0))))
        self.benchmark_status.setText(
            f'{data.get("count", 0):,} packets  •  simulated delay {data.get("delay_us", 0)} µs\n'
            f'FIXED: {float(fixed.get("seconds", 0)):.3f} s, {float(fixed.get("throughput", 0)):,.0f} packets/s '
            f'(peak {fixed.get("peak_workers", 0)} workers)\n'
            f'ADAPTIVE: {float(adaptive.get("seconds", 0)):.3f} s, {float(adaptive.get("throughput", 0)):,.0f} packets/s '
            f'(peak {adaptive.get("peak_workers", 0)} workers)\n'
            f'Adaptive speed ratio: {factor:.2f}× (machine-dependent)'
        )
        self._benchmark_packets_reported += int(data.get('count', 0)) * len(results)
        self.benchmark_count_note.setText(
            f'Benchmark workload processed: {self._benchmark_packets_reported:,} packets '
            f'across {len(results)} passes per comparison. Historical worker counters '
            'include this work; normal-session dashboard totals do not.'
        )
        self.log('INFO', 'BENCHMARK', f'Engine benchmark: adaptive speed ratio {factor:.2f}×')

    def logs_page(self):
        w, l, h = self.page('ACTIVITY & SECURITY LOGS', 'Timestamped local-session events and blocked packet decisions')
        export = QPushButton('EXPORT CSV')
        export.clicked.connect(self.export_logs)
        h.addWidget(export)
        p, pl = panel('EVENT TIMELINE')
        self.logs_table = table(['Local Time (12h)', 'Level', 'Event', 'Details'])
        self.logs_table.setColumnWidth(0,145)
        self.logs_table.setColumnWidth(1,85)
        self.logs_table.setColumnWidth(2,140)
        self.logs_table.setColumnWidth(3,580)
        pl.addWidget(self.logs_table)
        l.addWidget(p, 1)
        return w

    def restore_firewall_policy(self):
        """Replay saved rules in order into a freshly started C++ engine.

        Ignore all intermediate RULES events until the final desired rule list
        is observed, preventing partial startup state from overwriting the disk.
        """
        if self.rule_load_error:
            self.log('ERROR', 'RULE CONFIG',
                     f'Could not read saved firewall policy: {self.rule_load_error}')
            self.send('RULES')
            return
        if not self.saved_rules:
            self.rules_restored = True
            self.send('RULES')
            return
        self.restoring_rules = True
        self.add_rule_button.setEnabled(False)
        for index, rule in enumerate(self.saved_rules, 1):
            self.send('ADD {ip} {port} {protocol} {action}'.format(**rule))
            if not rule['enabled']:
                # The newly-started engine assigns deterministic IDs 1,2,...
                self.send(f'TOGGLE {index}')
        self.send('RULES')
        self.log('INFO', 'RULE CONFIG',
                 f'Restoring {len(self.saved_rules)} firewall rules from disk')

    def save_firewall_policy(self):
        """Save only confirmed engine rule lists, never pending edits."""
        try:
            write_rules(self.rule_policy_path, self.rules)
        except (OSError, ValueError, TypeError) as exc:
            self.log('ERROR', 'RULE CONFIG', f'Cannot save policy: {exc}')

    def navigate(self, index):
        self.stack.setCurrentIndex(index)
        for i, b in enumerate(self.nav):
            b.setChecked(i == index)
        if index == 1:
            self.filter_packets()
        if index == 4 and self.proc.state() == QProcess.ProcessState.Running:
            self.send('WORKERS')

    def update_clock(self):
        self.time_label.setText(format_local_time())

    def send(self, command):
        if self.proc.state() != QProcess.ProcessState.Running:
            self.log('ERROR', 'ENGINE', f'Cannot send {command}: engine is offline')
            return False
        self.proc.write((command+'\n').encode('utf-8'))
        return True

    def generate(self, count):
        if self.send(f'GENERATE {count}'):
            self.sim_feedback.setText(f'Command sent: generate {count:,} synthetic packets. Check Overview for results.')
            self.log('INFO', 'SIMULATOR', f'Requested {count:,} packets')

    def start_security_scenario(self, name):
        if self.scenario_worker is not None and self.scenario_worker.isRunning():
            self.scenario_feedback.setText('A scenario is already running.')
            return
        self.scenario_worker = ScenarioWorker(
            name, count=self.scenario_count.value(),
            failures=self.login_failures.value(), parent=self
        )
        for btn in self.scenario_buttons:
            btn.setEnabled(False)
        self.scenario_feedback.setText(f'Running {name} (synthetic scenario)...')
        self.scenario_worker.completed.connect(self.security_scenario_completed)
        self.scenario_worker.failed.connect(self.security_scenario_failed)
        self.scenario_worker.finished.connect(self.security_scenario_finished)
        self.scenario_worker.start()

    def security_scenario_completed(self, events):
        for ev in events:
            shown = event_for_table(ev)
            row_insert(self.scenario_alert_table, [
                format_scenario_time(shown['time']), shown['scenario'], shown['severity'],
                shown['source'], shown['details'],
                'YES (isolated)' if shown['engine_backed'] else 'NO (modeled)'
            ], 250)
            self.scenario_alert_table.setRowHeight(0, 51)
            self.scenario_alert_table.item(0, 0).setData(
                Qt.ItemDataRole.UserRole, json.dumps(ev)
            )
            self.scenario_history.append(ev)
            level = 'ERROR' if shown['severity'] == 'CRITICAL' else 'WARNING'
            self.log(level, shown['scenario'], f"{shown['severity']} simulated alert: {shown['details']}")
        self.scenario_feedback.setText(
            f'{len(events)} new alert(s)  •  {len(self.scenario_history)} total this session. '
            'Main firewall counters are unchanged.'
        )

    def security_scenario_failed(self, message):
        self.scenario_feedback.setText(f'Scenario failed: {message}')
        self.log('ERROR', 'SECURITY SCENARIO', message)

    def security_scenario_finished(self):
        for btn in self.scenario_buttons:
            btn.setEnabled(True)
        if self.scenario_worker is not None:
            self.scenario_worker.deleteLater()
            self.scenario_worker = None

    def read_engine(self):
        self.buffer += bytes(self.proc.readAllStandardOutput()).decode('utf-8', errors='replace')
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            if not line.strip():
                continue
            try:
                self.handle(json.loads(line))
            except json.JSONDecodeError:
                self.log('ERROR', 'PARSE', line[:160])

    def read_error(self):
        err = bytes(self.proc.readAllStandardError()).decode('utf-8', errors='replace').strip()
        if err:
            self.log('ERROR', 'ENGINE STDERR', err[:200])

    def engine_error(self, _):
        self.status.setText('● ENGINE ERROR')
        self.status.setStyleSheet(f'color:{RED}')
        self.log('ERROR', 'ENGINE', self.proc.errorString())

    def engine_finished(self, code, status):
        self.status.setText('● ENGINE OFFLINE')
        self.status.setStyleSheet(f'color:{RED}')
        self.log('INFO', 'ENGINE', f'Engine exited with code {code}')

    def log(self, level, event, details):
        stamp = format_local_hms()
        self.logs_history.append((stamp, level, event, str(details)))
        row_insert(self.logs_table, [stamp, level, event, details], 800)
        if level in ('WARNING', 'ERROR') or event in ('ENGINE', 'SIMULATOR'):
            row_insert(self.alerts, [stamp, event, str(details)[:95]], 100)

    def handle(self, data):
        typ = data.get('type')
        if typ == 'ready':
            self.status.setText('● C++ ENGINE ONLINE')
            self.status.setStyleSheet(f'color:{GREEN};font-weight:800;background:#201E19;border:1px solid #8A682E;border-radius:12px;padding:7px 10px;')
            self.log('INFO', 'ENGINE', data.get('message', 'Ready'))
            self.restore_firewall_policy()
        elif typ == 'stats':
            self.metrics = data
            for key, card in self.cards.items():
                card.set(int(data.get(key, 0)))
            workers = int(data.get('workers', 0))
            self.worker_label.setText(f'{workers} active C++ workers')
            queued = int(data.get('queued', 0))
            capacity = max(1, int(data.get('capacity', 3000)))
            self.update_queue_readout(data, record_sample=True)
            rate_limit = int(data.get('rate_limit', 0))
            rate_description = f'{rate_limit:,} packets/sec' if rate_limit else 'Unlimited'
            self.worker_rate_status.setText(
                f'Current limit: {rate_description}  •  waiting for tokens: {int(data.get("rate_waiting", 0))}'
            )
            if self._rate_guard.reported(rate_limit):
                self._syncing_rate_value = True
                try:
                    self.rate_limit_spin.setValue(rate_limit)
                finally:
                    self._syncing_rate_value = False
            if self._rate_guard.pending is not None:
                self.worker_rate_status.setText(
                    f'APPLYING {self._rate_guard.pending:,} packets/sec  •  '
                    f'engine currently reports {rate_description}. '
                    'Waiting for confirmation…'
                )
            elif self._rate_guard.dirty:
                self.worker_rate_status.setText(
                    f'UNAPPLIED EDIT  •  engine rate is {rate_description}; '
                    'click APPLY RATE LIMIT to change it.'
                )
            self.priority_status.setText(
                f'High priority processed: {int(data.get("priority_processed", 0)):,}  •  '
                f'queued: {int(data.get("priority_queued", 0)):,}  •  '
                f'avg normal wait: {int(data.get("avg_wait_us_normal", 0)):,} µs  •  '
                f'avg priority wait: {int(data.get("avg_wait_us_priority", 0)):,} µs'
            )
            processed = int(data.get('processed', 0))
            denied = int(data.get('denied', 0))
            # Measured interval avoids inaccurate pps if the UI is busy or resized.
            sample_time = time.monotonic()
            previous_time = getattr(self, '_last_stats_sample_time', None)
            delta_time = max(0.05, sample_time - previous_time) if previous_time is not None else 0.65
            self._last_stats_sample_time = sample_time
            allowed = int(data.get('allowed', 0))
            rate = max(0, allowed - self.last_allowed) / delta_time
            blocked_rate = max(0, denied - self.last_blocked) / delta_time
            self.traffic_chart.push(rate, blocked_rate)
            self.rate.setText(f'● Current ALLOW {rate:,.0f} pkt/s')
            self.blockrate.setText(f'● Current DENY {blocked_rate:,.0f} pkt/s')
            self.traffic_totals.setText(
                f'Session totals — ALLOW {allowed:,}  •  DENY {denied:,}'
            )
            self.last_processed = processed
            self.last_allowed = allowed
            self.last_blocked = denied
            generated = max(0, int(data.get('generated', 0)))
            self.dashboard_progress.setText(processing_readout(generated, processed))
            self.map_sampling_note.setText(
                f'Uniform event sample  •  {100.0 * denied / processed:.1f}% denied in session'
                if processed else 'Uniform event sample  •  waiting for packet data'
            )
            completion = min(100.0, processed / generated * 100) if generated else 0.0
            self.health_gauge.set_value(completion, f'{completion:.0f}%' if generated else '—')
            self.health_detail.setText('Processed / Generated packets')
            deny_percent = min(100.0, denied / processed * 100) if processed else 0.0
            tone = RED if deny_percent >= 20 else GOLD if deny_percent >= 5 else '#87745B'
            self.threat_gauge.set_value(deny_percent, f'{deny_percent:.0f}%' if processed else '—', tone)
            self.threat_detail.setText('Denied / Processed packets')
        elif typ == 'packet':
            self.event_counter += 1
            row = [data.get('id'), data.get('ip'), data.get('port'), data.get('protocol'), data.get('decision'), data.get('rule') or 'Default', data.get('priority', 'NORMAL')]
            self.recent_packets.append(tuple(row))
            if self.stack.currentIndex() == 1 and self.packet_filter.currentText() in ('ALL', data.get('decision')):
                row_insert(self.packet_table, row, 750)
            blocked = data.get('decision') == 'DENY'
            # Throttle map drawing/events to keep UI responsive during 20k packet bursts.
            if sample_packet_route(self._map_sample_rng.random()):
                self.map.add_packet(blocked, data)
            if blocked:
                self.log('WARNING', 'BLOCKED', f"{data.get('ip')}:{data.get('port')} / {data.get('protocol')} • Rule {data.get('rule')}")
        elif typ == 'workers':
            self.render_worker_report(data)
        elif typ == 'benchmark':
            self.render_benchmark(data)
        elif typ == 'scale':
            self.log('INFO', 'WORKER POOL',
                     f"Adaptive scaling {data.get('direction', '?')} to {data.get('workers', '?')} workers")
        elif typ == 'rules':
            self.rules = data.get('items', [])
            if self.restoring_rules:
                try:
                    current = [normalize_rule(r) for r in self.rules]
                except (ValueError, TypeError):
                    current = None
                if current == self.saved_rules:
                    self.restoring_rules = False
                    self.rules_restored = True
                    self.add_rule_button.setEnabled(True)
                    self.log('INFO', 'RULE CONFIG',
                             f'Restored {len(current)} saved firewall rules')
            elif self.rule_load_error is None and self.rules_restored:
                self.save_firewall_policy()
            self.rules_table.setRowCount(0)
            for r in self.rules:
                idx = self.rules_table.rowCount()
                self.rules_table.insertRow(idx)
                vals = [r['id'], r['ip'], r['port'] or 'ANY', r['protocol'], r['action'], 'YES' if r['enabled'] else 'NO']
                for j, value in enumerate(vals):
                    self.rules_table.setItem(idx, j, QTableWidgetItem(str(value)))
        elif typ in ('ack', 'error'):
            msg = data.get('message', '')
            if typ == 'ack' and str(msg).startswith('Rate limit'):
                self.send('STATS')  # confirmation comes from observed engine state
            if typ == 'error' and str(msg).startswith('Usage: RATE'):
                self._rate_guard.cancel()
                self.worker_rate_status.setText('RATE was rejected by the C++ engine: ' + str(msg))
            self.log('ERROR' if typ == 'error' else 'INFO', typ.upper(), msg)
            if typ == 'ack':
                self.sim_feedback.setText(msg)

    def filter_packets(self):
        wanted = self.packet_filter.currentText()
        self.packet_table.setRowCount(0)
        # Keep the GUI responsive even after tens of thousands of packets;
        # exports continue using the entire session history, not just 750.
        matching = [r for r in self.recent_packets if wanted == 'ALL' or r[4] == wanted]
        for row in matching[-750:]:
            row_insert(self.packet_table, row, 750)

    def selected_rule(self):
        row = self.rules_table.currentRow()
        if row < 0:
            QMessageBox.information(self, 'Select a rule', 'Select a rule in the table first.')
            return None
        item = self.rules_table.item(row, 0)
        return item.text() if item else None

    def add_rule(self):
        ip = self.ip.text().strip()
        if not ip or any(c.isspace() for c in ip):
            QMessageBox.warning(self, 'Invalid source', 'Use an IP address or * with no spaces.')
            return
        self.send(f'ADD {ip} {self.port.value()} {self.protocol.currentText()} {self.action.currentText()}')

    def toggle_rule(self):
        rid = self.selected_rule()
        if rid:
            self.send('TOGGLE '+rid)

    def delete_rule(self):
        rid = self.selected_rule()
        if rid:
            self.send('DELETE '+rid)

    def export_csv(self, title, headers, rows):
        path, _ = QFileDialog.getSaveFileName(self, title, str(Path.home()/'cybershield_export.csv'), 'CSV Files (*.csv)')
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            self.log('INFO', 'EXPORT', f'Saved {len(rows)} rows to {path}')
        except OSError as e:
            QMessageBox.critical(self, 'Export failed', str(e))

    def export_packets(self):
        self.export_csv('Export packet decisions', ['ID','Source IP','Port','Protocol','Decision','Rule','Priority'], list(self.recent_packets))

    def export_logs(self):
        self.export_csv('Export activity logs', ['Time','Level','Event','Details'], list(self.logs_history))

    def closeEvent(self, event):
        if self.scenario_worker is not None and self.scenario_worker.isRunning():
            QMessageBox.information(self, 'Simulation running', 'Finish the current security scenario before closing CyberShield.')
            event.ignore()
            return
        if self.proc.state() == QProcess.ProcessState.Running:
            self.send('QUIT')
            if not self.proc.waitForFinished(2000):
                self.proc.kill()
                self.proc.waitForFinished(1000)
        super().closeEvent(event)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName('CyberShield')
    window = App()
    window.show()
    sys.exit(app.exec())

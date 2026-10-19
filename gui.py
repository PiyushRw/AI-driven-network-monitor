"""PyQt5 + pyqtgraph dashboard. Run: python gui.py"""
import sys
from collections import deque
from PyQt5 import QtCore, QtWidgets
import pyqtgraph as pg
import config
from engine import Engine

N = 120  # points on screen


class Main(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Driven Network Monitor - DDoS Detection")
        self.eng = Engine()
        self.d_in, self.d_out, self.d_conn, self.d_syn = (deque([0] * N, maxlen=N) for _ in range(4))
        lay = QtWidgets.QVBoxLayout(self)
        self.status = QtWidgets.QLabel("Status: starting"); lay.addWidget(self.status)
        self.p1 = pg.PlotWidget(title="Traffic (bytes/s)"); self.p1.addLegend()
        self.c_in = self.p1.plot(pen="c", name="in"); self.c_out = self.p1.plot(pen="y", name="out")
        self.p2 = pg.PlotWidget(title="Connections"); self.p2.addLegend()
        self.c_conn = self.p2.plot(pen="g", name="total"); self.c_syn = self.p2.plot(pen="r", name="SYN_RECV")
        lay.addWidget(self.p1); lay.addWidget(self.p2)
        row = QtWidgets.QHBoxLayout(); lay.addLayout(row)
        for text, fn in [("Learn baseline (live)", self.learn), ("Train synthetic baseline", self.eng.train_synthetic),
                         ("Simulate SYN flood", lambda: self.sim("syn")), ("Simulate UDP flood", lambda: self.sim("udp")),
                         ("Stop simulation", lambda: self.sim(None))]:
            b = QtWidgets.QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        self.chk = QtWidgets.QCheckBox("Auto-block"); self.chk.stateChanged.connect(
            lambda s: setattr(self.eng, "auto_block", bool(s))); row.addWidget(self.chk)
        self.log = QtWidgets.QPlainTextEdit(readOnly=True); self.log.setMaximumHeight(140); lay.addWidget(self.log)
        self.timer = QtCore.QTimer(self); self.timer.timeout.connect(self.step)
        self.timer.start(int(config.SAMPLE_INTERVAL * 1000)); self.resize(900, 750)

    def learn(self):
        if not self.eng.learning:
            self.eng.start_learning(); self.log.appendPlainText("learning baseline...")
        else:
            self.log.appendPlainText("trained" if self.eng.finish_learning() else "need >= 30 windows")

    def sim(self, kind):
        self.eng.inject = kind; self.log.appendPlainText(f"simulation: {kind}")

    def step(self):
        r = self.eng.tick(); x = r["x"]
        self.d_in.append(x[0]); self.d_out.append(x[1]); self.d_conn.append(x[5]); self.d_syn.append(x[6])
        self.c_in.setData(list(self.d_in)); self.c_out.setData(list(self.d_out))
        self.c_conn.setData(list(self.d_conn)); self.c_syn.setData(list(self.d_syn))
        if self.eng.learning and len(self.eng.baseline) >= config.BASELINE_SECONDS:
            self.learn()
        state = "ATTACK DETECTED" if r["attack"] else "normal"
        self.status.setText(f"Status: {state}   votes={r['votes']}   {r['msg']}")
        self.status.setStyleSheet("color:red;font-weight:bold" if r["attack"] else "color:green")
        if r["attack"] or r["msg"].startswith(("DRY", "blocked")):
            self.log.appendPlainText(f"{state} {r['msg']}")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv); w = Main(); w.show(); sys.exit(app.exec_())

"""Glue: collector -> detector -> persistence rule -> mitigation. GUI-independent."""
import numpy as np
import config, mitigation
from collector import TrafficCollector
from detector import EnsembleDetector
from storage import Store
import simulator


class Engine:
    def __init__(self):
        self.collector, self.store = TrafficCollector(), Store()
        self.detector, self.baseline, self.streak = None, [], 0
        self.learning, self.auto_block, self.inject = False, config.AUTO_BLOCK, None
        self.blocked = set()
        try:
            self.detector = EnsembleDetector.load()
        except Exception:
            pass

    def start_learning(self):
        self.baseline, self.learning = [], True

    def finish_learning(self):
        self.learning = False
        if len(self.baseline) >= 30:
            self.detector = EnsembleDetector(); self.detector.fit(self.baseline); self.detector.save()
            self.store.event("info", detail=f"trained on {len(self.baseline)} windows")
            return True
        return False

    def train_synthetic(self):
        self.detector = EnsembleDetector(); self.detector.fit(simulator.normal(600)); self.detector.save()

    def tick(self):
        """One window. Returns dict for the UI."""
        x, per_ip = self.collector.sample()
        if self.inject is not None:                     # demo: replace with synthetic attack vector
            x = list(simulator.attack(1, self.inject)[0])
        out = {"x": x, "attack": False, "votes": {}, "msg": ""}
        self.store.metric(x[0], x[1], int(x[5]), int(x[6]))
        if self.learning:
            self.baseline.append(x); out["msg"] = f"learning {len(self.baseline)}/{config.BASELINE_SECONDS}"
            return out
        if not self.detector:
            out["msg"] = "no model: learn baseline or train synthetic"; return out
        attack, votes = self.detector.is_attack(x)
        out["votes"] = votes
        self.streak = self.streak + 1 if attack else 0
        if self.streak >= config.CONSECUTIVE_WINDOWS:
            out["attack"] = True
            self.store.event("alert", votes=votes, detail="persistent anomaly")
            offender = per_ip.most_common(1)[0] if per_ip else None
            if self.auto_block and offender and offender[1] >= config.MIN_CONNS_FROM_ONE_IP \
                    and offender[0] not in self.blocked:
                res = mitigation.block(offender[0]); self.blocked.add(offender[0])
                self.store.event("block", src_ip=offender[0], detail=res); out["msg"] = res
        return out

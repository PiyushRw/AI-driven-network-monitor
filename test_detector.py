"""Headless self-test: python test_detector.py  (no GUI, no real traffic)."""
import numpy as np
from detector import EnsembleDetector
import simulator

d = EnsembleDetector(); d.fit(simulator.normal(600))
for name, X in [("normal", simulator.normal(200)), ("syn", simulator.attack(200, "syn")),
                ("udp", simulator.attack(200, "udp")), ("http", simulator.attack(200, "http"))]:
    flagged = np.mean([d.is_attack(x)[0] for x in X])
    print(f"{name:7s} flagged {flagged:6.1%}")

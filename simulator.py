"""Synthetic feature vectors so you can train/test WITHOUT generating real attack traffic."""
import numpy as np
from config import FEATURES

rng = np.random.default_rng(42)


def normal(n=500):
    X = np.column_stack([
        rng.gamma(4, 30_000, n),            # bytes_in_ps
        rng.gamma(3, 10_000, n),            # bytes_out_ps
        rng.gamma(4, 40, n),                # pkts_in_ps
        rng.gamma(3, 25, n),                # pkts_out_ps
        rng.normal(750, 150, n).clip(60),   # avg_pkt_in
        rng.poisson(60, n),                 # conn_total
        rng.poisson(0.5, n),                # syn_recv
        rng.poisson(20, n),                 # unique_ips
        rng.beta(2, 12, n),                 # top_ip_share
        rng.poisson(0.2, n),                # err_drop_ps
    ])
    assert X.shape[1] == len(FEATURES)
    return X


def attack(n=100, kind="syn"):
    base = normal(n)
    if kind == "syn":      # many half-open connections from many (spoofed) IPs, tiny packets
        base[:, 2] *= 40; base[:, 4] = rng.normal(60, 10, n); base[:, 6] = rng.poisson(900, n)
        base[:, 5] += base[:, 6]; base[:, 7] = rng.poisson(400, n)
    elif kind == "udp":    # huge volume of big packets
        base[:, 0] *= 60; base[:, 2] *= 50; base[:, 4] = rng.normal(1200, 100, n)
        base[:, 9] += rng.poisson(30, n)
    elif kind == "http":   # many established connections from one IP
        base[:, 5] += rng.poisson(1500, n); base[:, 8] = rng.beta(30, 3, n); base[:, 7] = rng.poisson(5, n)
    return base

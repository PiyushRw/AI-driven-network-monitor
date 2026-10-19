"""Turns raw OS counters into one feature vector per time window (psutil only)."""
import time
from collections import Counter
import psutil
from config import FEATURES


class TrafficCollector:
    def __init__(self):
        self.prev = psutil.net_io_counters()
        self.prev_t = time.time()

    def sample(self):
        """Return (feature_vector, Counter{remote_ip: connection_count})."""
        now, cur = time.time(), psutil.net_io_counters()
        dt = max(now - self.prev_t, 1e-6)
        p = self.prev
        d = lambda a: max(getattr(cur, a) - getattr(p, a), 0) / dt   # per-second delta
        bytes_in, bytes_out = d("bytes_recv"), d("bytes_sent")
        pkts_in, pkts_out = d("packets_recv"), d("packets_sent")
        err_drop = (d("errin") + d("errout") + d("dropin") + d("dropout"))
        self.prev, self.prev_t = cur, now

        per_ip, syn_recv, total = Counter(), 0, 0
        try:
            for c in psutil.net_connections(kind="inet"):
                total += 1
                if c.status == "SYN_RECV":
                    syn_recv += 1
                if c.raddr:
                    per_ip[c.raddr.ip] += 1
        except (psutil.AccessDenied, PermissionError):
            pass  # run as admin/root to see all connections

        top_share = (max(per_ip.values()) / sum(per_ip.values())) if per_ip else 0.0
        feats = {
            "bytes_in_ps": bytes_in, "bytes_out_ps": bytes_out,
            "pkts_in_ps": pkts_in, "pkts_out_ps": pkts_out,
            "avg_pkt_in": bytes_in / pkts_in if pkts_in else 0.0,
            "conn_total": total, "syn_recv": syn_recv,
            "unique_ips": len(per_ip), "top_ip_share": top_share,
            "err_drop_ps": err_drop,
        }
        return [feats[k] for k in FEATURES], per_ip

"""Central settings. Change values here, not inside the other files."""
SAMPLE_INTERVAL = 1.0          # seconds per observation window
BASELINE_SECONDS = 120         # how long to learn "normal" traffic
CONTAMINATION = 0.02           # expected fraction of anomalies in baseline
VOTES_NEEDED = 2               # of 3 models must agree
CONSECUTIVE_WINDOWS = 3        # anomaly must persist this many windows
MIN_CONNS_FROM_ONE_IP = 50     # offender must hold at least this many connections
AUTO_BLOCK = False             # start in alert-only mode (safe default)
DRY_RUN = True                 # print firewall commands instead of running them
MODEL_PATH = "model.joblib"
DB_PATH = "events.db"
WHITELIST = ["127.0.0.1", "::1"]   # never block these (add your gateway/DNS!)
FEATURES = [
    "bytes_in_ps", "bytes_out_ps", "pkts_in_ps", "pkts_out_ps",
    "avg_pkt_in", "conn_total", "syn_recv", "unique_ips",
    "top_ip_share", "err_drop_ps",
]

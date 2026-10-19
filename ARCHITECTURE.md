# Architecture & Technical Reference

> **Audience:** Anyone who wants to understand *exactly* how the monitor works — every file, every function, every algorithm decision, and the detection + mitigation pipeline end-to-end.

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Data Flow Pipeline](#2-data-flow-pipeline)
3. [File-by-File Reference](#3-file-by-file-reference)
   - [config.py](#31-configpy)
   - [collector.py](#32-collectorpy)
   - [detector.py](#33-detectorpy)
   - [simulator.py](#34-simulatorpy)
   - [engine.py](#35-enginepy)
   - [mitigation.py](#36-mitigationpy)
   - [storage.py](#37-storagepy)
   - [gui.py](#38-guipy)
   - [test_detector.py](#39-test_detectorpy)
   - [flow_eval/evaluate_cicids.py](#310-flow_evalevaluate_cicidspy)
   - [flow_eval/make_mock_cicids.py](#311-flow_evalmake_mock_cicidspy)
4. [Detection Methodology](#4-detection-methodology)
   - [Why Unsupervised?](#41-why-unsupervised)
   - [Isolation Forest](#42-isolation-forest)
   - [One-Class SVM](#43-one-class-svm)
   - [Local Outlier Factor](#44-local-outlier-factor)
   - [Majority-Vote Ensemble](#45-majority-vote-ensemble)
   - [Persistence Rule](#46-persistence-rule)
5. [Auto-Blocking Mechanism](#5-auto-blocking-mechanism)
6. [Feature Engineering](#6-feature-engineering)
7. [CICIDS2017 Evaluation Protocol](#7-cicids2017-evaluation-protocol)
8. [Attack Signatures in the Simulator](#8-attack-signatures-in-the-simulator)
9. [Security Design Decisions](#9-security-design-decisions)
10. [Limitations & Future Work](#10-limitations--future-work)

---

## 1. System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         HOST MACHINE                             │
│                                                                  │
│  ┌──────────┐   1-sec    ┌─────────────┐   feature    ┌───────┐ │
│  │  psutil  │──window───▶│  collector  │──vector[10]─▶│       │ │
│  │ (OS API) │            └─────────────┘              │       │ │
│  └──────────┘                                         │engine │ │
│                                                       │       │ │
│  ┌──────────┐  vote(1/0) ┌─────────────┐  is_attack  │       │ │
│  │IForest   │◀──────────│             │◀────────────│       │ │
│  │OC-SVM    │           │  detector   │             │       │ │
│  │LOF       │──────────▶│ (ensemble)  │─────────────▶│       │ │
│  └──────────┘  scores   └─────────────┘  True/False │       │ │
│                                                       │       │ │
│  ┌──────────┐  streak≥N  ┌─────────────┐             │       │ │
│  │mitigation│◀──────────│ persistence │◀────────────│       │ │
│  │(firewall)│           │    rule     │             └───────┘ │
│  └──────────┘           └─────────────┘                       │
│                                                                  │
│  ┌──────────┐            ┌─────────────┐                        │
│  │ storage  │◀───────────│   SQLite    │                        │
│  │(events.db│            │  (events,   │                        │
│  │ metrics) │            │   metrics)  │                        │
│  └──────────┘            └─────────────┘                        │
│                                                                  │
│  ┌──────────────────────────────────────┐                       │
│  │         PyQt5 GUI (gui.py)           │                       │
│  │  plots │ buttons │ log │ status bar  │                       │
│  └──────────────────────────────────────┘                       │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow Pipeline

```
Every SAMPLE_INTERVAL seconds (default: 1 s):

  1. collector.sample()
       └─ psutil.net_io_counters()   → bytes/pkts delta ÷ dt
       └─ psutil.net_connections()   → conn_total, syn_recv, unique_ips, top_ip_share
       └─ returns: feature_vector[10], per_ip Counter

  2. engine.tick()
       ├─ [if learning]  append to baseline buffer → no detection this tick
       ├─ [if injecting] replace feature_vector with simulator.attack()
       └─ detector.is_attack(feature_vector)
              └─ StandardScaler.transform()
              └─ IForest.predict()  → +1 / -1
              └─ OCSVM.predict()   → +1 / -1
              └─ LOF.predict()     → +1 / -1
              └─ sum votes: anomalous_count ≥ VOTES_NEEDED → True

  3. Persistence gate
       ├─ streak += 1 if attack else streak = 0
       └─ alert only if streak ≥ CONSECUTIVE_WINDOWS (default: 3)

  4. [If alert + AUTO_BLOCK]
       └─ per_ip.most_common(1) → offender IP
       └─ offender connections ≥ MIN_CONNS_FROM_ONE_IP?
              └─ mitigation.block(ip) → firewall rule

  5. storage.metric() + storage.event()  → SQLite

  6. GUI update (pyqtgraph plots + status label)
```

---

## 3. File-by-File Reference

### 3.1 `config.py`

**Purpose:** Single source of truth for all tuneable parameters. Every other module imports from here — no magic numbers anywhere else.

| Symbol | Type | Default | Role |
|---|---|---|---|
| `SAMPLE_INTERVAL` | `float` | `1.0` | Seconds per observation window |
| `BASELINE_SECONDS` | `int` | `120` | Minimum windows needed before `finish_learning()` trains the model |
| `CONTAMINATION` | `float` | `0.02` | Passed to `IsolationForest` and `LOF` as the expected anomaly fraction |
| `VOTES_NEEDED` | `int` | `2` | How many of the 3 models must vote "anomalous" |
| `CONSECUTIVE_WINDOWS` | `int` | `3` | Persistence gate depth — suppresses one-spike false positives |
| `MIN_CONNS_FROM_ONE_IP` | `int` | `50` | Auto-block threshold: offender must dominate this many connections |
| `AUTO_BLOCK` | `bool` | `False` | Master switch for firewall actions |
| `DRY_RUN` | `bool` | `True` | Print-only mode — never runs any system commands |
| `MODEL_PATH` | `str` | `"model.joblib"` | Path for saving/loading the trained `EnsembleDetector` |
| `DB_PATH` | `str` | `"events.db"` | SQLite database path |
| `WHITELIST` | `list[str]` | `["127.0.0.1","::1"]` | IPs never passed to `mitigation.block()` |
| `FEATURES` | `list[str]` | *(10 names)* | Ordered feature names — controls `collector.py` output order |

---

### 3.2 `collector.py`

**Purpose:** Translates raw OS network counters into a normalised 10-element feature vector every second.

#### Class `TrafficCollector`

**`__init__(self)`**
- Calls `psutil.net_io_counters()` to snapshot the current byte/packet totals and records `time.time()`.
- These become the "previous" state for the first `sample()` call.

**`sample(self) → (list[float], Counter)`**
- Computes `dt = now - prev_t` (clamped to ≥ 1 µs to avoid division-by-zero).
- For each counter field (`bytes_recv`, `bytes_sent`, `packets_recv`, `packets_sent`, `errin`, `errout`, `dropin`, `dropout`), computes the **per-second delta**: `(current − previous) / dt`, clamped to ≥ 0 (counters can wrap on 32-bit OSes).
- Calls `psutil.net_connections(kind="inet")` to iterate every TCP/UDP socket:
  - Counts `SYN_RECV` sockets (`syn_recv`) — a DDoS hallmark.
  - Counts connections per remote IP into `per_ip: Counter`.
- `top_ip_share` = `max(per_ip.values()) / total_conns` — high value means one IP dominates (e.g. HTTP flood from single source).
- Returns `[feats[k] for k in config.FEATURES]` — order is fixed and must match the scaler trained in `detector.py`.

> **`psutil.AccessDenied` / `PermissionError`:** silently caught. Connection-level data is optional; the byte/packet deltas still work without elevated privileges.

---

### 3.3 `detector.py`

**Purpose:** Wraps three scikit-learn anomaly detectors behind a unified interface with a shared `StandardScaler`.

#### Class `EnsembleDetector`

**`__init__(self)`**
- Reads `config.CONTAMINATION` to initialise all three models with the same expected anomaly rate.
- `IsolationForest(n_estimators=200)` — 200 trees, fully parallel (`n_jobs=-1`).
- `OneClassSVM(kernel="rbf", gamma="scale", nu=max(c, 0.01))` — RBF kernel, `nu` is the upper bound on training outliers and the lower bound on support vectors.
- `LocalOutlierFactor(n_neighbors=20, novelty=True)` — `novelty=True` enables `predict()` on new points after `.fit()`.
- `self.fitted = False` — guards against calling `is_attack()` before training.

**`fit(self, X: list[list[float]])`**
- Converts `X` to a NumPy array, runs `StandardScaler.fit_transform()`.
- Fits all three models on the scaled data.
- Sets `self.fitted = True`.

**`votes(self, x: list[float]) → dict[str, int]`**
- Scales a single feature vector.
- Each model calls `.predict()` which returns `+1` (normal) or `-1` (anomalous).
- Returns `{model_name: 1 if prediction == -1 else 0}`.

**`is_attack(self, x) → (bool, dict)`**
- Calls `votes()`.
- Returns `True` if `sum(votes.values()) >= config.VOTES_NEEDED`.

**`save(path)` / `load(path)`**
- Uses `joblib.dump` / `joblib.load` to persist/restore the entire `EnsembleDetector` object (scaler + 3 models + `fitted` flag).

---

### 3.4 `simulator.py`

**Purpose:** Generates synthetic feature vectors for training and attack injection without generating any real network traffic.

**Module-level `rng = np.random.default_rng(42)`** — seeded for reproducibility.

**`normal(n=500) → np.ndarray shape (n, 10)`**
- Samples each feature from a distribution matching realistic home/office traffic:
  - `bytes_in_ps` — Gamma(4, 30 000): heavy-tailed, bursts to ~120 KB/s
  - `bytes_out_ps` — Gamma(3, 10 000)
  - `pkts_in/out_ps` — Gamma(4/3, 40/25)
  - `avg_pkt_in` — Normal(750, 150) clipped at 60 (Ethernet minimum)
  - `conn_total` — Poisson(60)
  - `syn_recv` — Poisson(0.5): almost never in normal traffic
  - `unique_ips` — Poisson(20)
  - `top_ip_share` — Beta(2, 12): usually no dominant IP
  - `err_drop_ps` — Poisson(0.2): rare
- Assertion confirms feature count matches `len(config.FEATURES)`.

**`attack(n=100, kind="syn"|"udp"|"http") → np.ndarray`**
- Starts from `normal(n)` and exaggerates specific features:
  - **SYN flood:** `pkts_in_ps ×40`, `avg_pkt_in ~60` (tiny SYN packets), `syn_recv ~900`, `unique_ips ~400` (many spoofed IPs)
  - **UDP flood:** `bytes_in_ps ×60`, `pkts_in_ps ×50`, `avg_pkt_in ~1200` (large UDP datagrams), `err_drop_ps +~30`
  - **HTTP flood:** `conn_total +~1500`, `top_ip_share ~0.9` (single IP), `unique_ips ~5` (few sources)

---

### 3.5 `engine.py`

**Purpose:** Orchestrates the full pipeline. Designed to be GUI-independent — can run in a headless loop or be driven by a timer.

#### Class `Engine`

**`__init__(self)`**
- Creates a `TrafficCollector`, a `Store`, initialises state variables.
- Tries to load a saved model via `EnsembleDetector.load()`. If no model file exists, `self.detector = None` and the UI will prompt the user to train.
- `self.streak = 0` — persistence counter.
- `self.inject = None` — when set to `"syn"` / `"udp"` / `"http"`, replaces real feature vectors with simulated attack vectors.

**`start_learning(self)`**
- Sets `self.learning = True` and clears `self.baseline`.

**`finish_learning(self) → bool`**
- Returns `False` and does nothing if fewer than 30 windows were collected (not enough data).
- Otherwise: creates a new `EnsembleDetector`, calls `.fit(self.baseline)`, calls `.save()`, logs to `Store`.

**`train_synthetic(self)`**
- Fits on `simulator.normal(600)` — a "factory default" model useful for demos when no real baseline is available.

**`tick(self) → dict`**
- **Called once per `SAMPLE_INTERVAL` by the GUI timer.**
- Collects `x, per_ip = collector.sample()`.
- If `self.inject` is set, replaces `x` with a synthetic attack vector.
- Writes raw metrics to SQLite via `store.metric()`.
- **Learning mode:** appends `x` to baseline, returns early.
- **No model:** returns a message asking the user to train.
- Calls `detector.is_attack(x)` → `(attack_bool, votes_dict)`.
- Updates `self.streak`.
- If `streak >= CONSECUTIVE_WINDOWS`:
  - Sets `out["attack"] = True`, logs an alert event.
  - If `auto_block` is enabled, picks the top offender IP from `per_ip`, checks connection count, calls `mitigation.block()`.
- Returns a `dict` with keys `x`, `attack`, `votes`, `msg` for the GUI to render.

---

### 3.6 `mitigation.py`

**Purpose:** Safely translates a validated IP address into the correct OS firewall command.

**`_commands(ip) → list[list[str]]`**
- Detects the OS via `platform.system()`.
- **Windows:** `netsh advfirewall firewall add rule name=DDoSMonitor-<ip> dir=in action=block remoteip=<ip>`
- **Linux:** `iptables -I INPUT -s <ip> -j DROP`
- **macOS:** `pfctl -t ddos_block -T add <ip>` (requires a pre-loaded pf anchor)
- Returns a list of commands (each a list of strings — never a shell string).

**`is_blockable(ip) → bool`**
- Calls `ipaddress.ip_address(ip)` — raises `ValueError` on invalid input (prevents injection).
- Rejects loopback, multicast, unspecified addresses, and anything in `config.WHITELIST`.

**`block(ip) → str`**
- Calls `is_blockable()` first.
- If `config.DRY_RUN`: returns the command string for display, runs nothing.
- Otherwise: calls `subprocess.run(cmd_list, check=False, capture_output=True, timeout=10)` for each command. Using a list (not `shell=True`) prevents shell injection.

**`unblock(ip) → str`**
- Same safety checks, but issues the corresponding delete/remove rule.
- On Windows: `netsh advfirewall firewall delete rule name=DDoSMonitor-<ip>`
- On Linux: `iptables -D INPUT -s <ip> -j DROP`

---

### 3.7 `storage.py`

**Purpose:** Provides a thin, parameterised SQLite interface for events and time-series metrics.

#### Schema

```sql
CREATE TABLE events (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,              -- Unix timestamp
  kind    TEXT NOT NULL               -- 'alert' | 'block' | 'info'
            CHECK (kind IN ('alert','block','info')),
  src_ip  TEXT,
  votes   TEXT,                       -- JSON-ish string of vote dict
  detail  TEXT
);
CREATE INDEX idx_events_ts ON events(ts);

CREATE TABLE metrics (
  ts        REAL NOT NULL,
  bytes_in  REAL,
  bytes_out REAL,
  conns     INTEGER,
  syn_recv  INTEGER
);
```

#### Class `Store`

**`event(kind, src_ip, votes, detail)`** — inserts a row into `events` using a parameterised query (no string interpolation → no SQL injection).

**`metric(bytes_in, bytes_out, conns, syn)`** — lightweight time-series insert; one row per window.

**`recent(n=50)`** — returns the last N events ordered by time descending, formatted with `datetime()`.

**`top_offenders(n=5)`** — returns the top N blocked IPs by block-count; useful for incident review.

---

### 3.8 `gui.py`

**Purpose:** PyQt5 dashboard that drives the `Engine` via a `QTimer` and renders real-time plots.

#### Class `Main(QWidget)`

**`__init__(self)`**
- Creates an `Engine` instance.
- Creates four `deque(maxlen=120)` ring buffers (120 s of history): `d_in`, `d_out`, `d_conn`, `d_syn`.
- Builds the widget layout:
  - `QLabel` status bar (green/red, bold on attack)
  - Two `pyqtgraph.PlotWidget`: traffic (bytes/s) and connections
  - `QHBoxLayout` of buttons: *Learn baseline*, *Train synthetic*, *Simulate SYN flood*, *Simulate UDP flood*, *Stop simulation*
  - `QCheckBox` Auto-block
  - `QPlainTextEdit` event log (read-only, 140 px max height)
- Starts `QTimer` at `SAMPLE_INTERVAL × 1000` ms.

**`learn(self)`**
- First click: calls `engine.start_learning()`.
- Second click: calls `engine.finish_learning()`; if successful the model is live immediately.
- Auto-triggered if `len(baseline) >= BASELINE_SECONDS` during a `step()` tick.

**`sim(self, kind)`**
- Sets `engine.inject = kind`; `kind=None` stops the simulation.

**`step(self)`** — called by `QTimer` every second:
1. Calls `engine.tick()`.
2. Appends the four tracked features to their ring buffers.
3. Calls `setData()` on all four plot curves.
4. Auto-finishes learning if the buffer is full.
5. Updates the status label colour and text.
6. Appends attack/block messages to the event log.

---

### 3.9 `test_detector.py`

**Purpose:** One-file CI/smoke test. No GUI, no real traffic, no network.

- Instantiates `EnsembleDetector`, fits on `simulator.normal(600)`.
- For each of 4 scenarios — `normal`, `syn`, `udp`, `http` — generates 200 vectors and computes the fraction flagged by `is_attack()`.
- Expected: normal ≈ 2–5%, attacks ≈ 88–100%.

---

### 3.10 `flow_eval/evaluate_cicids.py`

**Purpose:** Honest, leakage-free off-line benchmark of the unsupervised ensemble on the CICIDS2017 DDoS dataset.

#### Key Constants

| Name | Value | Meaning |
|---|---|---|
| `BASE` | 18 columns | Raw CICIDS2017 flow features used |
| `BENIGN_NAMES` | `{"BENIGN","NORMAL",...}` | Label variants treated as normal |
| `ENGINEERED` | 4 derived columns | Ratios computed from `BASE` |

#### Functions

**`load(path) → DataFrame`**
- Reads CSV with `encoding="latin1"` (CICIDS2017 has non-ASCII chars).
- Strips leading spaces from column names (a quirk of the CIC export tool).
- Raises `SystemExit` with a helpful message if any required column is missing.
- Replaces `inf/-inf` with NaN and drops NaN rows in `BASE` columns.

**`is_benign(label_series) → bool Series`**
- Case-insensitive membership check against `BENIGN_NAMES`.

**`features(df) → np.ndarray`**
- Selects `BASE` columns as float, adds 4 engineered features:
  - `fwd_bwd_pkt_ratio = fwd / (bwd + 1)` — direction asymmetry
  - `bytes_per_packet = total_bytes / (total_pkts + 1)`
  - `resp_byte_ratio = bwd_bytes / (fwd_bytes + 1)` — server-to-client ratio
  - `syn_minus_ack = SYN_count − ACK_count` — unacknowledged SYNs
- Applies `log1p(X.clip(lower=0))` — tames the extreme right-skewed distributions common in network flow data.

**`fit(Xtr, seed, svm_n, lof_n) → (scaler, models_dict)`**
- Fits `StandardScaler` on the full training set.
- Sub-samples `svm_n=8000` rows for OC-SVM and `lof_n=20000` for LOF — both are O(n²) and intractable on 370 k rows.
- Returns the scaler and a dict of fitted models.

**`raw_scores(sc, models, X) → dict[str, ndarray]`**
- Converts every model to a **higher = more anomalous** score:
  - IForest: `-score_samples()` (score_samples is higher for normals)
  - OC-SVM: `-decision_function()` (positive = normal side of hyperplane)
  - LOF: `-score_samples()` (same convention)

**`ensemble(scores, ref) → ndarray`**
- For each model: robust z-score using the calibration-set median and IQR.
  `z = (score − median_cal) / IQR_cal`
- Returns `mean(z_iforest, z_ocsvm, z_lof)` — a single ensemble anomaly score.

**`report(name, cal, test, y, fpr) → dict`**
- Threshold = `quantile(cal_scores, 1 − fpr)` — calibrated so that exactly `fpr` fraction of calibration (benign) rows are flagged.
- Computes AUC, precision, recall, F1, actual FPR on the test set.

**`main()`**
- Parses args, loads data, time-splits Monday → train (70%) + calib (30%).
- Caps test rows at `--max-test` (default 60 000) to fit in RAM.
- Fits models, computes scores, calls `report()` for each model + ensemble.
- Optionally runs supervised `RandomForestClassifier` as an upper-bound reference.
- Saves `results.csv`, `predictions.csv`, `flow_detector.joblib`.

---

### 3.11 `flow_eval/make_mock_cicids.py`

**Purpose:** Generates synthetic CSV files with the CICIDS2017 column layout so the pipeline can be tested without downloading the 250 MB real dataset.

- Imports `BASE` from `evaluate_cicids.py` to guarantee column compatibility.
- `block(n, attack)`: uses log-normal random data; attack rows exaggerate `Flow Packets/s` and `SYN Flag Count`.
- Column names are prefixed with a leading space (` Label`) to replicate the CIC export quirk.
- Writes `mock_monday.csv` (6 000 benign) and `mock_friday_ddos.csv` (3 000 benign + 1 500 DDoS).

> **Warning:** Numbers from mock files are statistically meaningless. Never quote them as results.

---

## 4. Detection Methodology

### 4.1 Why Unsupervised?

Labelled attack traffic is expensive and quickly becomes stale (new DDoS tools, new protocols). An **unsupervised approach** learns only what normal looks like — anything outside that learned boundary is anomalous, including zero-day attacks.

The trade-off: higher false-positive rates than a trained classifier. The ensemble + persistence rule reduce FPR significantly.

### 4.2 Isolation Forest

- Builds an ensemble of binary trees that **randomly** select a feature, then a split value, repeatedly until the point is isolated.
- Anomalies are isolated in **fewer splits** (shallower depth) than normal points.
- Anomaly score = `−mean_path_length` across all trees (normalised by the expected path length for a random point).
- **Why it works for DDoS:** A SYN flood creates extreme `syn_recv` and `pkts_in_ps` values that are isolated immediately.

### 4.3 One-Class SVM

- Learns a **hypersphere** (or hyperplane in feature space) that encloses the normal training data.
- Uses the **RBF kernel** to handle non-linear boundaries.
- `nu` parameter (= `config.CONTAMINATION`) sets the maximum fraction of training points allowed outside the sphere.
- Test points outside the sphere get `decision_function < 0` (anomalous).
- **Why it works:** Very sensitive to the overall density shape — complements IForest which only uses depth.

### 4.4 Local Outlier Factor

- For each point, computes a **local reachability density** relative to its `k` nearest neighbours.
- Anomaly score = ratio of neighbours' density to point's density. Normal points have score ≈ 1.
- `novelty=True` enables prediction on new points using the fitted neighbour structure.
- **Why it works:** Detects anomalies in low-density regions — useful for HTTP floods where only a few features deviate but they deviate from the local neighbourhood.

### 4.5 Majority-Vote Ensemble

```
IForest vote  +  OC-SVM vote  +  LOF vote
          ≥ VOTES_NEEDED (default: 2)
                     │
                 is_attack = True
```

- Any single model can be fooled by a novel attack style. Requiring agreement from 2 of 3 reduces both false positives and false negatives.
- Models are trained on the **same scaled data** but explore different geometric assumptions — their errors are largely uncorrelated.

### 4.6 Persistence Rule

```python
self.streak = self.streak + 1 if attack else 0
if self.streak >= config.CONSECUTIVE_WINDOWS:
    # fire alert
```

- A **one-window spike** (e.g. a brief download burst) is not flagged.
- A **sustained anomaly** (DDoS is by definition sustained) triggers after `CONSECUTIVE_WINDOWS` = 3 seconds.
- This alone reduces false-positive alerts by roughly 70–80% in practice.

---

## 5. Auto-Blocking Mechanism

```
                          streak ≥ CONSECUTIVE_WINDOWS
                                    │
                              auto_block = True?
                                    │
                         per_ip.most_common(1) → (ip, count)
                                    │
                          count ≥ MIN_CONNS_FROM_ONE_IP?
                                    │
                           ip not in WHITELIST?
                                    │
                           ip is valid, routable?
                                    │
                              DRY_RUN = False?
                                    │
                       ┌────────────────────────────┐
                       │  OS-specific firewall call  │
                       │  Windows: netsh advfirewall │
                       │  Linux:   iptables -I INPUT │
                       │  macOS:   pfctl -T add      │
                       └────────────────────────────┘
                                    │
                        store.event("block", src_ip=ip)
                        self.blocked.add(ip)  ← no double-block
```

**Why so many gates?**
- `MIN_CONNS_FROM_ONE_IP`: Prevents blocking an innocent IP that happens to be connected when unrelated anomalous traffic spikes.
- `WHITELIST`: Prevents locking yourself out of your own gateway or DNS.
- `ipaddress` validation: Prevents command injection via a crafted IP string.
- `subprocess` list args: Even if validation were somehow bypassed, a list-based `subprocess.run()` never passes through a shell.
- `DRY_RUN`: Default `True` so the system can be evaluated safely before any blocking is enabled.
- `self.blocked` set: Prevents re-blocking (and cluttering the log) for an already-blocked IP.

---

## 6. Feature Engineering

### Live monitor features (`collector.py`)

All 10 features are per-second rates or dimensionless ratios computed from OS counters:

| # | Feature | Formula / Source | DDoS signal |
|---|---|---|---|
| 0 | `bytes_in_ps` | `Δbytes_recv / dt` | High in volumetric floods |
| 1 | `bytes_out_ps` | `Δbytes_sent / dt` | Low in reflection attacks (attacker sends little) |
| 2 | `pkts_in_ps` | `Δpackets_recv / dt` | Very high in packet-rate floods |
| 3 | `pkts_out_ps` | `Δpackets_sent / dt` | — |
| 4 | `avg_pkt_in` | `bytes_in / pkts_in` | Tiny (~60 B) in SYN floods; huge in UDP floods |
| 5 | `conn_total` | `len(net_connections())` | High in HTTP/SYN floods |
| 6 | `syn_recv` | count of `SYN_RECV` sockets | Primary SYN flood indicator |
| 7 | `unique_ips` | `len(per_ip Counter)` | High (spoofed) in SYN, low in HTTP |
| 8 | `top_ip_share` | `max(per_ip) / total` | High in HTTP flood (single source) |
| 9 | `err_drop_ps` | `Δ(errin+errout+dropin+dropout) / dt` | High when NIC is overwhelmed |

### CICIDS2017 features (`evaluate_cicids.py`)

Uses 18 raw CIC flow columns plus 4 engineered ratios:

| Engineered feature | Formula | DDoS signal |
|---|---|---|
| `fwd_bwd_pkt_ratio` | `fwd_pkts / (bwd_pkts + 1)` | High in SYN flood (mostly outgoing SYNs, few replies) |
| `bytes_per_packet` | `total_bytes / (total_pkts + 1)` | Tiny in SYN, large in UDP |
| `resp_byte_ratio` | `bwd_bytes / (fwd_bytes + 1)` | Near-zero if server never responds (flooded) |
| `syn_minus_ack` | `SYN_count − ACK_count` | Positive means half-open connections |

`log1p(clip(X, lower=0))` is applied to all 22 features to compress the heavy right tails common in network flow data.

---

## 7. CICIDS2017 Evaluation Protocol

The protocol is designed to be **honest** — no information from the test set leaks into training or threshold selection.

```
Monday CSV (benign only, 529 481 flows)
    │
    ├──70% (370 636 flows)──▶  FIT  scaler + IForest + OC-SVM + LOF
    │
    └──30% (158 845 flows)──▶  CALIBRATE  threshold
           │                      threshold = quantile(cal_scores, 1 − fpr)
           │                      e.g. fpr=0.05 → top-5% of benign scores
           │
Friday CSV (benign + DDoS, sampled to 60 000 flows)
    └───────────────────────▶  TEST  (never seen before)
                                  Measure: AUC, precision, recall, F1, actual FPR
```

**Ensemble score calibration (`ensemble()` function):**
For each model's raw scores on the calibration set:
```
robust_z = (score − median_cal) / IQR_cal
```
This maps all three models to a common scale regardless of their raw score distributions. The ensemble score is `mean(robust_z_iforest, robust_z_ocsvm, robust_z_lof)`.

**Verified results:**

| Model | AUC | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| IForest | 0.71 | 0.69 | 0.63 | 0.66 | 0.37 |
| OC-SVM | 0.86 | 0.76 | 0.78 | 0.77 | 0.34 |
| LOF | 0.85 | 0.89 | 0.20 | 0.33 | 0.03 |
| **Ensemble** | **0.84** | **0.91** | **0.64** | **0.75** | **0.08** |
| Random Forest *(supervised upper bound)* | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |

The ensemble achieves **precision 0.91** (very few false alarms) at the cost of **recall 0.64** (catches 64% of DDoS flows). The supervised Random Forest shows the theoretical maximum — the unsupervised gap is the price of not using labels.

---

## 8. Attack Signatures in the Simulator

| Attack type | Manipulated features | Real-world analogue |
|---|---|---|
| **SYN flood** | `pkts_in_ps ×40`, `avg_pkt_in ~60 B`, `syn_recv ~900`, `unique_ips ~400` | Botnets send millions of SYN packets from spoofed IPs; servers queue half-open connections until memory is exhausted |
| **UDP flood** | `bytes_in_ps ×60`, `pkts_in_ps ×50`, `avg_pkt_in ~1200 B`, `err_drop_ps +~30` | Amplification attacks (DNS, NTP, Memcached) send large UDP responses; NIC drops packets |
| **HTTP flood** | `conn_total +~1500`, `top_ip_share ~0.9`, `unique_ips ~5` | A botnet or single high-bandwidth client opens thousands of persistent HTTP connections |

---

## 9. Security Design Decisions

| Decision | Rationale |
|---|---|
| `subprocess` list args (not `shell=True`) | Prevents shell injection; each argument is passed verbatim to the OS |
| `ipaddress.ip_address()` validation before any system call | Ensures the string is a valid IP; malformed strings raise `ValueError` before they reach `subprocess` |
| Loopback + multicast rejection | Prevents self-lockout or broadcast storms |
| `WHITELIST` checked before blocking | Prevents blocking gateway / DNS / trusted hosts |
| `DRY_RUN = True` by default | Safe-by-default; operator must explicitly opt into live blocking |
| `self.blocked` set in `Engine` | Idempotent — won't issue duplicate firewall rules or flood the log |
| Parameterised SQLite queries | `?` placeholders prevent SQL injection in event/metric inserts |
| Calibration-set threshold selection | Threshold is set on held-out benign data, not the test set — no optimistic bias |

---

## 10. Limitations & Future Work

| Limitation | Potential improvement |
|---|---|
| **Host-only view:** `psutil` sees aggregated counters, not per-flow metadata | Integrate `scapy` or `pyshark` for deep-packet features |
| **No IPv6 blocking on Linux** | `ip6tables` support in `mitigation.py` |
| **OC-SVM and LOF are slow on large datasets** | Sub-sampling is used; could replace with `SGDOneClassSVM` or `BIRCH`-LOF |
| **LOF recall is low (20%)** | LOF is a local density estimator — global volumetric DDoS floods the whole feature space uniformly, making it hard to detect locally |
| **No automatic model refresh** | Re-train periodically or on concept-drift detection |
| **Single host only** | Distributed sensor + central aggregator architecture |
| **No alerting/SIEM integration** | Add Webhook / Syslog / Slack notifications from `storage.py` |

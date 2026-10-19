# AI-Driven Network Monitor

An **unsupervised, real-time DDoS / anomaly detection system** built with Python and `psutil` — no packet-capture driver required. A three-model ensemble (Isolation Forest + One-Class SVM + LOF) learns what *your* machine's traffic looks like and alerts (or auto-blocks) when something unusual appears.

> For a deep dive into every file, function, and algorithm, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Features

| Capability | Detail |
|---|---|
| **Live traffic collection** | `psutil` reads OS-level byte/packet counters and connection tables every second |
| **Ensemble detection** | IsolationForest + One-Class SVM + LOF — majority vote, configurable threshold |
| **Persistence rule** | Alert fires only after N consecutive anomalous windows (no single-spike false positives) |
| **Auto-mitigation** | Optionally issues `netsh` / `iptables` / `pfctl` firewall rules to block the offending IP |
| **SQLite event log** | Every alert, block, and training event is stored with a timestamp |
| **PyQt5 dashboard** | Real-time plots of bytes/s and connection counts, live vote display, simulation buttons |
| **Attack simulation** | Inject synthetic SYN flood, UDP flood, or HTTP flood vectors for demo/testing |
| **CICIDS2017 evaluation** | Off-line benchmark script (`flow_eval/evaluate_cicids.py`) measures AUC, precision, recall, F1 |

---

## Project Structure

```
network/
├── config.py              # All tuneable settings (single source of truth)
├── collector.py           # psutil → 10-feature vector per 1-second window
├── detector.py            # EnsembleDetector (IForest + OC-SVM + LOF)
├── simulator.py           # Synthetic normal / attack vectors (no real traffic needed)
├── engine.py              # Glue: collector → detector → persistence rule → mitigation
├── mitigation.py          # OS-aware IP blocking (netsh / iptables / pfctl), dry-run safe
├── storage.py             # SQLite schema + event/metric helpers
├── gui.py                 # PyQt5 + pyqtgraph real-time dashboard  ← main entry point
├── test_detector.py       # Headless self-test (no GUI, no real traffic)
├── requirements.txt       # Full deps including PyQt5 (local / host use)
├── requirements-eval.txt  # Headless deps only (Docker / CI)
├── Dockerfile             # python:3.12-slim image, runs headless
├── .dockerignore
├── ARCHITECTURE.md        # In-depth technical reference
└── flow_eval/
    ├── evaluate_cicids.py   # Off-line benchmark on CICIDS2017 CSVs
    └── make_mock_cicids.py  # Generates tiny mock CSVs for smoke-testing only
```

---

## Quick Start

### 1. Create a virtual environment (recommended: `uv`)

```powershell
# Install uv once if you don't have it
pip install uv

# Create a Python 3.12 venv and activate it
uv venv --python 3.12
.venv\Scripts\Activate.ps1     # Windows PowerShell
# source .venv/bin/activate    # Linux / macOS
```

### 2. Install dependencies

```powershell
# Fast install with uv (recommended)
uv pip install -r requirements.txt

# Or standard pip
pip install -r requirements.txt
```

> **Windows:** `psutil` works out of the box.
> **Linux / macOS:** reading all connections may need `sudo python gui.py`.

### 3. Headless self-test (no GUI, no real traffic)

```powershell
python test_detector.py
```

Verified output on Python 3.12 + scikit-learn 1.9:

```
normal  flagged   2.5%
syn     flagged 100.0%
udp     flagged 100.0%
http    flagged 100.0%
```

### 4. Launch the dashboard

```powershell
python gui.py
```

On first run (no saved model) click **Train synthetic baseline** — trains on 600 synthetic normal windows and saves `model.joblib`. You can then:

- **Learn baseline (live)** — trains on your real traffic (~2 min, click again to finish).
- **Simulate SYN / UDP flood** — watch the detector fire in real time.
- **Auto-block checkbox** — enable firewall blocking (also requires `AUTO_BLOCK = True` in `config.py`).

---

## Configuration (`config.py`)

| Setting | Default | Meaning |
|---|---|---|
| `SAMPLE_INTERVAL` | `1.0` s | Window length |
| `BASELINE_SECONDS` | `120` | Minimum live-learning windows before training |
| `CONTAMINATION` | `0.02` | Expected anomaly fraction used by models |
| `VOTES_NEEDED` | `2` | Models that must agree to flag a window |
| `CONSECUTIVE_WINDOWS` | `3` | Alert only after this many consecutive flagged windows |
| `MIN_CONNS_FROM_ONE_IP` | `50` | Connections from one IP to trigger a block |
| `AUTO_BLOCK` | `False` | Enable firewall blocking (safe default: off) |
| `DRY_RUN` | `True` | Print firewall commands instead of running them |
| `MODEL_PATH` | `model.joblib` | Where the trained model is saved/loaded |
| `DB_PATH` | `events.db` | SQLite database path |
| `WHITELIST` | `["127.0.0.1","::1"]` | IPs that will never be blocked |

> **Important:** Add your gateway, DNS server, and trusted IPs to `WHITELIST` before enabling `AUTO_BLOCK`.

---

## Features Collected (per 1-second window)

| Feature | Description |
|---|---|
| `bytes_in_ps` | Bytes received per second |
| `bytes_out_ps` | Bytes sent per second |
| `pkts_in_ps` | Packets received per second |
| `pkts_out_ps` | Packets sent per second |
| `avg_pkt_in` | Average inbound packet size |
| `conn_total` | Total open connections |
| `syn_recv` | Connections stuck in `SYN_RECV` state |
| `unique_ips` | Number of distinct remote IPs |
| `top_ip_share` | Fraction of connections from the single busiest IP |
| `err_drop_ps` | Errors + dropped packets per second |

---

## CICIDS2017 Off-Line Evaluation

Benchmarks the same unsupervised ensemble against the public [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset.

### 1. Download the data

Get the **MachineLearningCVE** CSVs from the University of New Brunswick "IDS 2017" page. Place both files inside `flow_eval/`:

- `Monday-WorkingHours.pcap_ISCX.csv` — benign only (training + calibration)
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` — benign + DDoS (test set)

### 2. Run the evaluation

```powershell
cd flow_eval
python evaluate_cicids.py `
    --train Monday-WorkingHours.pcap_ISCX.csv `
    --test  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv `
    --fpr 0.05 `
    --baseline
```

### Verified results (Python 3.12, scikit-learn 1.9.1)

```
train-file labels: {'BENIGN': 529481}
benign train=370636  calibration=158845
test flows=60000  attack share=57.0%

                                 model    AUC  precision  recall     F1    FPR  threshold
                              iforest 0.7095     0.6909  0.6289 0.6584 0.3723     0.5570
                                ocsvm 0.8563     0.7554  0.7837 0.7693 0.3359    -0.0003
                                  lof 0.8481     0.8888  0.2028 0.3302 0.0336     2.8401
             ENSEMBLE (mean robust-z) 0.8410     0.9112  0.6393 0.7514 0.0825     2.5957
RandomForest (supervised, time-split) 0.9998     0.9983  0.9990 0.9986 0.0019     0.5000

Share of flows flagged per label:
 BENIGN    0.0825   ← false-positive rate
 DDoS      0.6393   ← recall
```

### CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `--train` | *(required)* | Benign-heavy day CSV |
| `--test` | *(required)* | Attack-day CSV(s) — accepts multiple paths |
| `--fpr` | `0.05` | Target false-positive rate for threshold calibration |
| `--max-test` | `60000` | Cap on test rows sampled (memory guard) |
| `--baseline` | off | Also run a supervised Random Forest upper-bound |
| `--dump` | `predictions.csv` | Per-row predictions output |
| `--out` | `flow_detector.joblib` | Saved scaler + models bundle |

### No-leakage protocol

```
Monday CSV  ──70%──▶  Train   (benign only, unsupervised)
            ──30%──▶  Calib   (threshold → target FPR on held-out benign)
Friday CSV  ────────▶  Test    (benign + DDoS, never seen before)
```

### Smoke-test (no real CSVs needed)

```powershell
cd flow_eval
python make_mock_cicids.py          # writes mock_monday.csv + mock_friday_ddos.csv
python evaluate_cicids.py --train mock_monday.csv --test mock_friday_ddos.csv --fpr 0.05
```

> Numbers from mock files are meaningless — use only to verify the pipeline runs.

---

## Docker (headless / CI / evaluation)

The image is built on `python:3.12-slim` and runs without a display. The GUI must be used on the host.

### Build

```bash
docker build -t ai-network-monitor .
```

### Headless self-test

```bash
docker run --rm ai-network-monitor
```

### CICIDS2017 evaluation (mount your CSV directory)

```bash
# Windows PowerShell
docker run --rm `
  -v "${PWD}\flow_eval:/app/flow_eval" `
  -w /app/flow_eval `
  ai-network-monitor `
  python evaluate_cicids.py `
    --train Monday-WorkingHours.pcap_ISCX.csv `
    --test  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv `
    --fpr 0.05 --baseline

# Linux / macOS
docker run --rm \
  -v "$(pwd)/flow_eval":/app/flow_eval \
  -w /app/flow_eval \
  ai-network-monitor \
  python evaluate_cicids.py \
    --train Monday-WorkingHours.pcap_ISCX.csv \
    --test  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
    --fpr 0.05 --baseline
```

### Interactive shell

```bash
docker run --rm -it ai-network-monitor bash
```

### Docker file summary

| File | Purpose |
|---|---|
| `Dockerfile` | `python:3.12-slim`, installs headless deps, default CMD runs self-test |
| `requirements-eval.txt` | Headless deps only (no Qt) — used inside Docker |
| `requirements.txt` | Full deps including PyQt5 — for host / local use |
| `.dockerignore` | Excludes `.git`, CSVs, model files, `__pycache__` from build context |

---

## Running Tests

```powershell
python test_detector.py
```

No network access. No GUI. No extra deps beyond `requirements.txt`.

---

## License

This project is provided for educational purposes. See individual file headers for details.


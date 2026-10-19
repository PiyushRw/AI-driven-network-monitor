"""
Evaluate the 3-model anomaly ensemble on the REAL CICIDS2017 CSVs (MachineLearningCVE folder).

Protocol (unsupervised, honest):
  * TRAIN  : benign flows only, first 70% of the Monday file (file order = time order)
  * CALIB  : last 30% of Monday (benign) -> used ONLY to choose the alert threshold (target FPR)
  * TEST   : Friday-DDoS file (benign + DDoS) -> never seen in training or calibration
  * Optional supervised baseline (Random Forest) for comparison, time-split inside the test file.

Usage:
  python evaluate_cicids.py --train Monday-WorkingHours.pcap_ISCX.csv \
      --test Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --fpr 0.05 --baseline
"""
import argparse
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# Raw CICIDS2017 flow columns we use (names AFTER stripping the leading spaces in the CSV header)
BASE = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Flow IAT Mean", "Fwd IAT Mean", "SYN Flag Count", "ACK Flag Count", "PSH Flag Count",
        "RST Flag Count", "Average Packet Size", "Init_Win_bytes_forward", "Init_Win_bytes_backward"]
ENGINEERED = ["fwd_bwd_pkt_ratio", "bytes_per_packet", "resp_byte_ratio", "syn_minus_ack"]


def load(path):
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    missing = [c for c in BASE + ["Label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"{path}: missing columns {missing}\nFound: {list(df.columns)[:15]} ...")
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=BASE).reset_index(drop=True)
    return df


def features(df):
    X = df[BASE].astype(float).copy()
    X["fwd_bwd_pkt_ratio"] = X["Total Fwd Packets"] / (X["Total Backward Packets"] + 1)
    X["bytes_per_packet"] = (X["Total Length of Fwd Packets"] + X["Total Length of Bwd Packets"]) / \
                            (X["Total Fwd Packets"] + X["Total Backward Packets"] + 1)
    X["resp_byte_ratio"] = X["Total Length of Bwd Packets"] / (X["Total Length of Fwd Packets"] + 1)
    X["syn_minus_ack"] = X["SYN Flag Count"] - X["ACK Flag Count"]
    return np.log1p(X.clip(lower=0)).values        # log1p tames the heavy-tailed counters


def fit(Xtr, seed=0, svm_n=8000, lof_n=20000):
    sc = StandardScaler().fit(Xtr)
    Z = sc.transform(Xtr)
    rng = np.random.default_rng(seed)
    sub = lambda n: Z[rng.choice(len(Z), min(n, len(Z)), replace=False)]   # SVM/LOF are slow on big data
    return sc, {
        "iforest": IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(Z),
        "ocsvm": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(sub(svm_n)),
        "lof": LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1).fit(sub(lof_n)),
    }


def raw_scores(sc, models, X):
    """Higher = more anomalous, for every model."""
    Z = sc.transform(X)
    return {"iforest": -models["iforest"].score_samples(Z),
            "ocsvm": -models["ocsvm"].decision_function(Z),
            "lof": -models["lof"].score_samples(Z)}


def ensemble(scores, ref):
    """Mean of robust z-scores (median/IQR taken from the benign calibration set)."""
    out = []
    for k, s in scores.items():
        med = np.median(ref[k]); iqr = np.subtract(*np.percentile(ref[k], [75, 25])) or 1.0
        out.append((s - med) / iqr)
    return np.mean(out, axis=0)


def report(name, cal, test, y, fpr):
    thr = np.quantile(cal, 1 - fpr)
    pred = test > thr
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return {"model": name, "AUC": roc_auc_score(y, test), "precision": p, "recall": r, "F1": f,
            "FPR": (pred & (y == 0)).sum() / max((y == 0).sum(), 1), "threshold": thr}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True, help="benign-heavy day, e.g. Monday")
    ap.add_argument("--test", required=True, nargs="+", help="attack-day CSV(s)")
    ap.add_argument("--fpr", type=float, default=0.05)
    ap.add_argument("--max-test", type=int, default=60000)
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--out", default="flow_detector.joblib")
    a = ap.parse_args()

    tr = load(a.train)
    tr = tr[tr["Label"].str.upper() == "BENIGN"].reset_index(drop=True)
    cut = int(len(tr) * 0.7)
    Xtr, Xcal = features(tr.iloc[:cut]), features(tr.iloc[cut:])
    print(f"benign train={len(Xtr)}  calibration={len(Xcal)}")

    te = pd.concat([load(p) for p in a.test], ignore_index=True)
    te_full = te
    if len(te) > a.max_test:
        te = te.sample(a.max_test, random_state=0).sort_index()
    y = (te["Label"].str.upper() != "BENIGN").astype(int).values
    print(f"test flows={len(te)}  attack share={y.mean():.1%}")
    print(te["Label"].value_counts().to_string())
    if y.sum() == 0 or y.sum() == len(y):
        raise SystemExit("test set needs both benign and attack rows")

    sc, models = fit(Xtr)
    s_cal, s_te = raw_scores(sc, models, Xcal), raw_scores(sc, models, features(te))
    rows = [report(k, s_cal[k], s_te[k], y, a.fpr) for k in s_te]
    e_cal, e_te = ensemble(s_cal, s_cal), ensemble(s_te, s_cal)
    rows.append(report("ENSEMBLE (mean robust-z)", e_cal, e_te, y, a.fpr))

    if a.baseline:   # supervised upper bound: needs labels, time-split inside the test file
        d = te_full.reset_index(drop=True); half = len(d) // 2
        Xd, yd = features(d), (d["Label"].str.upper() != "BENIGN").astype(int).values
        tag = "time-split"
        if len(set(yd[:half])) < 2 or len(set(yd[half:])) < 2:   # one class missing in a half
            from sklearn.model_selection import train_test_split
            idx_tr, idx_te = train_test_split(np.arange(len(d)), test_size=0.5, stratify=yd, random_state=0)
            tag = "random split (time-split impossible: a half had one class)"
        else:
            idx_tr, idx_te = np.arange(half), np.arange(half, len(d))
        rf = RandomForestClassifier(n_estimators=150, n_jobs=-1, random_state=0).fit(Xd[idx_tr], yd[idx_tr])
        pr = rf.predict_proba(Xd[idx_te])[:, 1]; pb = pr > 0.5; yt = yd[idx_te]
        p, r, f, _ = precision_recall_fscore_support(yt, pb, average="binary", zero_division=0)
        rows.append({"model": f"RandomForest (supervised, {tag})", "AUC": roc_auc_score(yt, pr),
                     "precision": p, "recall": r, "F1": f,
                     "FPR": (pb & (yt == 0)).sum() / max((yt == 0).sum(), 1), "threshold": 0.5})

    res = pd.DataFrame(rows).round(4)
    print("\n", res.to_string(index=False))
    res.to_csv("results.csv", index=False)

    thr = np.quantile(e_cal, 1 - a.fpr)
    pred = e_te > thr
    per = pd.DataFrame({"Label": te["Label"].values, "flagged": pred}).groupby("Label")["flagged"].mean().round(4)
    print("\nShare of flows flagged per label (benign = false-positive rate, attacks = recall):\n", per.to_string())
    joblib.dump({"scaler": sc, "models": models, "cal_scores": s_cal, "ens_threshold": thr,
                 "features": BASE + ENGINEERED}, a.out)
    print(f"\nsaved {a.out} and results.csv")


if __name__ == "__main__":
    main()

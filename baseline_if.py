r"""Isolation Forest baseline on the same 5 features, scaling and split as the autoencoder.
Run:  python baseline_if.py      (needs data\features.csv and data\scaler.json from catavo_ml.py)"""
import json, os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

DATA = os.environ.get("CATAVO_DATA", r"C:\catavo-ml\data")
FEATURES = ["session_duration", "failed_before_login", "new_ip", "login_gap"]    # same 4 features as the autoencoder


def prep(df):
    x = df[FEATURES].astype(float).copy()
    x["login_gap"] = np.log1p(x["login_gap"])
    return x.values


def load_scaler():
    sc = json.load(open(os.path.join(DATA, "scaler.json")))
    return np.array(sc["lo"]), np.array(sc["span"])


def score_if(df):
    """Return (anomaly score, threshold). Higher score = more anomalous; flag if score > threshold."""
    m = joblib.load(os.path.join(DATA, "if_model.joblib"))
    thr = json.load(open(os.path.join(DATA, "if_threshold.json")))["threshold"]
    lo, span = load_scaler()
    return -m.score_samples((prep(df) - lo) / span), thr


if __name__ == "__main__":
    np.random.seed(42)                       # same split as catavo_ml.py
    df = pd.read_csv(os.path.join(DATA, "features.csv"))
    x = prep(df)
    idx = np.random.permutation(len(x))
    cut = int(0.8 * len(x))
    lo, span = load_scaler()
    tr, va = (x[idx[:cut]] - lo) / span, (x[idx[cut:]] - lo) / span

    m = IsolationForest(n_estimators=200, random_state=42).fit(tr)
    s_tr, s_va = -m.score_samples(tr), -m.score_samples(va)
    thr = float(np.percentile(s_tr, 99))     # same rule as the autoencoder: 99th percentile of normal
    print(f"threshold (99th pct of training score) = {thr:.4f}")
    print(f"validation false-positive rate = {(s_va > thr).mean() * 100:.1f}%  ({(s_va > thr).sum()} of {len(s_va)})")
    joblib.dump(m, os.path.join(DATA, "if_model.joblib"))
    json.dump({"threshold": thr}, open(os.path.join(DATA, "if_threshold.json"), "w"))
    print("saved if_model.joblib and if_threshold.json in", DATA)

r"""CAT-AVO features v2: two normal batches (evening 13 Oct and daytime 14 Oct).
Run:  python features2.py     (needs data\keycloak_all.csv, the full Splunk export)
Writes: features.csv (training rows), baseline_ips.json, keycloak_normal_split.csv (all clean normal events, tagged
batch and part = train / holdout). Old files are copied to data\v1 first.
Holdout = the last HOLD logins of each user in batch B2; they are never used for training."""
import json, os, shutil
import pandas as pd

DATA = os.environ.get("CATAVO_DATA", r"C:\catavo-ml\data")
P = lambda n: os.path.join(DATA, n)
IST = "Asia/Kolkata"
WINDOWS = [("B1", "2026-10-13 20:00", "2026-10-14 01:00"),
           ("B2", "2026-10-14 13:19", "2026-10-14 15:00")]
HOLD = 40
ALLOWED = {"937444ef-c098-428f-a308-845b98c6afc3": "192.168.100.50",    # user1
           "a2bff448-a23d-4de0-bfa8-6e97263d9815": "192.168.100.70"}    # user2
COLS = ["login_hour", "session_duration", "failed_before_login", "new_ip", "login_gap"]

# 1. keep the old (v1) files
v1 = P("v1")
if not os.path.isdir(v1):
    os.makedirs(v1)
    for f in ("features.csv", "baseline_ips.json", "model.pt", "scaler.json", "threshold.json", "if_model.joblib",
              "if_threshold.json", "loss_history.csv", "training_loss.png", "eval_summary.csv", "eval_runs.csv",
              "eval_output.txt", "keycloak_normal.csv"):
        if os.path.exists(P(f)):
            shutil.copy(P(f), v1)
    print("old files copied to", v1)

# 2. read, keep only the clean normal windows and the two normal source IPs
d = pd.read_csv(P("keycloak_all.csv"))
d["t"] = pd.to_datetime(d["_time"], utc=True, format="ISO8601").dt.tz_convert(IST)
d = d[d.userId.notna() & d.type.isin(["LOGIN", "LOGOUT", "LOGIN_ERROR"])].copy()
ip_ok = d.ipAddress.isin(ALLOWED.values())
d = d[ip_ok].sort_values("t").reset_index(drop=True)
print("events kept per window and type:")

parts = []
for name, a, b in WINDOWS:
    w = d[(d.t >= pd.Timestamp(a, tz=IST)) & (d.t < pd.Timestamp(b, tz=IST))].copy()
    w["batch"] = name
    w["part"] = "train"
    if name == "B2":                                    # chronological holdout: last HOLD logins per user
        for u, g in w[w.type == "LOGIN"].groupby("userId"):
            ordered = g.sort_values("t")
            if len(ordered) > HOLD:
                cut = ordered.iloc[len(ordered) - HOLD].t
                w.loc[(w.userId == u) & (w.t >= cut), "part"] = "holdout"
    print(name, w.groupby(["type", "part"]).size().to_dict())
    parts.append(w)
allev = pd.concat(parts, ignore_index=True)
allev.drop(columns=["t"]).to_csv(P("keycloak_normal_split.csv"), index=False)

# 3. training features (same definitions as features.py), per batch so a gap never spans the break between batches
rows = []
for name, w in allev.groupby("batch"):
    logins = w[w.type == "LOGIN"].copy()
    errors = w[w.type == "LOGIN_ERROR"]
    lo = w[w.type == "LOGOUT"].drop_duplicates("sessionId").set_index("sessionId")["t"]
    logins["login_hour"] = (logins.t.dt.hour + logins.t.dt.minute / 60 - 4) % 24
    logins["session_duration"] = (logins.sessionId.map(lo) - logins.t).dt.total_seconds()
    logins["failed_before_login"] = [
        len(errors[(errors.userId == r.userId) & (errors.t < r.t) & (errors.t >= r.t - pd.Timedelta(minutes=5))])
        for r in logins.itertuples()]
    logins["new_ip"] = [int(r.ipAddress != ALLOWED[r.userId]) for r in logins.itertuples()]
    logins["login_gap"] = logins.groupby("userId").t.diff().dt.total_seconds()
    rows.append(logins)
f = pd.concat(rows, ignore_index=True)
f["login_gap"] = f.login_gap.fillna(f.login_gap.median())      # first login of a batch has no previous login
f = f[f.part == "train"].dropna(subset=COLS)
f[["userId", "t"] + COLS].to_csv(P("features.csv"), index=False)
json.dump({u: [ip] for u, ip in ALLOWED.items()}, open(P("baseline_ips.json"), "w"), indent=1)

print("\ntraining rows:", len(f), " per batch:", f.groupby("batch").size().to_dict())
print(f[COLS].describe().round(2).T[["mean", "std", "min", "max"]])
print("holdout logins:", int(((allev.part == "holdout") & (allev.type == "LOGIN")).sum()))

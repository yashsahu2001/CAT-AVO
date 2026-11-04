import json, sys
import pandas as pd

SRC = sys.argv[1] if len(sys.argv) > 1 else r"C:\catavo-ml\data\keycloak_normal.csv"
OUT = sys.argv[2] if len(sys.argv) > 2 else r"C:\catavo-ml\data\features.csv"
BASE = sys.argv[3] if len(sys.argv) > 3 else r"C:\catavo-ml\data\baseline_ips.json"
START = "2026-10-13 20:00"   # skip the manual tests from Oct 12

d = pd.read_csv(SRC)
d["t"] = pd.to_datetime(d["_time"], utc=True).dt.tz_convert("Asia/Kolkata")
d = d[d["t"] >= pd.Timestamp(START, tz="Asia/Kolkata")].sort_values("t").reset_index(drop=True)

logins = d[d.type == "LOGIN"].copy()
errors = d[d.type == "LOGIN_ERROR"]
lo = d[d.type == "LOGOUT"].drop_duplicates("sessionId").set_index("sessionId")["t"]

# day starts at 04:00 (quietest hour) so late-evening and after-midnight logins stay close together
logins["login_hour"] = (logins.t.dt.hour + logins.t.dt.minute / 60 - 4) % 24
logins["session_duration"] = (logins.sessionId.map(lo) - logins.t).dt.total_seconds()

def fails(r):
    e = errors[(errors.userId == r.userId) & (errors.t < r.t) & (errors.t >= r.t - pd.Timedelta(minutes=5))]
    return len(e)
logins["failed_before_login"] = logins.apply(fails, axis=1)

baseline = logins.groupby("userId").ipAddress.agg(lambda s: sorted(set(s))).to_dict()
logins["new_ip"] = [int(r.ipAddress not in baseline[r.userId]) for r in logins.itertuples()]

gap = logins.groupby("userId").t.diff().dt.total_seconds()
logins["login_gap"] = gap.fillna(gap.median())

cols = ["login_hour", "session_duration", "failed_before_login", "new_ip", "login_gap"]
out = logins.dropna(subset=cols)[["userId", "t"] + cols]
out.to_csv(OUT, index=False)
json.dump(baseline, open(BASE, "w"), indent=1)
print("rows:", len(out), "dropped (no logout):", len(logins) - len(out))
print(out[cols].describe().round(2).T[["mean", "std", "min", "max"]])
print(baseline)

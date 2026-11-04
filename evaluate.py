r"""CAT-AVO evaluation (Task 21). Offline: scores the attack runs and the normal traffic with the
autoencoder, the Isolation Forest and the two Splunk rules.
  python evaluate.py [--normal2 C:\catavo-ml\data\keycloak_normal2.csv]
Needs in the data folder: keycloak_normal.csv, monitor_log.csv, attack_runs_kali.csv, attack_runs_laptop.csv,
features.csv, baseline_ips.json and the trained models."""
import argparse, json, os
import numpy as np
import pandas as pd

import baseline_if
import catavo_ml
import monitor

DATA = os.environ.get("CATAVO_DATA", r"C:\catavo-ml\data")
START = pd.Timestamp("2026-10-13 20:00", tz="Asia/Kolkata")
ALLOWED = {"192.168.100.50", "192.168.100.70"}
HOST_IP = {"catavo-kali": "192.168.100.40", "YashSahu": "192.168.100.70"}
FEATS = ["login_hour", "session_duration", "failed_before_login", "new_ip", "login_gap"]
P = lambda n: os.path.join(DATA, n)


def clean(d, after=None, keep=()):
    d = d.copy()
    d["t"] = pd.to_datetime(d["_time"], utc=True, format="ISO8601")
    d = d[d.type.isin(["LOGIN", "LOGIN_ERROR"]) & d.userId.notna()].rename(columns={"ipAddress": "ip"})
    if after is not None:
        d = d[d.t >= after]
    return d.sort_values("t")[["t", "type", "userId", "ip", *keep]].reset_index(drop=True)


def load_events(path, after=None):
    return clean(pd.read_csv(path), after)


def featurize(ev, base, md, mg):
    F = monitor.Features(base, md, mg)
    out = pd.DataFrame([F.row(r._asdict()) for r in ev.itertuples(index=False)])
    for c in ("t", "type", "userId", "ip"):
        out[c] = ev[c].values if c != "t" else list(ev["t"])
    return out


def rule_flags(df):
    """Rule 1: >=5 LOGIN_ERROR from the same IP within the trailing 5 minutes. Rule 2: LOGIN from an IP outside the allow-list."""
    df = df.reset_index(drop=True)
    r1 = np.zeros(len(df), bool)
    t = pd.to_datetime(pd.Series(list(df.t)), utc=True, format="ISO8601").reset_index(drop=True)
    for ip, g in df[df.type == "LOGIN_ERROR"].groupby("ip"):
        times = t[g.index].values
        for i, idx in enumerate(g.index):
            r1[df.index.get_loc(idx)] = (times[i] - times[: i + 1] < np.timedelta64(300, "s")).sum() >= 5
    r2 = ((df.type == "LOGIN") & ~df.ip.isin(ALLOWED)).values
    return r1, r2


def rules_grouped(df, key):
    """Apply the rules to each group on its own, so one run cannot leak into the next."""
    r1, r2 = np.zeros(len(df), bool), np.zeros(len(df), bool)
    for _, g in df.groupby(key, sort=False):
        a_, b_ = rule_flags(g)
        pos = df.index.get_indexer(g.index)
        r1[pos], r2[pos] = a_, b_
    return r1, r2


def flags_for(df, det, key=None):
    r1, r2 = rules_grouped(df, key) if key else rule_flags(df)
    m, lo, span, thr = det["ae"]
    out = {}

    def ae(d):
        e = catavo_ml.errors(m, (catavo_ml.prep(d) - lo) / span)
        return e > thr

    out["Autoencoder"] = ae(df)
    for name, col in (("AE, gap frozen", "login_gap"), ("AE, new_ip frozen", "new_ip"),
                      ("AE, failed-logins frozen", "failed_before_login")):
        d = df.copy()
        d[col] = det["med"][col]
        out[name] = ae(d)
    s, th = baseline_if.score_if(df)
    out["Isolation Forest"] = s > th
    out["Isolation Forest, 95th pct"] = s > det["if95"]
    out["Rule 1 (brute force)"], out["Rule 2 (unknown IP)"] = r1, r2
    out["Rules 1 OR 2"] = r1 | r2
    return pd.DataFrame(out, index=df.index)


def label_attacks(log, runs):
    log = log.copy()
    log["t"] = pd.to_datetime(log.event_time, utc=True, format="ISO8601")
    log = log.drop_duplicates(["event_time", "type", "userId", "ip"], keep="last").sort_values("t").reset_index(drop=True)
    log["run_id"], log["scenario"], log["source"] = None, None, None
    for r in runs.itertuples():
        ip = HOST_IP.get(r.host)
        if ip is None:
            continue
        m = (log.ip == ip) & (log.t >= r.start - pd.Timedelta(seconds=2)) & (log.t <= r.end + pd.Timedelta(seconds=15))
        log.loc[m, ["run_id", "scenario", "source"]] = [r.run_id, r.scenario, "Kali (new IP)" if ip.endswith(".40") else "laptop (known IP)"]
    return log[log.run_id.notna()].reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal2", help="optional fresh normal events (Splunk export) for an unbiased false-positive rate")
    a = ap.parse_args()

    base = json.load(open(P("baseline_ips.json")))
    ft = pd.read_csv(P("features.csv"))
    med = {c: float(ft[c].median()) for c in FEATS}
    model, lo, span, thr = catavo_ml.load_model()
    det = {"ae": (model, lo, span, thr), "med": med}

    runs = pd.concat([pd.read_csv(P("attack_runs_kali.csv")), pd.read_csv(P("attack_runs_laptop.csv"))])
    runs["start"] = pd.to_datetime(runs.start, utc=True, format="ISO8601")
    runs["end"] = pd.to_datetime(runs.end, utc=True, format="ISO8601")
    atk = label_attacks(pd.read_csv(P("monitor_log.csv")), runs)
    meta0 = atk.drop_duplicates("run_id").set_index("run_id")[["scenario", "source"]]
    parts = []
    for rid, g in atk.groupby("run_id", sort=False):       # every run starts with fresh state (an isolated incident)
        f = featurize(g[["t", "type", "userId", "ip"]].reset_index(drop=True), base, med["session_duration"], med["login_gap"])
        f["run_id"] = rid
        parts.append(f)
    atk = pd.concat(parts, ignore_index=True)
    atk["scenario"], atk["source"] = atk.run_id.map(meta0.scenario), atk.run_id.map(meta0.source)
    atk_f = atk
    missing = sorted(set(runs.run_id) - set(atk.run_id))
    if missing:
        print(f"WARNING: {len(missing)} runs have no scored events (excluded): {missing[:5]}...")

    sp = pd.read_csv(P("keycloak_normal_split.csv"))
    pieces = []
    for b, g in sp.groupby("batch"):                       # each batch is featurized on its own (fresh state)
        ev = clean(g, keep=("part", "batch"))
        f_ = featurize(ev[["t", "type", "userId", "ip"]], base, med["session_duration"], med["login_gap"])
        f_["part"], f_["batch"] = ev.part.values, ev.batch.values
        pieces.append(f_)
    nrm_all = pd.concat(pieces, ignore_index=True)
    nrm = nrm_all[nrm_all.part == "train"].reset_index(drop=True)          # in-sample
    hold = nrm_all[nrm_all.part == "holdout"].reset_index(drop=True)       # never used for training
    det["if95"] = float(np.percentile(baseline_if.score_if(nrm)[0], 95))      # looser threshold, for comparison
    fa, fn, fh = flags_for(atk_f, det, key="run_id"), flags_for(nrm, det), flags_for(hold, det)
    dets = list(fa.columns)

    print(f"\nattack attempts scored: {len(atk)} in {atk.run_id.nunique()} runs;  normal attempts: {len(nrm)} in-sample, {len(hold)} holdout")
    print("in-sample FPR by batch (evening B1 / daytime B2):")
    print(fn.groupby(nrm.batch.values).mean().mul(100).round(1)[["Autoencoder", "Isolation Forest"]].to_string())
    summ = pd.DataFrame({"in-sample FPR %": (fn.mean() * 100).round(1),
                         "holdout FPR %": (fh.mean() * 100).round(1),
                         "attempt recall %": (fa.mean() * 100).round(1)})
    fa["run_id"] = atk.run_id.values
    byrun = fa.groupby("run_id").any()
    summ["runs detected %"] = (byrun.mean() * 100).round(1)
    meta = atk.drop_duplicates("run_id").set_index("run_id")[["scenario", "source"]]
    sa, th_if = baseline_if.score_if(atk_f)
    sn, _ = baseline_if.score_if(nrm)
    ea = catavo_ml.errors(model, (catavo_ml.prep(atk_f) - lo) / span)
    en = catavo_ml.errors(model, (catavo_ml.prep(nrm) - lo) / span)
    print(f"\nscore check  AE threshold {thr:.4f}: normal median {np.median(en):.4f} max {en.max():.4f}; attack median {np.median(ea):.4f}")
    print(f"             IF threshold {th_if:.4f}: normal median {np.median(sn):.4f} max {sn.max():.4f}; attack median {np.median(sa):.4f} max {sa.max():.4f}")
    dbg = atk_f.assign(ae=ea, iff=sa)
    print("\nattack rows, median per scenario/source:")
    print(dbg.groupby(["scenario", "source"])[FEATS + ["ae", "iff"]].median().round(3).to_string())
    print("\nnormal rows with the highest IF score:")
    print(nrm.assign(iff=sn).nlargest(5, "iff")[FEATS + ["iff"]].round(3).to_string())
    print("\n=== Overall (rates in %) ===")
    print(summ.to_string())

    print("\n=== Runs detected, by scenario and source (detected/total) ===")
    j = byrun.join(meta)
    tab = {}
    for (sc, src), g in j.groupby(["scenario", "source"]):
        tab[f"{sc} | {src}"] = {d: f"{int(g[d].sum())}/{len(g)}" for d in dets}
    print(pd.DataFrame(tab).T.to_string())

    print("\n=== Attempts until first alert (median, over detected runs) ===")
    first = {}
    for d in dets:
        n = []
        for rid, g in fa.assign(t=atk.t.values).sort_values("t").groupby("run_id"):
            h = np.flatnonzero(g[d].values)
            if len(h):
                n.append(h[0] + 1)
        first[d] = float(np.median(n)) if n else None
    print(pd.Series(first).to_string())

    print("\n=== False positives by attempt type ===")
    print(fn.groupby(nrm.type.values).mean().mul(100).round(1)[["Autoencoder", "Isolation Forest", "Rule 1 (brute force)", "Rule 2 (unknown IP)"]].to_string())

    summ.to_csv(P("eval_summary.csv"))
    byrun.join(meta).to_csv(P("eval_runs.csv"))
    print("\nsaved eval_summary.csv and eval_runs.csv in", DATA)

    if False and a.normal2:
        n2 = featurize(load_events(a.normal2), base, med["session_duration"], med["login_gap"])
        f2 = flags_for(n2, det)
        print(f"\n=== Fresh normal traffic ({len(n2)} attempts, not used in training) - false-positive rate % ===")
        print((f2.mean() * 100).round(1).to_string())


if __name__ == "__main__":
    main()

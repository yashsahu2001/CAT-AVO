"""CAT-AVO monitor: polls Splunk for Keycloak login events, scores every authentication attempt
with the autoencoder and (with --act) responds through soar.py.
  python monitor.py          dry run: score and log only, no response
  python monitor.py --act    real response: revoke sessions, block IP on RHEL and pfSense
Stop with Ctrl+C.  Log: data\monitor_log.csv"""
import argparse, csv, json, os, threading, time
from collections import defaultdict, deque
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd
import requests

import catavo_ml
import soar

DATA = os.environ.get("CATAVO_DATA", r"C:\catavo-ml\data")
SPLUNK = "https://192.168.100.30:8089"
IST = ZoneInfo("Asia/Kolkata")
LOG_COLS = ["event_time", "type", "userId", "ip", "score", "threshold", "flagged", "action",
            "keycloak_revoke_s", "rhel_firewall_s", "pfsense_block_s", "total_s", "event_to_done_s",
            "login_hour", "session_duration", "failed_before_login", "new_ip", "login_gap"]


class Features:
    """Builds the 5 features for one attempt from what has been seen so far."""

    def __init__(self, baseline, med_duration, med_gap):
        self.base, self.med_dur, self.med_gap = baseline, med_duration, med_gap
        self.errors = defaultdict(deque)
        self.last_login = {}

    def row(self, ev):
        t, u = ev["t"], ev["userId"]
        q = self.errors[u]
        while q and (t - q[0]).total_seconds() > 300:
            q.popleft()
        failed = sum(1 for x in q if x < t)
        local = t.astimezone(IST)
        hour = (local.hour + local.minute / 60 - 4) % 24
        new_ip = int(ev["ip"] not in self.base.get(u, []))
        gap = (t - self.last_login[u]).total_seconds() if u in self.last_login else self.med_gap
        if ev["type"] == "LOGIN_ERROR":
            q.append(t)
        else:
            self.last_login[u] = t
        return {"login_hour": hour, "session_duration": self.med_dur, "failed_before_login": failed,
                "new_ip": new_ip, "login_gap": gap}


def splunk(auth, query, earliest="-10m"):
    r = requests.post(f"{SPLUNK}/services/search/jobs/export", auth=auth, verify=False, timeout=30,
                      data={"search": query, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"})
    r.raise_for_status()
    out = []
    for line in r.text.splitlines():
        if line.strip():
            j = json.loads(line)
            if "result" in j:
                out.append(j["result"])
    return out


def fetch(auth, since):
    q = ("search index=keycloak realmName=catavo (type=LOGIN OR type=LOGIN_ERROR) "
         f"| eval it=_indextime, t=_time | where it>={since} | sort 0 +t "
         "| table t, it, type, userId, ipAddress")
    return splunk(auth, q)


def parse(r):
    return {"t": datetime.fromtimestamp(float(r["t"]), tz=timezone.utc), "it": float(r["it"]), "type": r["type"],
            "userId": r.get("userId"), "ip": r.get("ipAddress")}


def respond(ip, user_id):
    if ip in soar.PROTECTED:                       # never firewall lab infrastructure or the SOAR host
        s = time.perf_counter()
        ok = soar.revoke_sessions(user_id)
        return {"keycloak_revoke": round(time.perf_counter() - s, 2) if ok else None,
                "total": round(time.perf_counter() - s, 2)}
    return soar.respond(ip, user_id)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--act", action="store_true")
    ap.add_argument("--poll", type=float, default=3.0)
    ap.add_argument("--auto-unblock", type=float, default=0, help="test mode: undo the block this many seconds after responding")
    args = ap.parse_args()
    requests.packages.urllib3.disable_warnings()

    model, lo, span, thr = catavo_ml.load_model()
    base = json.load(open(os.path.join(DATA, "baseline_ips.json")))
    ft = pd.read_csv(os.path.join(DATA, "features.csv"))
    feats = Features(base, float(ft.session_duration.median()), float(ft.login_gap.median()))

    user = os.environ.get("SOAR_SPLUNK_USER") or input("Splunk username [admin]: ").strip() or "admin"
    auth = (user, soar.secret("SOAR_SPLUNK_PW", f"Splunk password for {user}: "))
    if args.act:
        for env, p in (("SOAR_KC_PW", "Keycloak labadmin password: "), ("SOAR_PF_PW", "pfSense root password: "),
                       ("SOAR_RHEL_PW", "RHEL soar password: ")):
            soar.secret(env, p)

    since = float(splunk(auth, "search index=keycloak | stats max(_indextime) as m", "0")[0]["m"])
    path = os.path.join(DATA, "monitor_log.csv")
    new = not os.path.exists(path)
    logf = open(path, "a", newline="")
    log = csv.DictWriter(logf, LOG_COLS)
    if new:
        log.writeheader()
    print(f"monitor started ({'ACTING' if args.act else 'dry run'}), threshold {thr:.5f}. Ctrl+C to stop.")

    seen, handled, n = set(), set(), 0
    for r in fetch(auth, since):                   # events already there at startup are history: mark seen, do not act
        seen.add((r["t"], r["type"], r.get("userId"), r.get("ipAddress")))
    while True:
        try:
            rows = fetch(auth, since)
        except Exception as ex:
            print("splunk error:", ex)
            time.sleep(args.poll)
            continue
        for r in rows:
            key = (r["t"], r["type"], r.get("userId"), r.get("ipAddress"))
            if key in seen:
                continue
            seen.add(key)
            since = max(since, float(r["it"]))
            ev = parse(r)
            if not ev["userId"]:
                continue                               # unknown user name: only the Splunk rules cover this
            f = feats.row(ev)
            x = (catavo_ml.prep(pd.DataFrame([f])) - lo) / span
            score = float(catavo_ml.errors(model, x)[0])
            flagged = score > thr
            rec = {"event_time": ev["t"].isoformat(), "type": ev["type"], "userId": ev["userId"], "ip": ev["ip"],
                   "score": round(score, 5), "threshold": round(thr, 5), "flagged": int(flagged), "action": "", **f}
            n += 1
            if flagged:
                pair = (ev["ip"], ev["userId"])
                if pair in handled:
                    rec["action"] = "already_handled"
                elif args.act:
                    res = respond(ev["ip"], ev["userId"])
                    done = datetime.now(timezone.utc)
                    handled.add(pair)
                    rec.update({"action": "responded", "keycloak_revoke_s": res.get("keycloak_revoke"),
                                "rhel_firewall_s": res.get("rhel_firewall"), "pfsense_block_s": res.get("pfsense_block"),
                                "total_s": res.get("total"),
                                "event_to_done_s": round((done - ev["t"]).total_seconds(), 2)})
                    if args.auto_unblock and ev["ip"] not in soar.PROTECTED:
                        def undo(ip=ev["ip"], pair=pair):
                            try:
                                soar.unblock_rhel(ip)
                                soar.unblock_pfsense(ip)
                                print(f"  auto-unblocked {ip}")
                            except Exception as ex:
                                print("  auto-unblock error:", ex)
                            handled.discard(pair)
                        tm = threading.Timer(args.auto_unblock, undo)
                        tm.daemon = True
                        tm.start()
                else:
                    rec["action"] = "would_respond"
                print(f"[{ev['t'].astimezone(IST):%H:%M:%S}] ANOMALY {ev['type']} ip={ev['ip']} score={score:.4f} -> {rec['action']}")
            elif n % 25 == 0:
                print(f"  {n} attempts scored, last score {score:.4f} (normal)")
            log.writerow(rec)
            logf.flush()
        time.sleep(args.poll)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""CAT-AVO attack simulator (lab only). Standard library only, runs on Kali or on the laptop.
  python3 attacks.py <scenario> [--user user1] [--runs 1] [--pause 120]
Scenarios: brute_force, spray, slow_low, stolen_credential, token_burst
Appends ground truth (run id, scenario, host, start, end) to attack_runs.csv in the current folder."""
import argparse, csv, getpass, json, os, random, socket, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime

KC = os.environ.get("CATAVO_KC", "http://192.168.100.20:8080/realms/catavo/protocol/openid-connect")
SPEED = float(os.environ.get("CATAVO_SPEED", "1"))      # >1 only for testing the script itself


def nap(a, b=None):
    time.sleep(random.uniform(a, b if b is not None else a) / SPEED)


def post(path, data):
    req = urllib.request.Request(f"{KC}/{path}", data=urllib.parse.urlencode(data).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


def login(user, pw):
    return post("token", {"client_id": "catavo-sim", "grant_type": "password",
                          "username": user, "password": pw, "scope": "openid"})


def logout(tok):
    post("logout", {"client_id": "catavo-sim", "refresh_token": tok})


def brute_force(user, pw):
    for i in range(15):
        login(user, f"guess{i}")
        nap(1, 2)


def spray(user, pw):
    for rnd in range(3):
        for u in ("user1", "user2"):
            login(u, "Winter2026!")
            nap(3, 6)
        nap(20)


def slow_low(user, pw):
    for i in range(6):
        login(user, f"slow{i}")
        nap(60, 100)


def stolen_credential(user, pw):
    code, tok = login(user, pw)
    print("  login status", code)
    nap(10, 40)
    if tok.get("refresh_token"):
        logout(tok["refresh_token"])


def token_burst(user, pw):
    for _ in range(10):
        code, tok = login(user, pw)
        if tok.get("refresh_token"):
            logout(tok["refresh_token"])
        nap(1, 3)


SCENARIOS = {f.__name__: f for f in (brute_force, spray, slow_low, stolen_credential, token_burst)}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=SCENARIOS)
    ap.add_argument("--user", default="user1")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--pause", type=float, default=120, help="seconds between runs")
    a = ap.parse_args()
    pw = (os.environ.get("CATAVO_PW") or getpass.getpass(f"Correct password for {a.user}: ")) if a.scenario in ("stolen_credential", "token_burst") else ""
    new = not os.path.exists("attack_runs.csv")
    f = open("attack_runs.csv", "a", newline="")
    w = csv.writer(f)
    if new:
        w.writerow(["run_id", "scenario", "host", "user", "start", "end"])
    for n in range(1, a.runs + 1):
        rid = f"{a.scenario}-{socket.gethostname()}-{datetime.now():%m%d%H%M%S}-{n}"
        start = datetime.now().astimezone().isoformat(timespec="seconds")
        print(f"run {n}/{a.runs}  {rid}  started {start}")
        SCENARIOS[a.scenario](a.user, pw)
        end = datetime.now().astimezone().isoformat(timespec="seconds")
        w.writerow([rid, a.scenario, socket.gethostname(), a.user, start, end])
        f.flush()
        print(f"  finished {end}")
        if n < a.runs:
            nap(a.pause)

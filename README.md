# CAT-AVO: Continuous Adaptive Trust & Automated Vulnerability Orchestration

Post-authentication behavioural trust using an unsupervised PyTorch autoencoder, with automated response, in an isolated VMware lab.

> Industry Project, KIIT. Author: Yash Sahu (Roll No. 25168014).

## What this project does

Most systems trust a session once the user has logged in. CAT-AVO keeps checking: it learns what **normal** login behaviour looks like for each user, scores every new login against it, and when a login looks abnormal it **automatically contains the attacker**.

```
User login -> Keycloak event -> Splunk -> monitor.py (every 3 s)
           -> autoencoder reconstruction error -> above threshold?
           -> SOAR: revoke Keycloak session + block IP on RHEL firewall + block IP on pfSense
```

## Lab (VMware, network 192.168.100.0/24, no Internet)

| Machine | Address | Role |
|---|---|---|
| pfSense 2.4.5-p1 | 192.168.100.1 | Firewall, DHCP, syslog, SOAR block list |
| CATAVO-AD (Windows Server 2019) | 192.168.100.10 | Active Directory, domain `catavo.local` |
| RHEL 10.2 | 192.168.100.20 | Keycloak 26.8.0 (port 8080) |
| RHEL 10.2 (same VM) | 192.168.100.30 | Splunk Enterprise 10.6.0.5 |
| Kali Linux | 192.168.100.40 | Attacker |
| CATAVO-WS01 (Windows 11) | 192.168.100.50 | Endpoint, Splunk Universal Forwarder |
| Laptop (host) | 192.168.100.70 | SOAR and ML code, second user and attack source |

To fit one 32 GB laptop, Keycloak and Splunk share one RHEL VM and use two IP addresses.

## The model

* Autoencoder 4-3-2-3-4 (Tanh, Adam, learning rate 0.01, 1000 epochs), trained **only on normal logins**.
* Features: `session_duration`, `failed_before_login`, `new_ip`, `login_gap`.
* Alert threshold: 99th percentile of the training reconstruction error (0.02303).
* Baselines for comparison: Splunk correlation rules and an Isolation Forest on the same features.

## Results (54 simulated attack runs, 27 from Kali and 27 from the laptop)

| Detector | Runs detected | False positives (hold-out) |
|---|---|---|
| Autoencoder | 45 / 54 (83.3 %) | 2.4 % |
| Splunk rules (brute force OR unknown IP) | 38 / 54 (70.4 %) | 0 % |
| Isolation Forest (95th percentile) | 32 / 54 (59.3 %) | 8.5 % |

End-to-end response time (Keycloak event to completed response): mean 7.2 s, median 6.5 s. Most of it is Splunk indexing and polling.

## Files

| File | Purpose |
|---|---|
| `features.py` | First feature builder (five features), superseded |
| `features2.py` | Final data preparation: two normal batches, hold-out split, four features |
| `catavo_ml.py` | Autoencoder: model, training and scoring functions |
| `baseline_if.py` | Isolation Forest baseline |
| `soar.py` | Response actions: Keycloak session revoke, RHEL firewall block, pfSense block |
| `monitor.py` | Live detection loop: polls Splunk, scores logins, calls `soar.py` |
| `attacks.py` | Five attack scenarios (brute force, spray, slow and low, stolen credential, token burst) |
| `evaluate.py` | Offline comparison of all detectors |

## How to run (order)

Python 3.13 with: `torch pandas numpy scikit-learn requests paramiko matplotlib`

```
python features2.py                      # needs data\keycloak_all.csv (Splunk export)
python catavo_ml.py --epochs 1000        # trains the autoencoder
python baseline_if.py                    # trains the Isolation Forest
python monitor.py                        # dry run: score and print only
python monitor.py --act                  # real response (revoke session, block IP)
python3 attacks.py brute_force --user user1 --runs 3     # on Kali, lab only
python evaluate.py                       # compares all detectors
```

Passwords are never stored in the code: they are read from environment variables (`SOAR_KC_PW`, `SOAR_PF_PW`, `SOAR_RHEL_PW`, `SOAR_SPLUNK_PW`) or typed at a hidden prompt. The `data` folder (exports, trained model files, logs) is not part of this repository.

## Limitations

* Small evaluation: 3 to 6 runs per scenario and source, 82 hold-out attempts, two users.
* The attacks were written by the project author and are synthetic.
* A stolen password used from the user's own machine was not detected by any method.
* `new_ip` acts almost like a hard rule; the Isolation Forest baseline is weak partly for this reason.
* The full loop takes about 7 seconds because of the SIEM path.
* Active Directory account lockout and vulnerability scanning are not implemented (future work).

## Lab-only notice

`attacks.py` and the response scripts were written for an isolated lab. Run them only on systems you own or are authorised to test.

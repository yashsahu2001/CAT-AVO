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

<p align="center"><img src="docs/images/fig01.jpg" width="700" alt="System architecture of the CAT-AVO lab"><br><em>Figure 1: System architecture of the CAT-AVO lab</em></p>

<p align="center"><img src="docs/images/fig02.jpg" width="700" alt="End-to-end working flow of CAT-AVO"><br><em>Figure 2: End-to-end working flow of CAT-AVO</em></p>


## Contents

1. [Lab](#lab-vmware-network-19216810024-no-internet)
2. [The model](#the-model)
3. [Results](#results-54-simulated-attack-runs-27-from-kali-and-27-from-the-laptop)
4. [Files](#files)
5. [Quick start](#quick-start-order)
6. [Command reference by machine](#command-reference-by-machine)
7. [Automated response (SOAR)](#automated-response-soar)
8. [Attack simulation](#attack-simulation)
9. [Splunk searches](#splunk-searches-used)
10. [Lab build walkthrough (screenshots)](#lab-build-walkthrough-screenshots)
11. [Limitations](#limitations)

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

To fit one 32 GB laptop, Keycloak and Splunk share one RHEL VM and use two IP addresses. With every VM running, the laptop uses roughly 22 GB of memory. All VMs sit on one isolated host-only segment (VMnet2) behind pfSense, and all machines use Indian Standard Time so that timestamps can be compared directly.

**Service ports**

| Service | Port |
|---|---|
| Keycloak (realm `catavo`, client `catavo-sim`) | 8080 |
| Splunk web / REST API / receiving (Universal Forwarders) | 8000 / 8089 / 9997 |
| Splunk syslog input (pfSense, restricted to 192.168.100.1) | UDP 5514 |

**Splunk indexes** (5 GB each): `pfsense`, `ad`, `endpoint`, `keycloak`.

## The model

* Autoencoder 4-3-2-3-4 (Tanh, Adam, learning rate 0.01, 1000 epochs), trained **only on normal logins** (720 training logins: 600 from the evening batch B1 and 120 from the daytime batch B2; 80 further logins are held out).
* Features: `session_duration`, `failed_before_login`, `new_ip`, `login_gap` (log-transformed).
* Alert threshold: 99th percentile of the training reconstruction error (0.02303).
* Baselines for comparison: Splunk correlation rules and an Isolation Forest on the same features.

<p align="center"><img src="docs/images/fig70.jpg" width="700" alt="How the autoencoder works (original five-feature design; the final model uses four features)"><br><em>Figure 70: How the autoencoder works (original five-feature design; the final model uses four features)</em></p>


The hour of the day is still logged but is **not** a model input: with only two narrow time windows of lab data it caused false alarms on normal daytime logins (five-feature model: 48/54 detected, 6.1 % hold-out FP; final four-feature model: 45/54 detected, 2.4 % hold-out FP).

## Results (54 simulated attack runs, 27 from Kali and 27 from the laptop)

| Detector | Runs detected | False positives (hold-out) |
|---|---|---|
| Autoencoder | 45 / 54 (83.3 %) | 2.4 % |
| Splunk rules (brute force OR unknown IP) | 38 / 54 (70.4 %) | 0 % |
| Isolation Forest (95th percentile) | 32 / 54 (59.3 %) | 8.5 % |

The Isolation Forest at the strict 99th-percentile threshold detects 0 / 54, because `new_ip` never varies in its training data. From the harder known-laptop address the autoencoder detects 18 of 27 runs against 12 of 27 for the rules.

<p align="center"><img src="docs/images/fig72.png" width="560" alt="Detection rate of the four detectors"><br><em>Figure 72: Detection rate of the four detectors</em></p>

<p align="center"><img src="docs/images/fig73.png" width="560" alt="False-positive rate on normal logins"><br><em>Figure 73: False-positive rate on normal logins</em></p>


**Autoencoder detections per scenario and source**

| Scenario | From Kali | From laptop (known IP) |
|---|---|---|
| brute_force | 6 / 6 | 6 / 6 |
| spray | 6 / 6 | 6 / 6 |
| token_burst | 6 / 6 | 6 / 6 |
| stolen_credential | 6 / 6 | 0 / 6 |
| slow_low | 3 / 3 | 0 / 3 |

<p align="center"><img src="docs/images/fig74.png" width="560" alt="Autoencoder detection per scenario and source"><br><em>Figure 74: Autoencoder detection per scenario and source</em></p>

<p align="center"><img src="docs/images/fig75.png" width="560" alt="Autoencoder detection when one feature is frozen"><br><em>Figure 75: Autoencoder detection when one feature is frozen</em></p>


**End-to-end response time** (Keycloak event to completed response, 10 trials): mean 7.2 s, median 6.5 s, min 4.4 s, max 11.9 s. The three response actions themselves take 1.3 to 4.6 s; most of the rest is Splunk indexing and polling.

<p align="center"><img src="docs/images/fig76.png" width="560" alt="Latency from event to completed response"><br><em>Figure 76: Latency from event to completed response</em></p>


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

Data files written to `data\` (not in this repository): `features.csv`, `baseline_ips.json`, `keycloak_normal_split.csv`, `model.pt`, `scaler.json`, `threshold.json`, `loss_history.csv`, `training_loss.png`, `if_model.joblib`, `if_threshold.json`, `monitor_log.csv`, `attack_runs*.csv`, `eval_summary.csv`, `eval_runs.csv`, `eval_output.txt`.

## Quick start (order)

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

## Command reference by machine

Prompt conventions: `(venv) PS C:\catavo-ml>` is Windows PowerShell on the laptop with the virtual environment active; `PS C:\WINDOWS\system32>` is an Administrator PowerShell inside a Windows VM; `yashsahu@catavo-keycloak:~$` is the RHEL terminal. All ML and SOAR code lives in `C:\catavo-ml` on the laptop.

### 1. Laptop: project environment (Windows PowerShell)

```powershell
cd C:\catavo-ml
python -m venv venv                       # first time only
.\venv\Scripts\Activate.ps1               # prompt gains the (venv) prefix
pip install pandas numpy scikit-learn requests paramiko matplotlib
pip install torch                         # PyTorch for the autoencoder (same environment)
```

| Library | Used for |
|---|---|
| pandas, numpy | tables and arrays |
| scikit-learn | Isolation Forest baseline |
| requests | Splunk and Keycloak REST calls |
| paramiko | SSH to pfSense and RHEL for the response |
| matplotlib | training-loss chart |
| torch | autoencoder |

Optional: set the response passwords for the current PowerShell session only, typed at a hidden prompt (nothing is echoed or stored in the history):

```powershell
$env:SOAR_KC_PW     = [Net.NetworkCredential]::new("", (Read-Host "Keycloak admin password" -AsSecureString)).Password
$env:SOAR_PF_PW     = [Net.NetworkCredential]::new("", (Read-Host "pfSense root password"   -AsSecureString)).Password
$env:SOAR_RHEL_PW   = [Net.NetworkCredential]::new("", (Read-Host "RHEL soar password"      -AsSecureString)).Password
$env:SOAR_SPLUNK_PW = [Net.NetworkCredential]::new("", (Read-Host "Splunk password"         -AsSecureString)).Password
```

### 2. Laptop: building the dataset and training the models

| Command | What it does |
|---|---|
| `move -Force $HOME\Downloads\features2.py C:\catavo-ml\` | Moves a downloaded script into the project folder (`-Force` overwrites an older copy); same pattern for `catavo_ml.py`, `baseline_if.py`, `evaluate.py` |
| `python features2.py` | Cleans the Splunk export, selects the two normal batches, separates the 80 hold-out logins, builds the four features, writes `features.csv`, `baseline_ips.json`, `keycloak_normal_split.csv`; old files are first backed up in `data\v1` |
| `python catavo_ml.py --epochs 1000` | Trains the autoencoder, sets the threshold, saves `model.pt`, `scaler.json`, `threshold.json` and the loss chart |
| `python baseline_if.py` | Trains the Isolation Forest on the same data and split |
| `copy ...\eval_output.txt ...\eval_output_5feature.txt` | Keeps the earlier five-feature evaluation for comparison |
| `python evaluate.py \| Tee-Object C:\catavo-ml\data\eval_output.txt` | Scores all 54 attack runs and the normal data with every detector; shows the result and saves it to `eval_output.txt` |

<details>
<summary><b>Verified output: features2.py, catavo_ml.py, baseline_if.py, evaluate.py</b></summary>

`python features2.py`

```
old files copied to C:\catavo-ml\data\v1
events kept per window and type:
B1 {('LOGIN', 'train'): 600, ('LOGIN_ERROR', 'train'): 38, ('LOGOUT', 'train'): 600}
B2 {('LOGIN', 'holdout'): 80, ('LOGIN', 'train'): 120, ('LOGIN_ERROR', 'holdout'): 2, ('LOGIN_ERROR', 'train'): 3, ('LOGOUT', 'holdout'): 80, ('LOGOUT', 'train'): 120}
training rows: 720 per batch: {'B1': 600, 'B2': 120}
                      mean    std    min     max
login_hour           17.17   3.49   9.33   20.82
session_duration     33.44  15.31   3.06   59.09
failed_before_login   0.38   0.59   0.00    3.00
new_ip                0.00   0.00   0.00    0.00
login_gap            50.96  41.81   5.15  998.64
holdout logins: 80
```

`python catavo_ml.py --epochs 1000`

```
epoch 1 train 0.20995 val 0.19241
epoch 100 train 0.02136 val 0.02261
epoch 200 train 0.00370 val 0.00414
epoch 300 train 0.00228 val 0.00225
epoch 500 train 0.00213 val 0.00195
epoch 1000 train 0.00202 val 0.00174
threshold (99th pct of training error) = 0.02303
validation false-positive rate = 0.7% (1 of 144)
error mean 0.00202 max 0.09153
saved model.pt, scaler.json, threshold.json, training_loss.png in C:\catavo-ml\data
```

`python baseline_if.py`

```
threshold (99th pct of training score) = 0.6628
validation false-positive rate = 1.4% (2 of 144)
saved if_model.joblib and if_threshold.json in C:\catavo-ml\data
```

`python evaluate.py` (first part and summary)

```
WARNING: 1 runs have no scored events (excluded): ['brute_force-catavo-kali-1014015052-1']...
attack attempts scored: 420 in 54 runs; normal attempts: 761 in-sample, 82 holdout

=== Overall (rates in %) ===
                          in-sample FPR %  holdout FPR %  attempt recall %  runs detected %
Autoencoder                           0.9            2.4              82.6             83.3
AE, gap frozen                        0.0            0.0              69.8             72.2
AE, new_ip frozen                     0.9            2.4              57.1             48.1
AE, failed-logins frozen              0.9            1.2              67.1             72.2
Isolation Forest                      0.3            2.4               0.0              0.0
Isolation Forest, 95th pct            4.9            8.5              64.3             59.3
Rule 1 (brute force)                  0.0            0.0              37.6             48.1
Rule 2 (unknown IP)                   0.0            0.0              15.7             22.2
Rules 1 OR 2                          0.0            0.0              53.3             70.4
```

The `WARNING` line only says that one run in the run file left no events in Splunk and was left out; the 54 scored runs are the ones reported. The score check shows the separation that makes the detector work: normal logins have a median error of 0.0007 (max 0.0908) and attacks a median of 0.3117, against the threshold of 0.0230.

</details>

### 3. Windows 11 VM (CATAVO-WS01): normal-behaviour generator

User1 is simulated with a PowerShell loop that signs in to Keycloak through the `catavo-sim` client, stays logged in for a while and signs out, 100 times, with human-like random pauses. Run it in an **Administrator PowerShell**. The same script with `user2` on the laptop produced the second user's data.

```powershell
$u  = "user1"
$pw = [Net.NetworkCredential]::new("",(Read-Host "Password" -AsSecureString)).Password   # hidden prompt
$n  = 100
$kc = "http://192.168.100.20:8080/realms/catavo/protocol/openid-connect"

for($i=1;$i -le $n;$i++){
  $r=Get-Random -Maximum 100
  if($r -lt 25){$p=Get-Random -Minimum 1 -Maximum 5}elseif($r -lt 90){$p=Get-Random -Minimum 5 -Maximum 25}else{$p=Get-Random -Minimum 60 -Maximum 180}
  Start-Sleep -Seconds $p
  if((Get-Random -Maximum 15) -eq 0){
    try{Invoke-RestMethod -Method Post -Uri "$kc/token" -Body @{client_id="catavo-sim";grant_type="password";username=$u;password="wrong$i";scope="openid"}}catch{}
    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 10)
  }
  $t=Invoke-RestMethod -Method Post -Uri "$kc/token" -Body @{client_id="catavo-sim";grant_type="password";username=$u;password=$pw;scope="openid"}
  if((Get-Random -Maximum 100) -lt 25){$d=Get-Random -Minimum 3 -Maximum 10}else{$d=Get-Random -Minimum 10 -Maximum 60}
  Start-Sleep -Seconds $d
  Invoke-RestMethod -Method Post -Uri "$kc/logout" -Body @{client_id="catavo-sim";refresh_token=$t.refresh_token} | Out-Null
  Write-Host "session $i done at $(Get-Date -Format HH:mm:ss)"
}
```

| Part of the loop | What it does |
|---|---|
| `Get-Random` / `Start-Sleep -Seconds $p` | Waits before the next session: 25 % of the time 1 to 4 s, 65 % 5 to 24 s, 10 % 60 to 179 s |
| `password="wrong$i"` | About one session in fifteen starts with a mistyped password (a `LOGIN_ERROR` event), then pauses 3 to 9 s |
| `.../token` with the real password | The actual login; Keycloak records a `LOGIN` event with user, session and source IP |
| `Start-Sleep -Seconds $d` | Keeps the session open (25 % of the time 3 to 9 s, otherwise 10 to 59 s): the session-duration feature |
| `.../logout` with `refresh_token` | Signs out; Keycloak records a `LOGOUT` event so the pipeline can measure the session length |

Check that the Splunk Universal Forwarder is running on the endpoint:

```powershell
Get-Service Splunk*
# Status   Name              DisplayName
# Running  SplunkForwarder   SplunkForwarder
```

Collection was done in two batches: B1 on the evening of 13 October 2026 (20:00 to 01:00 IST) and B2 on the afternoon of 14 October (13:19 to 15:00) so that the model also sees daytime behaviour. The Keycloak events were exported from Splunk as CSV (`keycloak_all.csv`: 2351 rows, 993 `LOGIN`, 992 `LOGOUT`, 366 `LOGIN_ERROR`).

<p align="center"><img src="docs/images/fig66.jpg" width="300" alt="Data generator finishing session 300"><br><em>Figure 66: Data generator finishing session 300</em></p>


### 4. Windows Server 2019 (CATAVO-AD): domain controller

```powershell
hostname          # CATAVO-AD  (domain catavo.local)
```

### 5. RHEL 10.2 (catavo-keycloak): network and Splunk start

```bash
ip a                                   # ens160 holds 192.168.100.20/24
ip route                               # default route via the pfSense LAN address 192.168.100.1
ping -c 3 192.168.100.1                # gateway reachable (about 1 ms, 0 % loss)
ping -c 3 8.8.8.8                      # 100 % loss: the lab has no Internet, as designed
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

`splunk start` checks the configuration, validates the installed files ("All installed files intact", "All preliminary checks passed"), creates a certificate and waits for the web interface on `http://127.0.0.1:8000`. Software was installed from locally transferred packages because the lab has no Internet access.

### 6. Kali Linux: attack commands

`attacks.py` uses only the Python standard library, so it runs on Kali without any installation.

```bash
python3 attacks.py <scenario> [--user user1] [--runs 1] [--pause 120]
# scenarios: brute_force, spray, slow_low, stolen_credential, token_burst
```

| Argument | Meaning |
|---|---|
| `<scenario>` | Which of the five attacks to run |
| `--user user1` | Account that is attacked (default `user1`) |
| `--runs N` | How many repeated runs in one call |
| `--pause 120` | Seconds between two runs, so runs do not overlap |

For `stolen_credential` and `token_burst` the script asks for the correct password at a hidden prompt. Every run is appended to `attack_runs.csv` (run id, scenario, host, user, start, end): this file is the ground truth used by `evaluate.py`. The Keycloak endpoint can be overridden with the environment variable `CATAVO_KC`.

### 7. Laptop: response engine and monitor

| Command | What it does |
|---|---|
| `python monitor.py` | Dry run: scores every login and prints the decision (`would_respond`) but changes nothing |
| `python monitor.py --act` | Real response: revokes the Keycloak session and blocks the source on RHEL and pfSense |
| `python monitor.py --act --auto-unblock 20` | Test mode for latency measurement: the block is removed 20 s after it was applied |
| `python soar.py status` | Checks the Keycloak admin token, the pfSense `blocked_ips` table and the RHEL rich rules |
| `python soar.py block <ip> <userId>` | Applies the response manually to one address and user |
| `python soar.py unblock <ip>` | Removes the RHEL and pfSense blocks for an address |

Dry-run start-up (the Splunk user name and password are asked at hidden prompts):

```
(venv) PS C:\catavo-ml> python monitor.py
Splunk username [admin]: <your Splunk user>
Splunk password for <your Splunk user>:
monitor started (dry run), threshold 0.02303. Ctrl+C to stop.
```

After the test runs, `python soar.py status` confirmed a clean state: Keycloak admin token OK, pfSense `blocked_ips` (empty), RHEL rich rules (none).

Latency test: ten single wrong-password attempts from Kali, 45 s apart, with the monitor in act mode and the passwords entered before the monitor started.

| count | mean | std | min | 25 % | median | 75 % | max |
|---|---|---|---|---|---|---|---|
| 10 | 7.174 | 2.657 | 4.36 | 5.3125 | 6.505 | 8.9125 | 11.86 |

`monitor.py` options: `--act`, `--poll <seconds>` (default 3), `--auto-unblock <seconds>`. Every event is appended to `monitor_log.csv`; the end-to-end delay is the column `event_to_done_s`, and the single action times are `keycloak_revoke_s`, `rhel_firewall_s`, `pfsense_block_s`.

## Automated response (SOAR)

When the monitor flags a login, `soar.py` takes three coordinated actions against the offending user and source address:

| Target | Action | Command / API |
|---|---|---|
| Keycloak | End all sessions of the user | `POST /admin/realms/catavo/users/{id}/logout` (HTTP 204 = done) |
| RHEL host firewall | Drop traffic from the source (runtime rule only) | `sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="<ip>" drop'` |
| pfSense | Add to the `blocked_ips` table and kill existing states | `pfctl -t blocked_ips -T add <ip>; pfctl -k <ip>` |

Manual checks and clean-up on the target machines:

```bash
# RHEL
sudo firewall-cmd --list-rich-rules
sudo firewall-cmd --remove-rich-rule='rule family="ipv4" source address="<ip>" drop'
# pfSense (shell over SSH)
pfctl -t blocked_ips -T show
pfctl -t blocked_ips -T delete <ip>
```

* **Protected addresses** (192.168.100.1, .10, .20, .30 and .70): for these only the session revocation is performed, so the engine can never lock out the firewall, the directory, Keycloak, Splunk or the operator's laptop.
* The RHEL rule is added at run time only, so it disappears on a firewall reload or restart: a stale block cannot lock a user out permanently. The engine uses a restricted account (`soar`) with a narrow sudoers rule.
* Monitor mode is dry-run by default; `--act` enables real actions.
* **Design finding:** pfSense can only filter traffic that crosses it. Traffic between two machines on the same segment does not, so a pfSense block alone does not stop a same-segment attacker from reaching Keycloak. The RHEL host-firewall block was added for this reason.

pfSense setup used by the SOAR engine: remote syslog to Splunk (192.168.100.30, UDP 5514, everything), a firewall alias `blocked_ips`, a block rule labelled "SOAR block list" at the top of the LAN rules (source = alias), and SSH enabled so the engine can run `pfctl`.

<p align="center"><img src="docs/images/fig13.jpg" width="600" alt="LAN rules with the SOAR block list rule on top"><br><em>Figure 13: LAN rules with the SOAR block list rule on top</em></p>


## Attack simulation

Attacks go to realm `catavo` / client `catavo-sim` through the same token endpoint as normal logins, from two sources: Kali (an unknown address) and the laptop acting as user2 (a known baseline address, the harder case). 54 runs: 27 from Kali and 27 from the laptop (six runs per scenario and source, three for `slow_low`).

| Scenario | Description |
|---|---|
| `brute_force` | 15 wrong passwords against one account, 1 to 2 s apart |
| `spray` | One common password tried against two accounts in three rounds |
| `slow_low` | Six wrong passwords 60 to 100 s apart, to stay below rate thresholds |
| `stolen_credential` | A correct password used once from a different source, then a logout |
| `token_burst` | Ten login and logout cycles with the correct password, 1 to 3 s apart |

Example (Kali, lab only):

```bash
python3 attacks.py brute_force --user user1 --runs 3
python3 attacks.py spray --runs 3
python3 attacks.py stolen_credential --user user1 --runs 3     # asks for the password
```

Evidence in Splunk: a brute-force run from the Kali address appears as 17 failed logins in the `keycloak` index.

<p align="center"><img src="docs/images/fig71.jpg" width="560" alt="Brute-force evidence: 17 LOGIN_ERROR events from the Kali address"><br><em>Figure 71: Brute-force evidence: 17 LOGIN_ERROR events from the Kali address</em></p>


## Splunk searches used

| Purpose | Search (SPL) |
|---|---|
| Keycloak events by type | `index=keycloak \| stats count by type` |
| Login events table | `index=keycloak (type=LOGIN OR type=LOGIN_ERROR) \| table _time, type, username, ipAddress, clientId` |
| Rule 1: brute force | `index=keycloak type=LOGIN_ERROR \| bin _time span=5m \| stats count by _time, ipAddress \| where count>=5` |
| Rule 2: unknown source | `index=keycloak type=LOGIN NOT ipAddress="192.168.100.50" NOT ipAddress="192.168.100.70" \| stats count by ipAddress, userId` |
| Windows logons | `index=ad OR index=endpoint (EventCode=4624 OR EventCode=4625) \| stats count by index, host, EventCode` |

The monitor reads Keycloak events through the Splunk REST interface (port 8089) every three seconds, searching `index=keycloak`, and processes only events newer than the monitor start.

**Telemetry sources**

| Source | Transport | Index | Content |
|---|---|---|---|
| pfSense | Syslog UDP 5514 | `pfsense` | Firewall and system events |
| Domain controller | Universal Forwarder, TCP 9997 | `ad` | Windows Application, Security, System logs incl. logon events |
| Windows 11 endpoint | Universal Forwarder, TCP 9997 | `endpoint` | Windows Application, Security, System logs |
| Keycloak | Server log read by Splunk | `keycloak` | `LOGIN`, `LOGIN_ERROR`, `LOGOUT`, `CODE_TO_TOKEN` with user, session, IP, error |

## Lab build walkthrough (screenshots)

Click a section to expand its screenshots.

<details>
<summary><b>pfSense firewall (Figures 3-14)</b></summary>

pfSense was installed first because every other machine depends on it for addressing and logging. WAN uses NAT for initial updates; LAN is the static address 192.168.100.1/24, and DHCP serves 192.168.100.100 to 192.168.100.200, leaving the low addresses for static servers.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig03.jpg" width="330" alt="pfSense installer: keyboard map selection"><br><sub><b>Fig. 3</b>: pfSense installer: keyboard map selection</sub></td>
<td align="center" valign="top"><img src="docs/images/fig04.jpg" width="330" alt="pfSense installation finished"><br><sub><b>Fig. 4</b>: pfSense installation finished</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig05.jpg" width="330" alt="pfSense console menu at first boot"><br><sub><b>Fig. 5</b>: pfSense console menu at first boot</sub></td>
<td align="center" valign="top"><img src="docs/images/fig06.jpg" width="330" alt="Assigning interfaces from the console menu"><br><sub><b>Fig. 6</b>: Assigning interfaces from the console menu</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig07.jpg" width="330" alt="LAN interface set to 192.168.100.1/24"><br><sub><b>Fig. 7</b>: LAN interface set to 192.168.100.1/24</sub></td>
<td align="center" valign="top"><img src="docs/images/fig08.jpg" width="330" alt="DHCP range 192.168.100.100 to 192.168.100.200"><br><sub><b>Fig. 8</b>: DHCP range 192.168.100.100 to 192.168.100.200</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig09.jpg" width="330" alt="pfSense setup wizard"><br><sub><b>Fig. 9</b>: pfSense setup wizard</sub></td>
<td align="center" valign="top"><img src="docs/images/fig10.jpg" width="330" alt="Remote logging from pfSense to Splunk (192.168.100.30, port 5514)"><br><sub><b>Fig. 10</b>: Remote logging from pfSense to Splunk (192.168.100.30, port 5514)</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig11.jpg" width="330" alt="Firewall alias blocked_ips used by the SOAR engine"><br><sub><b>Fig. 11</b>: Firewall alias blocked_ips used by the SOAR engine</sub></td>
<td align="center" valign="top"><img src="docs/images/fig12.jpg" width="330" alt="Block rule using the blocked_ips alias as source"><br><sub><b>Fig. 12</b>: Block rule using the blocked_ips alias as source</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig13.jpg" width="330" alt="LAN rules with the SOAR block list rule on top"><br><sub><b>Fig. 13</b>: LAN rules with the SOAR block list rule on top</sub></td>
<td align="center" valign="top"><img src="docs/images/fig14.jpg" width="330" alt="Secure Shell enabled on pfSense for SOAR commands"><br><sub><b>Fig. 14</b>: Secure Shell enabled on pfSense for SOAR commands</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>Active Directory domain controller (Figures 15-16)</b></summary>

CATAVO-AD runs Windows Server 2019 Standard Evaluation (Desktop Experience), hosts the domain `catavo.local` and the user accounts federated into Keycloak. A Splunk Universal Forwarder sends its Application, Security and System logs to Splunk.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig15.jpg" width="330" alt="Windows Server 2019 setup: edition selection"><br><sub><b>Fig. 15</b>: Windows Server 2019 setup: edition selection</sub></td>
<td align="center" valign="top"><img src="docs/images/fig16.jpg" width="330" alt="Domain controller CATAVO-AD (Windows Server 2019 Standard Evaluation)"><br><sub><b>Fig. 16</b>: Domain controller CATAVO-AD (Windows Server 2019 Standard Evaluation)</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>RHEL host: network (Figures 17-18)</b></summary>

Static address 192.168.100.20 on the lab network; the host reaches the gateway but not the Internet.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig17.jpg" width="330" alt="RHEL address and route (192.168.100.20)"><br><sub><b>Fig. 17</b>: RHEL address and route (192.168.100.20)</sub></td>
<td align="center" valign="top"><img src="docs/images/fig18.jpg" width="330" alt="RHEL reaches the gateway; internet is intentionally unreachable"><br><sub><b>Fig. 18</b>: RHEL reaches the gateway; internet is intentionally unreachable</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>Keycloak identity provider (Figures 19-30)</b></summary>

Keycloak 26.8.0 listens on port 8080. Administrator `labadmin` manages the master realm; realm `catavo` holds the lab identities and is connected to Active Directory through a read-only LDAP user federation `ad-catavo` (three directory users imported, including user1 and user2). A public OpenID Connect client `catavo-sim` with direct access grants enabled lets the data generator and attack scripts perform scripted logins. User events are saved and the `jboss-logging` listener writes each event (type, user, session, client, source IP) to the Keycloak server log, which Splunk reads into the `keycloak` index.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig19.jpg" width="330" alt="Keycloak first start (master realm)"><br><sub><b>Fig. 19</b>: Keycloak first start (master realm)</sub></td>
<td align="center" valign="top"><img src="docs/images/fig20.jpg" width="330" alt="Realms: master and catavo, administrator labadmin"><br><sub><b>Fig. 20</b>: Realms: master and catavo, administrator labadmin</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig21.jpg" width="330" alt="LDAP user federation ad-catavo to Active Directory"><br><sub><b>Fig. 21</b>: LDAP user federation ad-catavo to Active Directory</sub></td>
<td align="center" valign="top"><img src="docs/images/fig22.jpg" width="330" alt="Synchronisation: three users imported from AD"><br><sub><b>Fig. 22</b>: Synchronisation: three users imported from AD</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig23.jpg" width="330" alt="Credentials tab of user1 in realm catavo"><br><sub><b>Fig. 23</b>: Credentials tab of user1 in realm catavo</sub></td>
<td align="center" valign="top"><img src="docs/images/fig24.jpg" width="330" alt="user1 signs in to the Keycloak account console with an AD identity"><br><sub><b>Fig. 24</b>: user1 signs in to the Keycloak account console with an AD identity</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig25.jpg" width="330" alt="Creating client catavo-sim"><br><sub><b>Fig. 25</b>: Creating client catavo-sim</sub></td>
<td align="center" valign="top"><img src="docs/images/fig26.jpg" width="330" alt="Capability config: direct access grants enabled"><br><sub><b>Fig. 26</b>: Capability config: direct access grants enabled</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig27.jpg" width="330" alt="Client catavo-sim created"><br><sub><b>Fig. 27</b>: Client catavo-sim created</sub></td>
<td align="center" valign="top"><img src="docs/images/fig28.jpg" width="330" alt="Realm event listener jboss-logging"><br><sub><b>Fig. 28</b>: Realm event listener jboss-logging</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig29.jpg" width="330" alt="User events saving enabled"><br><sub><b>Fig. 29</b>: User events saving enabled</sub></td>
<td align="center" valign="top"><img src="docs/images/fig30.jpg" width="330" alt="Keycloak sign-in page of realm catavo"><br><sub><b>Fig. 30</b>: Keycloak sign-in page of realm catavo</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>Splunk Enterprise (Figures 31-46)</b></summary>

Four indexes (`pfsense`, `endpoint`, `ad`, `keycloak`, 5 GB each). pfSense logs arrive through a UDP data input on port 5514 (source type `syslog`, restricted to host 192.168.100.1, index `pfsense`); Windows machines send via Universal Forwarder to TCP 9997.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig31.jpg" width="330" alt="Starting Splunk Enterprise for the first time"><br><sub><b>Fig. 31</b>: Starting Splunk Enterprise for the first time</sub></td>
<td align="center" valign="top"><img src="docs/images/fig32.jpg" width="330" alt="Splunk Enterprise home page"><br><sub><b>Fig. 32</b>: Splunk Enterprise home page</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig33.jpg" width="330" alt="Creating the index pfsense"><br><sub><b>Fig. 33</b>: Creating the index pfsense</sub></td>
<td align="center" valign="top"><img src="docs/images/fig34.jpg" width="330" alt="Creating the index endpoint"><br><sub><b>Fig. 34</b>: Creating the index endpoint</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig35.jpg" width="330" alt="Creating the index ad"><br><sub><b>Fig. 35</b>: Creating the index ad</sub></td>
<td align="center" valign="top"><img src="docs/images/fig36.jpg" width="330" alt="Index pfsense created (5 GB maximum)"><br><sub><b>Fig. 36</b>: Index pfsense created (5 GB maximum)</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig37.jpg" width="330" alt="Splunk index list showing ad, endpoint and pfsense"><br><sub><b>Fig. 37</b>: Splunk index list showing ad, endpoint and pfsense</sub></td>
<td align="center" valign="top"><img src="docs/images/fig38.jpg" width="330" alt="Splunk data inputs"><br><sub><b>Fig. 38</b>: Splunk data inputs</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig39.jpg" width="330" alt="Add data: select UDP source"><br><sub><b>Fig. 39</b>: Add data: select UDP source</sub></td>
<td align="center" valign="top"><img src="docs/images/fig40.jpg" width="330" alt="Input settings: source type syslog"><br><sub><b>Fig. 40</b>: Input settings: source type syslog</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig41.jpg" width="330" alt="Input settings: index pfsense"><br><sub><b>Fig. 41</b>: Input settings: index pfsense</sub></td>
<td align="center" valign="top"><img src="docs/images/fig42.jpg" width="330" alt="Review: UDP 5514 restricted to 192.168.100.1"><br><sub><b>Fig. 42</b>: Review: UDP 5514 restricted to 192.168.100.1</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig43.jpg" width="330" alt="UDP input created successfully"><br><sub><b>Fig. 43</b>: UDP input created successfully</sub></td>
<td align="center" valign="top"><img src="docs/images/fig44.jpg" width="330" alt="First pfSense events visible in Splunk"><br><sub><b>Fig. 44</b>: First pfSense events visible in Splunk</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig45.jpg" width="330" alt="Forwarding and receiving page"><br><sub><b>Fig. 45</b>: Forwarding and receiving page</sub></td>
<td align="center" valign="top"><img src="docs/images/fig46.jpg" width="330" alt="Receiving enabled on port 9997"><br><sub><b>Fig. 46</b>: Receiving enabled on port 9997</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>Windows 11 endpoint (Figures 47-57)</b></summary>

CATAVO-WS01 (Windows 11 Pro) is joined to `catavo.local` and represents the normal workstation of user1. The Universal Forwarder points to 192.168.100.30:9997 and forwards the Application, Security and System logs into the `endpoint` index.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig47.jpg" width="330" alt="Creating the Windows 11 virtual machine"><br><sub><b>Fig. 47</b>: Creating the Windows 11 virtual machine</sub></td>
<td align="center" valign="top"><img src="docs/images/fig48.jpg" width="330" alt="Windows 11 setup: Pro edition"><br><sub><b>Fig. 48</b>: Windows 11 setup: Pro edition</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig49.jpg" width="330" alt="Windows 11 installation in progress"><br><sub><b>Fig. 49</b>: Windows 11 installation in progress</sub></td>
<td align="center" valign="top"><img src="docs/images/fig50.jpg" width="330" alt="Windows 11 desktop"><br><sub><b>Fig. 50</b>: Windows 11 desktop</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig51.jpg" width="330" alt="Domain user user1@catavo.local signed in on CATAVO-WS01"><br><sub><b>Fig. 51</b>: Domain user user1@catavo.local signed in on CATAVO-WS01</sub></td>
<td align="center" valign="top"><img src="docs/images/fig52.jpg" width="330" alt="Universal Forwarder: Application, Security and System logs selected"><br><sub><b>Fig. 52</b>: Universal Forwarder: Application, Security and System logs selected</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig53.jpg" width="330" alt="Universal Forwarder: receiving indexer 192.168.100.30:9997"><br><sub><b>Fig. 53</b>: Universal Forwarder: receiving indexer 192.168.100.30:9997</sub></td>
<td align="center" valign="top"><img src="docs/images/fig54.jpg" width="330" alt="Windows events from CATAVO-WS01 in Splunk"><br><sub><b>Fig. 54</b>: Windows events from CATAVO-WS01 in Splunk</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig55.jpg" width="330" alt="Three Windows log sources received from the workstation"><br><sub><b>Fig. 55</b>: Three Windows log sources received from the workstation</sub></td>
<td align="center" valign="top"><img src="docs/images/fig56.jpg" width="330" alt="Domain controller events received in Splunk"><br><sub><b>Fig. 56</b>: Domain controller events received in Splunk</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig57.jpg" width="330" alt="Logon events (4624) per index and host"><br><sub><b>Fig. 57</b>: Logon events (4624) per index and host</sub></td>
<td></td>
</tr>
</table>

</details>


<details>
<summary><b>Kali Linux attacker and resource footprint (Figures 58-60)</b></summary>

Kali runs on 192.168.100.40 with a static address and deliberately no default gateway, so it cannot reach the Internet or be used outside the lab. With all VMs running, the 32 GB laptop used roughly 22 GB.

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig58.jpg" width="330" alt="Kali Linux software selection"><br><sub><b>Fig. 58</b>: Kali Linux software selection</sub></td>
<td align="center" valign="top"><img src="docs/images/fig59.jpg" width="330" alt="Kali Linux installation complete"><br><sub><b>Fig. 59</b>: Kali Linux installation complete</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig60.jpg" width="330" alt="Laptop memory use with all lab VMs running"><br><sub><b>Fig. 60</b>: Laptop memory use with all lab VMs running</sub></td>
<td></td>
</tr>
</table>

</details>


<details>
<summary><b>Telemetry in Splunk (Figures 61-64)</b></summary>

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig61.jpg" width="330" alt="Keycloak event types received in Splunk"><br><sub><b>Fig. 61</b>: Keycloak event types received in Splunk</sub></td>
<td align="center" valign="top"><img src="docs/images/fig62.jpg" width="330" alt="Keycloak LOGIN and LOGIN_ERROR events in Splunk"><br><sub><b>Fig. 62</b>: Keycloak LOGIN and LOGIN_ERROR events in Splunk</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig63.jpg" width="330" alt="Keycloak events per user and source IP during baseline collection"><br><sub><b>Fig. 63</b>: Keycloak events per user and source IP during baseline collection</sub></td>
<td align="center" valign="top"><img src="docs/images/fig64.jpg" width="330" alt="Event counts per Splunk index"><br><sub><b>Fig. 64</b>: Event counts per Splunk index</sub></td>
</tr>
</table>

</details>


<details>
<summary><b>Normal-behaviour data collection (Figures 65-69)</b></summary>

<table>
<tr>
<td align="center" valign="top"><img src="docs/images/fig65.jpg" width="330" alt="Data generator running on the workstation"><br><sub><b>Fig. 65</b>: Data generator running on the workstation</sub></td>
<td align="center" valign="top"><img src="docs/images/fig66.jpg" width="330" alt="Data generator finishing session 300"><br><sub><b>Fig. 66</b>: Data generator finishing session 300</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig67.jpg" width="330" alt="Collected Keycloak events per user"><br><sub><b>Fig. 67</b>: Collected Keycloak events per user</sub></td>
<td align="center" valign="top"><img src="docs/images/fig68.jpg" width="330" alt="Event table prepared for export"><br><sub><b>Fig. 68</b>: Event table prepared for export</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="docs/images/fig69.jpg" width="330" alt="Exporting the normal-behaviour data as CSV"><br><sub><b>Fig. 69</b>: Exporting the normal-behaviour data as CSV</sub></td>
<td></td>
</tr>
</table>

</details>


## Limitations

* Small evaluation: 3 to 6 runs per scenario and source, 82 hold-out attempts, two users.
* The attacks were written by the project author and are synthetic.
* A stolen password used from the user's own machine was not detected by any method.
* `new_ip` acts almost like a hard rule; the Isolation Forest baseline is weak partly for this reason.
* The full loop takes about 7 seconds because of the SIEM path.
* Active Directory account lockout and vulnerability scanning are not implemented (future work).

## Lab-only notice

`attacks.py` and the response scripts were written for an isolated lab. Run them only on systems you own or are authorised to test.
